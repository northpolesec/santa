/// Copyright 2026 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     http://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#include "Source/santad/SNTBinaryUploadController.h"

#include <fcntl.h>
#include <libkern/OSByteOrder.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <sys/stat.h>
#include <unistd.h>

#import <Foundation/Foundation.h>
#import <Security/Security.h>

#include <map>
#include <string>
#include <vector>

#include "absl/cleanup/cleanup.h"
#include "absl/status/statusor.h"

#import "Source/common/MOLCodesignChecker.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTLogging.h"
#include "Source/common/String.h"

namespace santa {

namespace pbv1 = ::santa::commands::v1;
namespace pbtel = ::santa::telemetry::v1;

namespace {

pbv1::BinaryUploadResponse MakeResponse(pbv1::BinaryUploadResponse::Disposition disposition,
                                        const std::string& message) {
  pbv1::BinaryUploadResponse response;
  response.set_disposition(disposition);
  if (!message.empty()) {
    response.set_message(message);
  }
  return response;
}

// A clean "unsigned" result is legitimate (empty signing fields). Any other
// codesign evaluation error means we could not determine the signature, so the
// caller fails closed (M1).
bool IsUnsignedError(NSError* error) {
  return error != nil && error.code == errSecCSUnsigned;
}

// Derives the canonical macho_type string from the bytes at the given fd (C1: no
// path re-open). Fat/universal images follow the first (native/primary) slice.
// Non-mach-o input yields "". Reflects only the first slice for fat binaries.
std::string MachoTypeFromFD(int fd) {
  uint32_t magic = 0;
  if (pread(fd, &magic, sizeof(magic), 0) != static_cast<ssize_t>(sizeof(magic))) {
    return "";
  }

  off_t header_offset = 0;

  // Universal (fat) binary: follow the first arch slice to its mach_header.
  if (magic == FAT_MAGIC || magic == FAT_CIGAM || magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64) {
    bool swap = (magic == FAT_CIGAM || magic == FAT_CIGAM_64);
    bool is64 = (magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64);

    struct fat_header fh;
    if (pread(fd, &fh, sizeof(fh), 0) != static_cast<ssize_t>(sizeof(fh))) {
      return "";
    }
    uint32_t nfat = swap ? OSSwapInt32(fh.nfat_arch) : fh.nfat_arch;
    if (nfat == 0) {
      return "";
    }

    if (is64) {
      struct fat_arch_64 fa;
      if (pread(fd, &fa, sizeof(fa), sizeof(struct fat_header)) !=
          static_cast<ssize_t>(sizeof(fa))) {
        return "";
      }
      header_offset = static_cast<off_t>(swap ? OSSwapInt64(fa.offset) : fa.offset);
    } else {
      struct fat_arch fa;
      if (pread(fd, &fa, sizeof(fa), sizeof(struct fat_header)) !=
          static_cast<ssize_t>(sizeof(fa))) {
        return "";
      }
      header_offset = static_cast<off_t>(swap ? OSSwapInt32(fa.offset) : fa.offset);
    }

    if (pread(fd, &magic, sizeof(magic), header_offset) != static_cast<ssize_t>(sizeof(magic))) {
      return "";
    }
  }

  // Thin mach-o (or the resolved fat slice). filetype sits at the same offset in
  // both the 32- and 64-bit headers, so reading mach_header suffices.
  if (magic == MH_MAGIC || magic == MH_CIGAM || magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
    bool swap = (magic == MH_CIGAM || magic == MH_CIGAM_64);
    struct mach_header mh;
    if (pread(fd, &mh, sizeof(mh), header_offset) != static_cast<ssize_t>(sizeof(mh))) {
      return "";
    }
    uint32_t filetype = swap ? OSSwapInt32(mh.filetype) : mh.filetype;
    switch (filetype) {
      case MH_EXECUTE: return "executable";
      case MH_DYLIB: return "dylib";
      case MH_BUNDLE: return "bundle";
      case MH_KEXT_BUNDLE: return "kext";
      default: return "other";
    }
  }

  return "";
}

}  // namespace

SNTBinaryUploadController::SNTBinaryUploadController(std::unique_ptr<SleighLauncher> launcher,
                                                    uint32_t timeout_seconds)
    : launcher_(std::move(launcher)), timeout_seconds_(timeout_seconds) {
  serial_queue_ = dispatch_queue_create("com.northpolesec.santa.binaryupload",
                                        DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL);
}

pbv1::BinaryUploadResponse SNTBinaryUploadController::Handle(
    const pbv1::BinaryUploadRequest& request) {
  const pbv1::BinaryUploadRequest* req = &request;
  __block pbv1::BinaryUploadResponse response;
  dispatch_sync(serial_queue_, ^{
    response = this->HandleSerial(*req);
  });
  return response;
}

pbv1::BinaryUploadResponse SNTBinaryUploadController::HandleSerial(
    const pbv1::BinaryUploadRequest& request) {
  // C4: open once, regular-file only, non-blocking, NOT O_CLOEXEC (the child must
  // inherit the fd). O_NONBLOCK keeps the open from blocking on a FIFO and is a
  // no-op for regular-file reads.
  int fd = open(request.path().c_str(), O_RDONLY | O_NONBLOCK);
  if (fd < 0) {
    return MakeResponse(pbv1::BinaryUploadResponse::DISPOSITION_NOT_FOUND,
                        "cannot open " + request.path());
  }
  absl::Cleanup close_fd = [&fd]() { close(fd); };

  struct stat st;
  if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
    return MakeResponse(pbv1::BinaryUploadResponse::DISPOSITION_NOT_FOUND,
                        "not a regular file: " + request.path());
  }

  // C1 + M1: compute metadata from THIS fd; fail closed on a real codesign error
  // (a clean unsigned result is fine and yields empty signing fields).
  NSString* path = StringToNSString(request.path());
  NSError* error = nil;
  MOLCodesignChecker* csc = [[MOLCodesignChecker alloc] initWithBinaryPath:path
                                                           fileDescriptor:fd
                                                                    error:&error];
  if (!csc && !IsUnsignedError(error)) {
    return MakeResponse(pbv1::BinaryUploadResponse::DISPOSITION_REFUSED,
                        "code signature could not be evaluated");
  }

  pbtel::BinaryMetadata meta;
  meta.set_path(request.path());
  meta.set_file_size(st.st_size);
  meta.set_macho_type(MachoTypeFromFD(fd));
  if (csc) {
    if (csc.signingID) meta.set_signing_id(csc.signingID.UTF8String);
    if (csc.teamID) meta.set_team_id(csc.teamID.UTF8String);
    if (csc.cdhash) meta.set_cdhash(csc.cdhash.UTF8String);
    meta.set_is_platform_binary(csc.platformBinary);
  }

  std::vector<std::string> filter_expressions;
  for (NSString* expr in [[SNTConfigurator configurator] binaryUploadFilterExpressions]) {
    filter_expressions.emplace_back(expr.UTF8String);
  }

  std::map<std::string, std::string> form_values;
  for (const auto& [key, value] : request.signed_post().form_values()) {
    form_values[key] = value;
  }

  // Hand the fd to LaunchBinaryUpload, which closes it in the parent after fork.
  std::move(close_fd).Cancel();
  absl::StatusOr<pbv1::BinaryUploadResponse> result =
      launcher_->LaunchBinaryUpload(fd, request.signed_post().url(), form_values, request.sha256(),
                                    meta, filter_expressions, timeout_seconds_);
  if (!result.ok()) {
    return MakeResponse(pbv1::BinaryUploadResponse::DISPOSITION_INTERNAL_ERROR,
                        std::string(result.status().message()));
  }
  return *result;
}

}  // namespace santa
