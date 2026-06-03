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

#import <XCTest/XCTest.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <string>

#include "Source/santad/SleighLauncher.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "commands/v1.pb.h"
#include "telemetry/sleighconfig.pb.h"

// These tests drive the real fork/stdin/stdout machinery in SleighLauncher in any
// compilation mode: TestableSleighLauncher overrides the code-signature check (which
// production enforces outside DEBUG builds) so the unsigned stub sleigh is accepted.
namespace {
class TestableSleighLauncher : public santa::SleighLauncher {
 public:
  using santa::SleighLauncher::SleighLauncher;

 protected:
  absl::Status VerifySleighCodeSignature() override { return absl::OkStatus(); }
};
}  // namespace

@interface SleighLauncherTest : XCTestCase
@end

@implementation SleighLauncherTest

// Writes an executable /bin/sh stub at a unique temp path and returns the path.
- (NSString*)writeStubWithBody:(NSString*)body {
  NSString* path = [NSTemporaryDirectory()
      stringByAppendingPathComponent:[NSString stringWithFormat:@"sleigh-stub-%@",
                                                                [[NSUUID UUID] UUIDString]]];
  NSString* script = [@"#!/bin/sh\n" stringByAppendingString:body];
  NSError* err = nil;
  [script writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:&err];
  XCTAssertNil(err);
  XCTAssertEqual(chmod(path.UTF8String, 0755), 0);
  return path;
}

// Writes bytes to a unique temp file and returns an open read-only fd.
- (int)openTempFileWithBytes:(const std::string&)bytes {
  NSString* path = [NSTemporaryDirectory()
      stringByAppendingPathComponent:[NSString stringWithFormat:@"sleigh-in-%@",
                                                                [[NSUUID UUID] UUIDString]]];
  [[NSData dataWithBytes:bytes.data() length:bytes.size()] writeToFile:path atomically:YES];
  int fd = open(path.UTF8String, O_RDONLY);
  XCTAssertGreaterThanOrEqual(fd, 0);
  return fd;
}

// LaunchBinaryUpload forks the stub, which drains stdin (the config) and echoes a
// canned serialized BinaryUploadResponse on stdout; we parse it back.
- (void)testLaunchBinaryUploadParsesStdout {
  ::santa::commands::v1::BinaryUploadResponse canned;
  canned.set_disposition(::santa::commands::v1::BinaryUploadResponse::DISPOSITION_COMPLETED);
  canned.set_sha256_computed("deadbeef");
  canned.set_bytes_uploaded(42);
  std::string serialized;
  XCTAssertTrue(canned.SerializeToString(&serialized));

  NSString* b64 = [[NSData dataWithBytes:serialized.data()
                                  length:serialized.size()] base64EncodedStringWithOptions:0];
  // Drain stdin, then write the (base64-decoded) canned response to stdout.
  NSString* body =
      [NSString stringWithFormat:@"cat > /dev/null\nprintf %%s '%@' | /usr/bin/base64 -D\n", b64];
  NSString* stub = [self writeStubWithBody:body];

  TestableSleighLauncher launcher(stub.UTF8String);
  int fd = [self openTempFileWithBytes:std::string("\xfe\xed\xfa\xcf binary", 14)];

  ::santa::telemetry::v1::BinaryMetadata meta;
  meta.set_file_size(14);
  absl::StatusOr<::santa::commands::v1::BinaryUploadResponse> resp = launcher.LaunchBinaryUpload(
      fd, "https://example.com/post", {{"key", "objects/x"}}, "", meta, {}, /*timeout_seconds=*/10);

  XCTAssertTrue(resp.ok());
  XCTAssertEqual(resp->disposition(),
                 ::santa::commands::v1::BinaryUploadResponse::DISPOSITION_COMPLETED);
  XCTAssertEqual(resp->sha256_computed(), "deadbeef");
  XCTAssertEqual(resp->bytes_uploaded(), 42);
}

// A non-zero exit (no parseable response) surfaces as an error; the caller maps
// that to INTERNAL_ERROR rather than trusting a default-valued parse (M5).
- (void)testLaunchBinaryUploadNonZeroExitIsError {
  NSString* stub = [self writeStubWithBody:@"cat > /dev/null\nexit 3\n"];
  TestableSleighLauncher launcher(stub.UTF8String);
  int fd = [self openTempFileWithBytes:std::string("data", 4)];

  ::santa::telemetry::v1::BinaryMetadata meta;
  absl::StatusOr<::santa::commands::v1::BinaryUploadResponse> resp = launcher.LaunchBinaryUpload(
      fd, "https://example.com", {{"key", "k"}}, "", meta, {}, /*timeout_seconds=*/10);
  XCTAssertFalse(resp.ok());
  // Specifically a non-zero exit (kUnknown), not the codesign short-circuit
  // (kFailedPrecondition) — proves the child actually ran and exited 3.
  XCTAssertEqual(resp.status().code(), absl::StatusCode::kUnknown);
  XCTAssertTrue(std::string(resp.status().message()).find("exited with code 3") !=
                std::string::npos);
}

// Empty stdout (process exits 0 but writes nothing) is an error, not COMPLETED.
- (void)testLaunchBinaryUploadEmptyStdoutIsError {
  NSString* stub = [self writeStubWithBody:@"cat > /dev/null\n"];
  TestableSleighLauncher launcher(stub.UTF8String);
  int fd = [self openTempFileWithBytes:std::string("data", 4)];

  ::santa::telemetry::v1::BinaryMetadata meta;
  absl::StatusOr<::santa::commands::v1::BinaryUploadResponse> resp = launcher.LaunchBinaryUpload(
      fd, "https://example.com", {{"key", "k"}}, "", meta, {}, /*timeout_seconds=*/10);
  XCTAssertFalse(resp.ok());
  // Empty (but exit-0) stdout maps to kInternal in LaunchBinaryUpload (M5), not the
  // codesign short-circuit — proves the empty-stdout path is what's exercised.
  XCTAssertEqual(resp.status().code(), absl::StatusCode::kInternal);
}

// LaunchTelemetryExport still runs through SerializeTelemetryUploadConfig after the RunSleigh
// refactor.
// With no export configuration set (unit-test default), it must fail at the
// serialization guard — proving the telemetry path is intact, not crashing.
- (void)testTelemetryLaunchSerializationGuardIntact {
  NSString* stub = [self writeStubWithBody:@"cat > /dev/null\n"];
  TestableSleighLauncher launcher(stub.UTF8String);

  NSString* inPath = [NSTemporaryDirectory()
      stringByAppendingPathComponent:[NSString
                                         stringWithFormat:@"tlm-%@", [[NSUUID UUID] UUIDString]]];
  [@"telemetry" writeToFile:inPath atomically:YES encoding:NSUTF8StringEncoding error:nil];

  absl::Status s = launcher.LaunchTelemetryExport({inPath.UTF8String}, /*timeout_seconds=*/10);
  XCTAssertFalse(s.ok());  // exportConfig is nil → InvalidArgumentError from
                           // SerializeTelemetryUploadConfig.
}

@end
