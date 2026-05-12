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

#include <CommonCrypto/CommonDigest.h>
#include <Kernel/kern/cs_blobs.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "Source/common/verifyinghasher/FileReader.h"
#include "Source/common/verifyinghasher/VerifyingHasherCore.h"

using santa::ArchSelector;
using santa::FdFileReader;
using santa::VerifyingHasherCore;

namespace {

#if defined(__arm64__) || defined(__aarch64__)
constexpr ArchSelector kHostDefaultArch = {CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E};
#elif defined(__x86_64__)
constexpr ArchSelector kHostDefaultArch = {CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL};
#else
#error "Unsupported host architecture"
#endif

struct Args {
  std::string path;
  ArchSelector arch = kHostDefaultArch;
  size_t buf_size = 1u << 20;
  bool skip_page_hash = false;
};

void PrintUsage(FILE* f) {
  std::fprintf(f,
               "Usage: VerifyingHasher [-a ARCH] [-b BYTES] [-s] <path>\n"
               "  -a ARCH   architecture: arm64 | arm64e | x86_64\n"
               "            (default: host preferred — arm64e on Apple Silicon, x86_64 on Intel)\n"
               "  -b N      pread chunk size in bytes (default 1048576, minimum 512)\n"
               "  -s        skip per-page CodeDirectory verification\n"
               "            (cdhash and full-file SHA-256 still computed)\n"
               "  -h        show this help\n");
}

bool ParseArch(const char* s, ArchSelector& out) {
  if (std::strcmp(s, "arm64") == 0) {
    out = {CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL};
    return true;
  }
  if (std::strcmp(s, "arm64e") == 0) {
    out = {CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E};
    return true;
  }
  if (std::strcmp(s, "x86_64") == 0) {
    out = {CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL};
    return true;
  }
  return false;
}

const char* ArchName(const ArchSelector& a) {
  if (a.cputype == CPU_TYPE_ARM64 && a.cpusubtype == CPU_SUBTYPE_ARM64E) return "arm64e";
  if (a.cputype == CPU_TYPE_ARM64) return "arm64";
  if (a.cputype == CPU_TYPE_X86_64) return "x86_64";
  return "unknown";
}

bool ParseArgs(int argc, char** argv, Args& out) {
  int opt;
  while ((opt = getopt(argc, argv, "a:b:hs")) != -1) {
    switch (opt) {
      case 'a':
        if (!ParseArch(optarg, out.arch)) {
          std::fprintf(stderr, "invalid -a: %s (expected arm64|arm64e|x86_64)\n", optarg);
          return false;
        }
        break;
      case 'b': {
        char* endp = nullptr;
        long long v = std::strtoll(optarg, &endp, 10);
        if (endp == optarg || *endp != '\0' || v < 512) {
          std::fprintf(stderr, "invalid -b: %s (minimum 512)\n", optarg);
          return false;
        }
        out.buf_size = static_cast<size_t>(v);
        break;
      }
      case 's': out.skip_page_hash = true; break;
      case 'h': PrintUsage(stdout); std::exit(0);
      default: return false;
    }
  }
  if (optind >= argc) {
    std::fprintf(stderr, "missing <path>\n");
    return false;
  }
  out.path = argv[optind];
  return true;
}

std::string HexLower(const uint8_t* bytes, size_t n) {
  static const char* kHex = "0123456789abcdef";
  std::string s(n * 2, '\0');
  for (size_t i = 0; i < n; ++i) {
    s[2 * i] = kHex[(bytes[i] >> 4) & 0xF];
    s[2 * i + 1] = kHex[bytes[i] & 0xF];
  }
  return s;
}

}  // namespace

int main(int argc, char** argv) {
  Args args;
  if (!ParseArgs(argc, argv, args)) {
    PrintUsage(stderr);
    return 2;
  }

  int fd = ::open(args.path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    std::fprintf(stderr, "open %s: %s\n", args.path.c_str(), std::strerror(errno));
    return 1;
  }
  struct stat st{};
  if (::fstat(fd, &st) < 0) {
    std::fprintf(stderr, "fstat %s: %s\n", args.path.c_str(), std::strerror(errno));
    ::close(fd);
    return 1;
  }

  FdFileReader reader(fd, st.st_size);
  VerifyingHasherCore::Options opts;
  opts.buf_size = args.buf_size;
  opts.skip_page_hash = args.skip_page_hash;
  VerifyingHasherCore v(reader, args.arch, opts);
  auto status = v.Run();
  ::close(fd);

  if (status != VerifyingHasherCore::Status::kOk &&
      status != VerifyingHasherCore::Status::kPagesMismatched) {
    if (status == VerifyingHasherCore::Status::kSliceNotFound) {
      std::fprintf(stderr, "%s: %s (requested arch=%s; try -a with one of arm64|arm64e|x86_64)\n",
                   args.path.c_str(), std::string(v.LastError()).c_str(), ArchName(args.arch));
    } else {
      std::fprintf(stderr, "%s: %s\n", args.path.c_str(), std::string(v.LastError()).c_str());
    }
    return 1;
  }

  const auto& cd = v.ParsedCD();
  const auto& slice = v.Slice();
  const char* hash_name = cd.hash_type == CS_HASHTYPE_SHA1               ? "SHA1"
                          : cd.hash_type == CS_HASHTYPE_SHA384           ? "SHA384"
                          : cd.hash_type == CS_HASHTYPE_SHA256_TRUNCATED ? "SHA256_TRUNCATED"
                                                                         : "SHA256";

  std::printf("path: %s\n", args.path.c_str());
  std::printf("slice: %s at offset %llu, size %llu bytes\n", slice.arch_name.c_str(),
              (unsigned long long)slice.slice_offset, (unsigned long long)slice.slice_size);
  std::printf("codedir: hashType=%s, pageSize=%u, pageCount=%u, codeLimit=%llu\n", hash_name,
              cd.page_size, cd.page_count, (unsigned long long)cd.code_limit);

  auto digest = v.FullFileDigest();
  std::printf("full-file digest: %s\n", HexLower(digest.data(), digest.size()).c_str());
  auto cdhash = v.CDHash();
  std::printf("cdhash: %s\n", HexLower(cdhash.data(), cdhash.size()).c_str());
  if (v.PageHashSkipped()) {
    std::printf("page mismatches: (skipped)\n");
  } else {
    std::printf("page mismatches: %u\n", *v.Mismatches());
  }

  auto bad = v.MismatchedSlots();
  if (!bad.empty()) {
    std::printf("mismatched slots:");
    for (uint32_t s : bad)
      std::printf(" %u", s);
    std::printf("\n");
  }
  return 0;
}
