/// Copyright 2026 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     https://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

// Fuzz target: drive VerifyingHasherCore::Run() against arbitrary bytes.
// Oracles:
//   1. ASan (memory safety, OOB reads, leaks via ASan_LSan)
//   2. libFuzzer's default timeout (hangs)
//   3. CountingMemoryFileReader::MaxReadsAnyByte() <= 1
//      (the single-observation invariant)
#include <mach/machine.h>

#include <cstdint>
#include <cstdlib>
#include <vector>

#include "Source/common/verifyinghasher/CountingMemoryFileReader.h"
#include "Source/common/verifyinghasher/VerifyingHasherCore.h"

using santa::ArchSelector;
using santa::CountingMemoryFileReader;
using santa::VerifyingHasherCore;

namespace {
#if defined(__arm64__) || defined(__aarch64__)
constexpr ArchSelector kArch = {CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E};
#elif defined(__x86_64__)
constexpr ArchSelector kArch = {CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL};
#else
#error "Unsupported host architecture"
#endif
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  std::vector<uint8_t> bytes(data, data + size);
  CountingMemoryFileReader reader(std::move(bytes));
  VerifyingHasherCore v(reader, kArch);
  // Status is not an oracle; any return value (kOk, kPagesMismatched,
  // kMalformedSignature, kIoError, ...) is acceptable. The oracle is
  // the per-byte read count below.
  (void)v.Run();
  if (reader.MaxReadsAnyByte() > 1) std::abort();
  return 0;
}
