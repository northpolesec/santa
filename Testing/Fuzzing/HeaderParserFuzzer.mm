/// Copyright 2025 North Pole Security, Inc.
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

// Fuzz target: drive HeaderParser::Update() over chunk-arbitrary
// inputs. Oracle: ASan (memory safety, OOB on malformed fat tables /
// load commands).
#include <mach/machine.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>

#include "Source/common/verifyinghasher/HeaderParser.h"

using santa::ArchSelector;
using santa::HeaderParser;

namespace {
#if defined(__arm64__) || defined(__aarch64__)
constexpr ArchSelector kArch = {CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E};
#elif defined(__x86_64__)
constexpr ArchSelector kArch = {CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL};
#else
#error "Unsupported host architecture"
#endif

// Small enough to force multi-chunk parsing on every realistic input,
// large enough to make progress without driving libFuzzer iteration
// counts into the noise floor.
constexpr size_t kChunkSize = 256;
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  HeaderParser hp(kArch, static_cast<uint64_t>(size));
  // off matches `size`'s type (size_t) so the loop arithmetic is free
  // of mixed-width casts. The static_cast at the Update call site is
  // the only place we widen to HeaderParser::Update's uint64_t chunk_off.
  size_t off = 0;
  while (off < size && hp.status() == HeaderParser::Status::kNeedMore) {
    const size_t n = std::min(kChunkSize, size - off);
    hp.Update(data + off, n, static_cast<uint64_t>(off));
    off += n;
  }
  return 0;
}
