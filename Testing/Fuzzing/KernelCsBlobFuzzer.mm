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

// Fuzz target: drive KernelCsBlob::ParseBytes() over arbitrary bytes.
// Oracle: ASan (memory safety). ParseBytes's offset/length math lives in
// the SuperBlob/BlobIndex walk and slot extraction (FindSlotPayload),
// driven entirely by kernel_cs_blob, so the libFuzzer buffer maps directly
// onto that argument — this harness exercises that parsing to guard it
// against memory-safety regressions.
//
// cd_bytes is passed EMPTY: it is opaque detached content KCB never
// parses (it is only handed to CFDataCreateWithBytesNoCopy as CMS
// detached content), so fuzzing it exercises no Santa-side parsing.
//
// ParseBytes calls Apple's CMSDecoder (and, for a structurally valid TSA
// token, trust evaluation), so a finding could in principle land in
// Apple code rather than ours. In practice a mutated blob almost never
// forms a valid CMS, so the decoder bails early and trustd is rarely
// reached; the 16 MiB kMaxCsBlobSize cap in ParseBytes bounds work.
#include <cstddef>
#include <cstdint>
#include <span>

#include "Source/common/verifyinghasher/KernelCsBlob.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  santa::KernelCsBlob::ParseBytes(std::span<const uint8_t>(data, size),
                                  /*cd_bytes=*/{});
  return 0;
}
