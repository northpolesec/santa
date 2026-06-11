#!/bin/bash
#
# Copyright 2026 North Pole Security, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Regenerate Testing/Fuzzing/VerifyingHasherFuzzer_corpus/*,
# Testing/Fuzzing/HeaderParserFuzzer_corpus/*, and
# Testing/Fuzzing/KernelCsBlobFuzzer_corpus/*. Self-relocates so the
# script can be invoked from anywhere. Idempotent — overwrites existing
# files.
#
# Requires macOS + Apple Clang (the arm64e target is Apple-only) plus
# `lipo`, `otool`, `codesign`, `dd`, `python3`. Not portable to Linux.
set -uexo pipefail

cd "$(dirname "$0")/.."

CORPUS=Fuzzing/VerifyingHasherFuzzer_corpus
HDR=Fuzzing/HeaderParserFuzzer_corpus
KCB=Fuzzing/KernelCsBlobFuzzer_corpus
TESTDATA=../Source/common/verifyinghasher/testdata
mkdir -p "$CORPUS" "$HDR" "$KCB"

# Extract the raw arm64 cs_blob (the embedded-signature SuperBlob, trimmed
# to sb->length) from a Mach-O fixture $1 into $2. Handles both fat inputs
# (arm64 slice offset from `lipo`) and thin arm64 inputs (offset 0).
# Unlike the VerifyingHasher/HeaderParser fuzzers, KernelCsBlob::ParseBytes
# consumes a raw SuperBlob, not a Mach-O — so the seeds are the extracted
# cs_blobs, not the binaries themselves.
#
# This is the hardened sibling of the manual recipe in
# Source/common/verifyinghasher/testdata/README.md: it matches the arch
# field exactly (`$2=="arm64"`, so an arm64e slice can't be picked) and
# only reads `dataoff` once the LC_CODE_SIGNATURE flag is set. Keep these
# stricter forms — do not "reconcile" them back to the README's looser
# `/architecture arm64/` regex.
extract_arm64_csblob() {
    local src="$1" dst="$2" slice_off data_off
    # `lipo` errors on a thin file (pipefail would abort); `|| true`
    # collapses that to an empty match → slice_off defaults to 0.
    slice_off=$(lipo -detailed_info "$src" 2>/dev/null \
        | awk '$1=="architecture" && $2=="arm64"{f=1} f&&$1=="offset"{print $2; exit}' || true)
    slice_off=${slice_off:-0}
    data_off=$(otool -arch arm64 -l "$src" \
        | awk '/LC_CODE_SIGNATURE/{f=1} f&&/dataoff/{print $2; exit}')
    if [[ -z "$data_off" ]]; then
        echo "no arm64 LC_CODE_SIGNATURE in $src" >&2
        exit 1
    fi
    python3 - "$src" "$dst" "$slice_off" "$data_off" <<'PY'
import sys
src, dst, slice_off, data_off = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
data = open(src, "rb").read()
abs_off = slice_off + data_off
# Fail fast rather than silently emit a truncated/empty seed: Python slicing
# does not raise on out-of-range bounds, so validate offset, magic, and length.
if abs_off < 0 or abs_off + 8 > len(data):
    raise SystemExit(f"{src}: LC_CODE_SIGNATURE offset {abs_off} out of range")
if data[abs_off:abs_off + 4] != b"\xfa\xde\x0c\xc0":  # CSMAGIC_EMBEDDED_SIGNATURE
    raise SystemExit(f"{src}: no SuperBlob magic at offset {abs_off}")
sb_len = int.from_bytes(data[abs_off + 4:abs_off + 8], "big")  # SuperBlob length (BE)
if sb_len < 8 or abs_off + sb_len > len(data):
    raise SystemExit(f"{src}: implausible SuperBlob length {sb_len}")
with open(dst, "wb") as f:
    f.write(data[abs_off:abs_off + sb_len])
PY
}

TMP=$(mktemp -d)
# Single-quote so $TMP is expanded by the trap body at exit time, with
# its value still quoted — robust against $TMPDIR paths containing spaces.
trap 'rm -rf "$TMP"' EXIT

# 1. thin_arm64e — minimal signed Mach-O.
echo 'int main(){return 0;}' > "$TMP/return0.c"
clang -arch arm64e -o "$TMP/thin_arm64e" "$TMP/return0.c"
strip "$TMP/thin_arm64e"
codesign --sign - "$TMP/thin_arm64e"
cp "$TMP/thin_arm64e" "$CORPUS/thin_arm64e"

# 2. thin_arm64 (intermediate, not committed).
clang -arch arm64 -o "$TMP/thin_arm64" "$TMP/return0.c"
strip "$TMP/thin_arm64"
codesign --sign - "$TMP/thin_arm64"

# 3. fat32 — lipo of arm64 + arm64e.
lipo -create "$TMP/thin_arm64" "$TMP/thin_arm64e" -output "$CORPUS/fat32"

# 4. fat64_synthetic — adapts the byte-vector construction inside
#    tests/HeaderParserTest.cc:445-509 (TestParsesSyntheticFat64Binary)
#    for on-disk emission. The L1 regression case from that test:
#    FAT_MAGIC_64 wrapping a single x86_64 thin slice with one
#    LC_CODE_SIGNATURE. xnu rejects this for exec but dyld accepts
#    it for dylibs; the verifier accepts it.
python3 - <<'PY' "$CORPUS/fat64_synthetic"
import struct, sys

# Inner thin x86_64 slice with one LC_CODE_SIGNATURE, padded to 0x3000 bytes.
# struct mach_header_64: magic, cputype, cpusubtype, filetype, ncmds,
#                        sizeofcmds, flags, reserved (all uint32)
mh = struct.pack("<IiiIIIII",
    0xfeedfacf,           # MH_MAGIC_64
    0x01000007,           # CPU_TYPE_X86_64
    3,                    # CPU_SUBTYPE_X86_64_ALL
    2,                    # MH_EXECUTE
    1,                    # ncmds
    16,                   # sizeofcmds (sizeof(linkedit_data_command))
    0, 0)                 # flags, reserved
# struct linkedit_data_command: cmd, cmdsize, dataoff, datasize (all uint32)
lc = struct.pack("<IIII",
    0x1d,                 # LC_CODE_SIGNATURE
    16,                   # cmdsize
    0x800,                # dataoff
    0x100)                # datasize
slice_size = 0x3000
slice_bytes = mh + lc + b"\x00" * (slice_size - len(mh) - len(lc))

# Outer fat64 header (big-endian on disk).
# struct fat_header: magic, nfat_arch (both uint32 BE)
fh = struct.pack(">II",
    0xcafebabf,           # FAT_MAGIC_64
    1)                    # nfat_arch
# struct fat_arch_64: cputype, cpusubtype (int32),
#                     offset, size (uint64),
#                     align, reserved (uint32) — all BE
fa = struct.pack(">iiQQII",
    0x01000007,           # cputype
    3,                    # cpusubtype
    0x1000,               # offset
    slice_size,           # size
    12,                   # align (4 KiB)
    0)                    # reserved

slice_off = 0x1000
data = bytearray(slice_off + slice_size)
data[:len(fh)] = fh
data[len(fh):len(fh)+len(fa)] = fa
data[slice_off:slice_off+slice_size] = slice_bytes

with open(sys.argv[1], "wb") as f:
    f.write(data)
PY

# 5. hw_universal — fat32 (arm64 + x86_64) where each slice carries four
#    CodeDirectories (SHA-1, SHA-256, SHA-256-TRUNCATED, SHA-384). Exercises
#    the strongest-CD picker on a real signed binary; the only fixture that
#    drives the SHA-384 picked-CD path with real codesign output rather than
#    a synthetic blob.
cat > "$TMP/hw.c" <<'EOF'
#include <stdio.h>
int main(void) {
	printf("hello world 2\n");
	return 0;
}
EOF
clang -arch arm64 -arch x86_64 -o "$TMP/hw_universal" "$TMP/hw.c"
codesign -s - -f --digest-algorithm=sha1,sha256,sha256T,sha384 "$TMP/hw_universal"
cp "$TMP/hw_universal" "$CORPUS/hw_universal"

# 6. HeaderParser corpus: same files truncated to first 32 KiB.
#    (HeaderParser only needs the prefix region: fat header / fat arches /
#     mach_header / load commands. Page hashes live further into the file.)
for src in thin_arm64e fat32 fat64_synthetic hw_universal; do
    dd if="$CORPUS/$src" of="$HDR/${src}_hdr" bs=1 count=32768 status=none
done

# 7. KernelCsBlob corpus: raw cs_blobs (SuperBlobs), NOT Mach-Os.
#    - santactl_2026.4.csblob is already a raw SuperBlob (Dev-ID + TSA,
#      notarized-style) — copy it verbatim from the production testdata.
#    - The arm64 cs_blob is extracted from each committed Mach-O fixture:
#        hw_universal   ad-hoc, multi-CD (SHA-1/256/256T/384)
#        hw_entitled    XML + DER entitlement slots (thin arm64)
#        hw_team_signed Dev-ID, developer-controlled signingTime
cp "$TESTDATA/santactl_2026.4.csblob" "$KCB/santactl_2026.4.csblob"
extract_arm64_csblob "$TESTDATA/hw_universal"   "$KCB/hw_universal.csblob"
extract_arm64_csblob "$TESTDATA/hw_entitled"    "$KCB/hw_entitled.csblob"
extract_arm64_csblob "$TESTDATA/hw_team_signed" "$KCB/hw_team_signed.csblob"

echo "Corpus regenerated: $(ls $CORPUS | wc -l | tr -d ' ') seed(s) in $CORPUS, $(ls $HDR | wc -l | tr -d ' ') in $HDR, $(ls $KCB | wc -l | tr -d ' ') in $KCB"
