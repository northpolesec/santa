#!/bin/bash
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

# End-to-end smoke tests for VerifyingHasher.

set -euo pipefail

BIN="${BIN:-./bazel-bin/VerifyingHasher}"
if [ ! -x "$BIN" ]; then
    echo "binary not found: $BIN" >&2
    exit 2
fi

TMP="${TMPDIR:-/tmp}/verifyinghasher-smoke.$$"
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT

failures=0

assert_grep() {
    local needle="$1"; shift
    local file="$1"; shift
    if ! grep -q -- "$needle" "$file"; then
        echo "FAIL: expected '$needle' in $file" >&2
        sed 's/^/  /' "$file" >&2
        failures=$((failures + 1))
    fi
}

# Case 1: thin or fat /usr/bin/yes — exit 0 + digest matches shasum.
echo "Case 1: /usr/bin/yes"
"$BIN" /usr/bin/yes >"$TMP/case1.out" 2>"$TMP/case1.err" || {
    echo "FAIL: /usr/bin/yes returned non-zero" >&2
    failures=$((failures + 1))
}
expected_sha=$(shasum -a 256 /usr/bin/yes | awk '{print $1}')
assert_grep "$expected_sha" "$TMP/case1.out"
assert_grep "page mismatches: 0" "$TMP/case1.out"

# Case 2: /usr/bin/file — exit 0, digest matches.
echo "Case 2: /usr/bin/file"
"$BIN" /usr/bin/file >"$TMP/case2.out" 2>"$TMP/case2.err" || {
    echo "FAIL: /usr/bin/file returned non-zero" >&2
    failures=$((failures + 1))
}
expected_sha=$(shasum -a 256 /usr/bin/file | awk '{print $1}')
assert_grep "$expected_sha" "$TMP/case2.out"
assert_grep "page mismatches: 0" "$TMP/case2.out"

# Case 3: tampered copy.
echo "Case 3: tampered copy"
TAMP="$TMP/yes_tampered"
cp /usr/bin/yes "$TAMP"
chmod u+w "$TAMP"
# Derive the tamper offset from Case 1's verifier output so the smoke test
# stays valid across /usr/bin/yes layout changes (size shrink, arch
# reorder, thin-vs-fat). The signed region for the host slice is
# [slice_off, slice_off + codeLimit); the midpoint is guaranteed inside.
slice_off=$(grep -E '^slice: ' "$TMP/case1.out" | sed -E 's/.* at offset ([0-9]+).*/\1/')
code_limit=$(grep -E '^codedir: ' "$TMP/case1.out" | sed -E 's/.*codeLimit=([0-9]+).*/\1/')
if [ -z "$slice_off" ] || [ -z "$code_limit" ]; then
    echo "FAIL: could not parse slice_off/code_limit from Case 1 output" >&2
    failures=$((failures + 1))
else
    tamper_off=$(( slice_off + code_limit / 2 ))
    python3 -c "
import sys
p, off = sys.argv[1], int(sys.argv[2])
with open(p, 'r+b') as f:
    f.seek(off)
    b = f.read(1)
    f.seek(off)
    f.write(bytes([b[0] ^ 0xFF]))
" "$TAMP" "$tamper_off"
    "$BIN" "$TAMP" >"$TMP/case3.out" 2>"$TMP/case3.err" || {
        rc=$?
        echo "FAIL: tampered run exited with $rc (expected 0)" >&2
        failures=$((failures + 1))
    }
    if ! grep -E "page mismatches: [1-9]" "$TMP/case3.out" >/dev/null; then
        echo "FAIL: expected nonzero page mismatches in tampered run" >&2
        sed 's/^/  /' "$TMP/case3.out" >&2
        failures=$((failures + 1))
    fi
fi

# Case 4: non-Mach-O file.
echo "Case 4: /etc/hosts (negative)"
if "$BIN" /etc/hosts >"$TMP/case4.out" 2>"$TMP/case4.err"; then
    echo "FAIL: /etc/hosts unexpectedly succeeded" >&2
    failures=$((failures + 1))
fi
assert_grep "not a Mach-O" "$TMP/case4.err"

# Case 5: -s flag — same digest + cdhash as Case 1, plus the skip marker.
echo "Case 5: -s flag on /usr/bin/yes"
"$BIN" -s /usr/bin/yes >"$TMP/case5.out" 2>"$TMP/case5.err" || {
    echo "FAIL: -s /usr/bin/yes returned non-zero" >&2
    failures=$((failures + 1))
}
case1_digest=$(grep -E '^full-file digest:' "$TMP/case1.out" | awk '{print $3}')
case5_digest=$(grep -E '^full-file digest:' "$TMP/case5.out" | awk '{print $3}')
case1_cdhash=$(grep -E '^cdhash:' "$TMP/case1.out" | awk '{print $2}')
case5_cdhash=$(grep -E '^cdhash:' "$TMP/case5.out" | awk '{print $2}')
if [ -z "$case5_digest" ] || [ "$case1_digest" != "$case5_digest" ]; then
    echo "FAIL: -s digest ($case5_digest) differs from no-flag digest ($case1_digest)" >&2
    failures=$((failures + 1))
fi
if [ -z "$case5_cdhash" ] || [ "$case1_cdhash" != "$case5_cdhash" ]; then
    echo "FAIL: -s cdhash ($case5_cdhash) differs from no-flag cdhash ($case1_cdhash)" >&2
    failures=$((failures + 1))
fi
assert_grep "page mismatches: (skipped)" "$TMP/case5.out"

if [ "$failures" -ne 0 ]; then
    echo "smoke: $failures FAILURES" >&2
    exit 1
fi
echo "smoke: all cases passed"
