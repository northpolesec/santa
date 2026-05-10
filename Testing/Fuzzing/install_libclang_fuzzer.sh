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

# Apple Clang doesn't ship libclang_rt.fuzzer_osx.a; this script copies it
# from a downloaded LLVM release into the active Xcode toolchain.
#
# Diverges from google-santa's original install_libclang_fuzzer.sh: that
# script derived the LLVM version from `clang --version`, which only worked
# when Apple Clang's numbering happened to align with upstream LLVM tags.
# Apple Clang 21.0.0 has no upstream "llvmorg-21.0.0" tag, so we hardcode
# a recent LLVM release whose libFuzzer runtime is ABI-compatible with
# Apple Clang. Bump LLVM_VERSION when a newer release ships an
# arm64-apple-darwin tarball.
#
# Hardcoded for arm64 macOS. On x86_64 hosts, swap LLVM-${LLVM_VERSION}-macOS-ARM64
# -> LLVM-${LLVM_VERSION}-macOS-X64 in the URL below.
#
# The tarball's internal clang lib directory uses a short major version (e.g.
# "22"), not the full LLVM_VERSION string. TARBALL_CLANG_MAJOR is derived
# automatically from LLVM_VERSION and must be updated if that convention
# ever changes.

set -uexo pipefail

LLVM_VERSION=22.1.4
TARBALL_NAME="LLVM-${LLVM_VERSION}-macOS-ARM64"
TARBALL_FILE="${TARBALL_NAME}.tar.xz"
TARBALL_URL="https://github.com/llvm/llvm-project/releases/download/llvmorg-${LLVM_VERSION}/${TARBALL_FILE}"

# Major version only (e.g. "22" from "22.1.4") — matches the lib path inside the tarball.
TARBALL_CLANG_MAJOR="${LLVM_VERSION%%.*}"

# DST_PATH uses Apple Clang's version string (from `clang --version`) because
# the Xcode toolchain directory layout follows Apple's numbering, not LLVM's.
# Only the download URL needs the upstream LLVM version.
CLANG_VERSION=$(clang --version | head -n 1 | cut -d' ' -f 4)
if [[ -z "${CLANG_VERSION}" ]]; then
  echo "ERROR: failed to parse Apple Clang version from 'clang --version'" >&2
  exit 1
fi
DST_PATH="$(xcode-select -p)/Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/${CLANG_VERSION}/lib/darwin/libclang_rt.fuzzer_osx.a"

if [ -f "${DST_PATH}" ]; then
  echo "libclang_rt.fuzzer_osx.a already present at ${DST_PATH}, nothing to do."
  exit 0
fi

WORK_DIR=$(mktemp -d)
trap 'rm -rf "${WORK_DIR}"' EXIT

cd "${WORK_DIR}"

echo "Downloading ${TARBALL_URL} ..."
# --fail: surface 4xx/5xx as a non-zero exit instead of silently writing
# an HTML error body to disk and letting the next `tar` step die with a
# misleading "File format not recognized" error. The most likely failure
# mode for a hardcoded LLVM_VERSION is a future bump to a tag that hasn't
# shipped yet; --fail makes that diagnosable.
curl --fail -O -L "${TARBALL_URL}"

FUZZER_LIB_IN_TAR="${TARBALL_NAME}/lib/clang/${TARBALL_CLANG_MAJOR}/lib/darwin/libclang_rt.fuzzer_osx.a"
echo "Extracting ${FUZZER_LIB_IN_TAR} ..."
tar xf "${TARBALL_FILE}" "${FUZZER_LIB_IN_TAR}"

echo "Installing to ${DST_PATH} (requires sudo to write into Xcode toolchain) ..."
sudo cp "${FUZZER_LIB_IN_TAR}" "${DST_PATH}"

echo "Done."
