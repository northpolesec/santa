#!/bin/bash
set -eo pipefail

GIT_ROOT=$(git rev-parse --show-toplevel)

if [[ $(uname) = "Darwin" ]]; then
  CLANG_FORMAT="xcrun clang-format"
else
  CLANG_FORMAT="clang-format"
fi

find ${GIT_ROOT} \( -name "*.m" -o -name "*.h" -o -name "*.mm" -o -name "*.cc" \) -exec ${CLANG_FORMAT} --Werror --dry-run {} \+

swift format lint -s -r ${GIT_ROOT}

! git grep -EIn $'[ \t]+$' -- ':(exclude)*.patch'

# Select the pinned buildifier based on platform
UNAME_S=$(uname -s)
UNAME_M=$(uname -m)
case "${UNAME_S}" in
  Darwin)
    BUILDIFIER="${GIT_ROOT}/Testing/tools/buildifier"
    ;;
  Linux)
    case "${UNAME_M}" in
      x86_64|amd64)
        BUILDIFIER="${GIT_ROOT}/Testing/tools/buildifier-linux-amd64"
        ;;
      aarch64|arm64)
        BUILDIFIER="${GIT_ROOT}/Testing/tools/buildifier-linux-arm64"
        ;;
      *)
        echo "Unsupported Linux architecture: ${UNAME_M}"
        exit 1
        ;;
    esac
    ;;
  *)
    echo "Unsupported OS: ${UNAME_S}"
    exit 1
    ;;
esac

if [[ ! -x "${BUILDIFIER}" ]]; then
  echo "Error: buildifier not found at ${BUILDIFIER}"
  echo "Please ensure the appropriate Testing/tools/buildifier* binary exists"
  exit 1
fi

"${BUILDIFIER}" --lint=warn -r ${GIT_ROOT}

