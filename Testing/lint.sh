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

# Use the buildifier binary committed in the repository
BUILDIFIER="${GIT_ROOT}/Testing/tools/buildifier"

if [[ ! -x "${BUILDIFIER}" ]]; then
  echo "Error: buildifier not found at ${BUILDIFIER}"
  echo "Please ensure Testing/tools/buildifier exists in the repository"
  exit 1
fi

${BUILDIFIER} --lint=warn -r ${GIT_ROOT}

