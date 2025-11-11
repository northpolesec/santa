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

GBIN=${GOBIN:-${GOPATH:-${HOME}/go}/bin}
go install github.com/bazelbuild/buildtools/buildifier/cmd@latest
mv ${GBIN}/cmd ${GBIN}/buildifier
${GBIN}/buildifier --lint=warn -r ${GIT_ROOT}

