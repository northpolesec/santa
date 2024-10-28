#!/bin/bash
set -exo pipefail

GIT_ROOT=$(git rev-parse --show-toplevel)

find ${GIT_ROOT} \( -name "*.m" -o -name "*.h" -o -name "*.mm" -o -name "*.cc" \) -exec clang-format --Werror --dry-run {} \+

# Swift 6.0.1 included on the current Ubuntu 22.04 runner image has a bug that
# causes an infinite loop when calling `swift format`. Until the image is updated
# with a version of Swift without this problem, limit swift formatting checks to
# macOS hosts.
[[ "$(uname)" -eq "Darwin" ]] && swift format lint -r ${GIT_ROOT}

! git grep -EIn $'[ \t]+$' -- ':(exclude)*.patch'

go install github.com/bazelbuild/buildtools/buildifier@latest
~/go/bin/buildifier --lint=warn -r ${GIT_ROOT}

