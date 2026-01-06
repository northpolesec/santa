#!/bin/bash
GIT_ROOT=$(git rev-parse --show-toplevel)
BUILDIFIER=$(which buildifier 2>/dev/null || echo "${GOPATH:-${HOME}/go}/bin/buildifier")

/usr/bin/find ${GIT_ROOT} \( -name "*.m" -o -name "*.h" -o -name "*.mm" -o -name "*.cc" \) -exec xcrun clang-format -i {} \+
/usr/bin/xcrun swift format -i -r ${GIT_ROOT}
${BUILDIFIER} --lint=fix -r ${GIT_ROOT}
