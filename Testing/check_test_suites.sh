#!/bin/bash
#
# Checks that every santa_unit_test target is included in the top-level
# //:unit_tests test_suite (directly or transitively).
#
# Uses bazel query to compare all macos_unit_test targets against those
# reachable from //:unit_tests.
#
set -eo pipefail

GIT_ROOT=$(git rev-parse --show-toplevel)
cd "$GIT_ROOT"

# Tests that are intentionally excluded from //:unit_tests (e.g. integration tests).
EXCLUDED=(
  "//Source/santasyncservice:SNTPushClientNATSIntegrationTest"
)

echo "Checking for unit tests missing from //:unit_tests..."

all_tests=$(bazel query 'kind("macos_unit_test rule", //...)' 2>/dev/null | sort)
suite_tests=$(bazel query 'tests(//:unit_tests)' 2>/dev/null | sort)

missing=$(comm -23 <(echo "$all_tests") <(echo "$suite_tests"))

# Filter out excluded tests
for excl in "${EXCLUDED[@]}"; do
  missing=$(echo "$missing" | grep -vxF "$excl" || true)
done

# Trim whitespace
missing=$(echo "$missing" | sed '/^$/d')

if [[ -n "$missing" ]]; then
  echo "ERROR: The following test targets are not included in //:unit_tests:"
  echo "$missing" | sed 's/^/  /'
  echo ""
  echo "Add them to the appropriate unit_tests test_suite in their BUILD file,"
  echo "or add to EXCLUDED in this script if intentionally omitted."
  exit 1
fi

echo "All santa_unit_test targets are included in //:unit_tests."
