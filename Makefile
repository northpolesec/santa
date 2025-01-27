default: fmt build

fmt:
	./Testing/fix.sh

build:
	bazel build -c opt //:release

test:
	bazel test --define=SANTA_BUILD_TYPE=adhoc --test_output=errors //:unit_tests

reload:
	bazel run //:reload

.PHONY: fmt build test reload
