default: fmt build

fmt:
	./Testing/fix.sh

build:
	bazel build -c opt //:release

test:
	bazel test --define=SANTA_BUILD_TYPE=adhoc --test_output=errors //:unit_tests

reload:
	bazel run //:reload

clean:
	bazel clean

realclean:
	bazel clean --expunge

.PHONY: fmt build test reload clean realclean
