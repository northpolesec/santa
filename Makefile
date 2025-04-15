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

compile_commands:
	# Build all targets under source so any generated code will be emitted and
	# available for compile command construction.
	bazel build //Source/...
	bazel run :refresh_compile_commands

.PHONY: fmt build test reload clean realclean compile_commands
