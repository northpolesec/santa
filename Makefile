default: fmt build

fmt:
	./Testing/fix.sh

build:
	bazel build -c opt //Source/gui:Santa

test:
	bazel test --define=SANTA_BUILD_TYPE=adhoc --test_output=errors //:unit_tests

v2release:
	bazel build -c opt --apple_generate_dsym --copt=-DSANTA_FORCE_SYNC_V2=1 --macos_cpus=arm64,x86_64 //:release

v2release-notls:
	bazel build -c opt --apple_generate_dsym --copt=-DSANTA_FORCE_SYNC_V2=1 --copt=-DSANTA_NATS_DISABLE_TLS=1 --macos_cpus=arm64,x86_64 //:release

debugrelease:
	bazel build -c opt --apple_generate_dsym --copt=-DDEBUG=1 --copt=-DSANTA_FORCE_SYNC_V2=1 --copt=-DSANTA_NATS_DISABLE_TLS=1 --macos_cpus=arm64,x86_64 //:release

devrelease:
	bazel build -c opt --apple_generate_dsym --macos_cpus=arm64,x86_64 //:release

reload:
	bazel run //:reload

clean:
	bazel clean

realclean:
	bazel clean --expunge

compile_commands:
	# Build all targets under source so any generated code will be emitted and
	# available for compile command construction. The --keep_going flag ensures
	# cc_proto_library targets are built and visible to the
	# refresh_compile_commands rule.
	bazel build --keep_going //Source/...
	bazel run :refresh_compile_commands

.PHONY: fmt build test devrelease reload clean realclean compile_commands
