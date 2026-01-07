load("@rules_apple//apple:macos.bzl", "macos_command_line_application")
load("@rules_cc//cc:defs.bzl", "objc_library")
load("//:helper.bzl", "SANTA_MINIMUM_OS_VERSION", "santa_unit_test")

package(
    default_visibility = ["//:santa_package_group"],
)

licenses(["notice"])

objc_library(
    name = "SNTStoredEventArchiveGenerator",
    srcs = ["SNTStoredEventArchiveGenerator.mm"],
    deps = [
        "//Source/common:MOLCodesignChecker",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTStoredExecutionEvent",
        "//Source/common:SNTStoredFileAccessEvent",
        "//Source/common:SNTStoredNetworkMountEvent",
        "//Source/common:SNTStoredTemporaryMonitorModeAuditEvent",
    ],
)

objc_library(
    name = "SNTFileAccessRuleArchiveGenerator",
    srcs = ["SNTFileAccessRuleArchiveGenerator.mm"],
    deps = [
        "//Source/common:SNTFileAccessRule",
        "//Source/common/faa:WatchItems",
    ],
)

santa_unit_test(
    name = "OneOffBuildAll",
    deps = [
        ":SNTFileAccessRuleArchiveGenerator",
        ":SNTStoredEventArchiveGenerator",
    ],
)

test_suite(
    name = "BuildOnly",
    tests = [
        ":OneOffBuildAll",
    ],
)

macos_command_line_application(
    name = "stored_event_generator",
    bundle_id = "com.northpolesec.testing.stored_event_generator",
    codesignopts = [
        "--force",
        "--options library,kill,runtime",
    ],
    infoplists = None,
    minimum_os_version = SANTA_MINIMUM_OS_VERSION,
    provisioning_profile = None,
    version = "//:version",
    visibility = ["//:santa_package_group"],
    deps = [":SNTStoredEventArchiveGenerator"],
)

macos_command_line_application(
    name = "file_access_rule_generator",
    bundle_id = "com.northpolesec.testing.stored_event_generator",
    codesignopts = [
        "--force",
        "--options library,kill,runtime",
    ],
    infoplists = None,
    minimum_os_version = SANTA_MINIMUM_OS_VERSION,
    provisioning_profile = None,
    version = "//:version",
    visibility = ["//:santa_package_group"],
    deps = [":SNTFileAccessRuleArchiveGenerator"],
)
