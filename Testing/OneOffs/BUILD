load("@rules_cc//cc:defs.bzl", "objc_library")
load("@rules_apple//apple:macos.bzl", "macos_command_line_application")
load("//:helper.bzl", "santa_unit_test")

package(
    default_visibility = ["//:santa_package_group"],
)

licenses(["notice"])

objc_library(
    name = "SNTStoredEventArchiveGenerator",
    srcs = ["SNTStoredEventArchiveGenerator.mm"],
    deps = [
        "//Source/common:SNTStoredExecutionEvent",
        "//Source/common:SNTStoredFileAccessEvent",
        "//Source/common:SNTCommonEnums",
        "//Source/common:MOLCodesignChecker",
    ],
)

santa_unit_test(
  name = "SNTStoredEventArchiveGeneratorTest",
  deps = [
      ":SNTStoredEventArchiveGenerator",
  ],
)

test_suite(
  name = "BuildOnly",
  tests = [
    ":SNTStoredEventArchiveGeneratorTest",
  ]
)

macos_command_line_application(
    name = "stored_event_generator",
    bundle_id = "com.northpolesec.testing.stored_event_generator",
    codesignopts = [
        "--force",
        "--options library,kill,runtime",
    ],
    infoplists = None,
    minimum_os_version = "15.0",
    provisioning_profile = None,
    version = "//:version",
    visibility = ["//:santa_package_group"],
    deps = [":SNTStoredEventArchiveGenerator"],
)
