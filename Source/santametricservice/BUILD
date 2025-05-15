load("@rules_apple//apple:macos.bzl", "macos_command_line_application")
load("@rules_cc//cc:defs.bzl", "objc_library")
load("//:helper.bzl", "santa_unit_test")

licenses(["notice"])

objc_library(
    name = "SNTMetricServiceLib",
    srcs = [
        "SNTMetricService.h",
        "SNTMetricService.m",
        "main.m",
    ],
    hdrs = [
        "SNTMetricService.h",
    ],
    deps = [
        "//Source/common:MOLCodesignChecker",
        "//Source/common:MOLXPCConnection",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTDropRootPrivs",
        "//Source/common:SNTLogging",
        "//Source/common:SNTMetricSet",
        "//Source/common:SNTXPCMetricServiceInterface",
        "//Source/santametricservice/Formats:SNTMetricMonarchJSONFormat",
        "//Source/santametricservice/Formats:SNTMetricRawJSONFormat",
        "//Source/santametricservice/Writers:SNTMetricFileWriter",
        "//Source/santametricservice/Writers:SNTMetricHTTPWriter",
    ],
)

santa_unit_test(
    name = "SNTMetricServiceTest",
    srcs = ["SNTMetricServiceTest.m"],
    structured_resources = ["//Source/santametricservice/Formats:testdata"],
    deps = [
        ":SNTMetricServiceLib",
        "//Source/common:MOLAuthenticatingURLSession",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTMetricSet",
        "//Source/santametricservice/Formats:SNTMetricFormatTestHelper",
        "@OCMock",
    ],
)

test_suite(
    name = "unit_tests",
    tests = [
        ":SNTMetricServiceTest",
        "//Source/santametricservice/Formats:format_tests",
        "//Source/santametricservice/Writers:writer_tests",
    ],
)

macos_command_line_application(
    name = "santametricservice",
    bundle_id = "com.northpolesec.santa.metricservice",
    codesignopts = [
        "--force",
        "--options library,kill,runtime",
    ],
    infoplists = [
        "Info.plist",
        "//Source/common:CommitHash",
    ],
    minimum_os_version = "13.0",
    provisioning_profile = select({
        "//:adhoc_build": None,
        "//conditions:default": "//profiles:santa_dev",
    }),
    version = "//:version",
    visibility = ["//:santa_package_group"],
    deps = [
        ":SNTMetricServiceLib",
    ],
)
