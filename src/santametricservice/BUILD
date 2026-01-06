load("@rules_apple//apple:macos.bzl", "macos_command_line_application")
load("@rules_cc//cc:defs.bzl", "objc_library")
load("//:helper.bzl", "SANTA_MINIMUM_OS_VERSION", "santa_unit_test")

licenses(["notice"])

objc_library(
    name = "SNTMetricServiceLib",
    srcs = [
        "SNTMetricService.h",
        "SNTMetricService.mm",
        "main.mm",
    ],
    hdrs = [
        "SNTMetricService.h",
    ],
    deps = [
        "//src/common:MOLCodesignChecker",
        "//src/common:MOLXPCConnection",
        "//src/common:SNTConfigurator",
        "//src/common:SNTDropRootPrivs",
        "//src/common:SNTLogging",
        "//src/common:SNTMetricSet",
        "//src/common:SNTXPCMetricServiceInterface",
        "//src/santametricservice/formats:SNTMetricMonarchJSONFormat",
        "//src/santametricservice/formats:SNTMetricRawJSONFormat",
        "//src/santametricservice/writers:SNTMetricFileWriter",
        "//src/santametricservice/writers:SNTMetricHTTPWriter",
    ],
)

santa_unit_test(
    name = "SNTMetricServiceTest",
    srcs = ["SNTMetricServiceTest.mm"],
    structured_resources = ["//src/santametricservice/formats:testdata"],
    deps = [
        ":SNTMetricServiceLib",
        "//src/common:MOLAuthenticatingURLSession",
        "//src/common:SNTCommonEnums",
        "//src/common:SNTConfigurator",
        "//src/common:SNTMetricSet",
        "//src/santametricservice/formats:SNTMetricFormatTestHelper",
        "@OCMock",
    ],
)

test_suite(
    name = "unit_tests",
    tests = [
        ":SNTMetricServiceTest",
        "//src/santametricservice/formats:format_tests",
        "//src/santametricservice/writers:writer_tests",
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
        "//src/common:CommitHash",
    ],
    minimum_os_version = SANTA_MINIMUM_OS_VERSION,
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
