load("@rules_cc//cc:defs.bzl", "objc_library")
load("//:helper.bzl", "santa_unit_test")

package(
    default_visibility = ["//:santa_package_group"],
)

licenses(["notice"])

objc_library(
    name = "SNTMetricFormat",
    hdrs = ["SNTMetricFormat.h"],
)

objc_library(
    name = "SNTMetricFormatTestHelper",
    srcs = [
        "SNTMetricFormatTestHelper.mm",
    ],
    hdrs = ["SNTMetricFormatTestHelper.h"],
    deps = [
        "//Source/common:SNTMetricSet",
    ],
)

objc_library(
    name = "SNTMetricRawJSONFormat",
    srcs = [
        "SNTMetricFormat.h",
        "SNTMetricRawJSONFormat.h",
        "SNTMetricRawJSONFormat.mm",
    ],
    hdrs = [
        "SNTMetricRawJSONFormat.h",
    ],
    deps = [
        ":SNTMetricFormat",
        "//Source/common:SNTLogging",
    ],
)

objc_library(
    name = "SNTMetricMonarchJSONFormat",
    srcs = [
        "SNTMetricFormat.h",
        "SNTMetricMonarchJSONFormat.h",
        "SNTMetricMonarchJSONFormat.mm",
    ],
    hdrs = [
        "SNTMetricMonarchJSONFormat.h",
    ],
    deps = [
        ":SNTMetricFormat",
        "//Source/common:SNTLogging",
        "//Source/common:SNTMetricSet",
    ],
)

santa_unit_test(
    name = "SNTMetricRawJSONFormatTest",
    srcs = [
        "SNTMetricRawJSONFormatTest.mm",
    ],
    structured_resources = glob(["testdata/**"]),
    deps = [
        ":SNTMetricFormatTestHelper",
        ":SNTMetricRawJSONFormat",
    ],
)

santa_unit_test(
    name = "SNTMetricMonarchJSONFormatTest",
    srcs = [
        "SNTMetricMonarchJSONFormatTest.mm",
    ],
    structured_resources = [":testdata"],
    deps = [
        ":SNTMetricFormatTestHelper",
        ":SNTMetricMonarchJSONFormat",
        "@OCMock",
    ],
)

filegroup(
    name = "testdata",
    srcs = glob(["testdata/**"]),
)

test_suite(
    name = "format_tests",
    tests = [
        ":SNTMetricMonarchJSONFormatTest",
        ":SNTMetricRawJSONFormatTest",
    ],
)
