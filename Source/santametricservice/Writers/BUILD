load("@rules_cc//cc:defs.bzl", "objc_library")
load("//:helper.bzl", "santa_unit_test")

package(
    default_visibility = ["//:santa_package_group"],
)

licenses(["notice"])

objc_library(
    name = "SNTMetricWriter",
    hdrs = ["SNTMetricWriter.h"],
)

objc_library(
    name = "SNTMetricFileWriter",
    srcs = [
        "SNTMetricFileWriter.h",
        "SNTMetricFileWriter.mm",
    ],
    hdrs = [
        "SNTMetricFileWriter.h",
    ],
    deps = [
        ":SNTMetricWriter",
        "//Source/common:SNTLogging",
    ],
)

santa_unit_test(
    name = "SNTMetricFileWriterTest",
    srcs = [
        "SNTMetricFileWriterTest.mm",
    ],
    deps = [
        ":SNTMetricFileWriter",
        "//Source/common:SNTConfigurator",
    ],
)

objc_library(
    name = "SNTMetricHTTPWriter",
    srcs = [
        "SNTMetricHTTPWriter.h",
        "SNTMetricHTTPWriter.mm",
    ],
    hdrs = [
        "SNTMetricHTTPWriter.h",
    ],
    deps = [
        ":SNTMetricWriter",
        "//Source/common:MOLAuthenticatingURLSession",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTLogging",
    ],
)

santa_unit_test(
    name = "SNTMetricHTTPWriterTest",
    srcs = [
        "SNTMetricHTTPWriterTest.mm",
    ],
    deps = [
        ":SNTMetricHTTPWriter",
        "//Source/common:MOLAuthenticatingURLSession",
        "//Source/common:SNTConfigurator",
        "@OCMock",
    ],
)

test_suite(
    name = "writer_tests",
    tests = [
        ":SNTMetricFileWriterTest",
        ":SNTMetricHTTPWriterTest",
    ],
)
