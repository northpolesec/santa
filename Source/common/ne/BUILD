load("@rules_cc//cc:defs.bzl", "objc_library")
load("//:helper.bzl", "santa_unit_test")

package(
    default_visibility = ["//visibility:public"],
)

licenses(["notice"])

objc_library(
    name = "SNTNetworkExtensionSettings",
    srcs = ["SNTNetworkExtensionSettings.mm"],
    hdrs = ["SNTNetworkExtensionSettings.h"],
    deps = [
        "//Source/common:CoderMacros",
        "//Source/common:SNTLogging",
    ],
)

santa_unit_test(
    name = "SNTNetworkExtensionSettingsTest",
    srcs = ["SNTNetworkExtensionSettingsTest.mm"],
    deps = [
        ":SNTNetworkExtensionSettings",
    ],
)

test_suite(
    name = "unit_tests",
    tests = [
        ":SNTNetworkExtensionSettingsTest",
    ],
)
