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
    ],
)

objc_library(
    name = "SNTNetworkExtensionConfig",
    srcs = ["SNTNetworkExtensionConfig.mm"],
    hdrs = ["SNTNetworkExtensionConfig.h"],
    deps = [
        ":SNTNetworkExtensionSettings",
        "//Source/common:CoderMacros",
        "//Source/common:SNTNetworkFlowRule",
    ],
)

objc_library(
    name = "SNDXPCNetworkExtensionInterface",
    hdrs = ["SNDXPCNetworkExtensionInterface.h"],
    deps = [
        ":SNTNetworkExtensionConfig",
    ],
)

objc_library(
    name = "SNTXPCNetworkExtensionInterface",
    srcs = ["SNTXPCNetworkExtensionInterface.mm"],
    hdrs = ["SNTXPCNetworkExtensionInterface.h"],
    deps = [
        ":SNDXPCNetworkExtensionInterface",
        ":SNTNetworkExtensionConfig",
        ":SNTNetworkExtensionSettings",
        "//Source/common:MOLCodesignChecker",
        "//Source/common:MOLXPCConnection",
        "//Source/common:SNTNetworkFlowRule",
    ],
)

objc_library(
    name = "SNTSyncNetworkExtensionSettings",
    srcs = ["SNTSyncNetworkExtensionSettings.mm"],
    hdrs = ["SNTSyncNetworkExtensionSettings.h"],
    deps = [
        ":SNTNetworkExtensionSettings",
        "//Source/common:CoderMacros",
        "//Source/common:SNTLogging",
    ],
)

santa_unit_test(
    name = "SNTSyncNetworkExtensionSettingsTest",
    srcs = ["SNTSyncNetworkExtensionSettingsTest.mm"],
    deps = [
        ":SNTSyncNetworkExtensionSettings",
    ],
)

santa_unit_test(
    name = "SNTNetworkExtensionSettingsTest",
    srcs = ["SNTNetworkExtensionSettingsTest.mm"],
    deps = [
        ":SNTNetworkExtensionSettings",
    ],
)

santa_unit_test(
    name = "SNTNetworkExtensionConfigTest",
    srcs = ["SNTNetworkExtensionConfigTest.mm"],
    deps = [
        ":SNTNetworkExtensionConfig",
        ":SNTNetworkExtensionSettings",
        "//Source/common:SNTNetworkFlowRule",
    ],
)

test_suite(
    name = "unit_tests",
    tests = [
        ":SNTNetworkExtensionConfigTest",
        ":SNTNetworkExtensionSettingsTest",
        ":SNTSyncNetworkExtensionSettingsTest",
    ],
)
