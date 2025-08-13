load("@rules_apple//apple:macos.bzl", "macos_command_line_application")
load("@rules_cc//cc:defs.bzl", "objc_library")
load("//:helper.bzl", "santa_unit_test")

licenses(["notice"])

objc_library(
    name = "santactl_cmd",
    srcs = [
        "SNTCommand.mm",
        "SNTCommandController.mm",
    ],
    hdrs = [
        "SNTCommand.h",
        "SNTCommandController.h",
    ],
    deps = [
        "//Source/common:MOLXPCConnection",
        "//Source/common:SNTLogging",
        "//Source/common:SNTXPCControlInterface",
    ],
)

objc_library(
    name = "SNTCommandPrintLog",
    srcs = ["Commands/SNTCommandPrintLog.mm"],
    deps = [
        ":santactl_cmd",
        "//Source/common:SNTLogging",
        "//Source/common:santa_cc_proto_library_wrapper",
        "//Source/santad/Logs/EndpointSecurity/Writers/FSSpool:SpoolBatchers",
        "//Source/santad/Logs/EndpointSecurity/Writers/FSSpool:binaryproto_cc_proto_library_wrapper",
        "@protobuf//src/google/protobuf/json",
    ],
)

objc_library(
    name = "SNTCommandInstall",
    srcs = ["Commands/SNTCommandInstall.mm"],
    deps = [
        ":santactl_cmd",
        "//Source/common:MOLXPCConnection",
        "//Source/common:SNTLogging",
        "//Source/common:SNTXPCControlInterface",
    ],
)

objc_library(
    name = "SNTCommandTelemetry",
    srcs = ["Commands/SNTCommandTelemetry.mm"],
    deps = [
        ":santactl_cmd",
        "//Source/common:MOLXPCConnection",
        "//Source/common:SNTLogging",
        "//Source/common:SNTXPCControlInterface",
    ],
)

objc_library(
    name = "santactl_lib",
    srcs = [
        "Commands/SNTCommandCheckCache.mm",
        "Commands/SNTCommandDoctor.mm",
        "Commands/SNTCommandEventUpload.mm",
        "Commands/SNTCommandFileInfo.mm",
        "Commands/SNTCommandFlushCache.mm",
        "Commands/SNTCommandMetrics.h",
        "Commands/SNTCommandMetrics.mm",
        "Commands/SNTCommandRule.h",
        "Commands/SNTCommandRule.mm",
        "Commands/SNTCommandStatus.mm",
        "Commands/SNTCommandSync.mm",
        "Commands/SNTCommandVersion.mm",
        "main.mm",
    ] + select({
        "//:opt_build": [],
        "//conditions:default": [
            "Commands/SNTCommandBundleInfo.mm",
        ],
    }),
    sdk_dylibs = ["libz"],
    sdk_frameworks = ["IOKit"],
    deps = [
        ":SNTCommandInstall",
        ":SNTCommandPrintLog",
        ":SNTCommandTelemetry",
        ":santactl_cmd",
        "//Source/common:CertificateHelpers",
        "//Source/common:MOLAuthenticatingURLSession",
        "//Source/common:MOLCertificate",
        "//Source/common:MOLCodesignChecker",
        "//Source/common:MOLXPCConnection",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTDropRootPrivs",
        "//Source/common:SNTFileInfo",
        "//Source/common:SNTLogging",
        "//Source/common:SNTMetricSet",
        "//Source/common:SNTRule",
        "//Source/common:SNTRuleIdentifiers",
        "//Source/common:SNTStoredExecutionEvent",
        "//Source/common:SNTStrengthify",
        "//Source/common:SNTSystemInfo",
        "//Source/common:SNTXPCBundleServiceInterface",
        "//Source/common:SNTXPCControlInterface",
        "//Source/common:SNTXPCSyncServiceInterface",
        "//Source/common:SNTXPCUnprivilegedControlInterface",
        "//Source/common:SigningIDHelpers",
        "//Source/common:SystemResources",
        "@FMDB",
        "@abseil-cpp//absl/cleanup:cleanup",
    ],
)

macos_command_line_application(
    name = "santactl",
    bundle_id = "com.northpolesec.santa.ctl",
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
    deps = [":santactl_lib"],
)

santa_unit_test(
    name = "SNTCommandFileInfoTest",
    srcs = [
        "Commands/SNTCommandFileInfo.mm",
        "Commands/SNTCommandFileInfoTest.mm",
        "SNTCommand.h",
        "SNTCommand.mm",
        "SNTCommandController.h",
        "SNTCommandController.mm",
    ],
    deps = [
        "//Source/common:MOLCertificate",
        "//Source/common:MOLCodesignChecker",
        "//Source/common:MOLXPCConnection",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTFileInfo",
        "//Source/common:SNTLogging",
        "//Source/common:SNTRule",
        "//Source/common:SNTRuleIdentifiers",
        "//Source/common:SNTStoredExecutionEvent",
        "//Source/common:SNTXPCBundleServiceInterface",
        "//Source/common:SNTXPCControlInterface",
        "//Source/common:SigningIDHelpers",
        "@OCMock",
    ],
)

santa_unit_test(
    name = "SNTCommandMetricsTest",
    srcs = [
        "Commands/SNTCommandMetrics.h",
        "Commands/SNTCommandMetricsTest.mm",
        "SNTCommand.h",
        "SNTCommandController.h",
    ],
    structured_resources = glob(["Commands/testdata/*"]),
    visibility = ["//:santa_package_group"],
    deps = [
        ":santactl_lib",
        "//Source/common:MOLXPCConnection",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTMetricSet",
        "//Source/common:SNTXPCControlInterface",
        "//Source/santametricservice/Formats:SNTMetricFormatTestHelper",
        "@OCMock",
    ],
)

test_suite(
    name = "unit_tests",
    tests = [
        ":SNTCommandFileInfoTest",
        ":SNTCommandMetricsTest",
    ],
    visibility = ["//:santa_package_group"],
)
