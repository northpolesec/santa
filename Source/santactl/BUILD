load("@rules_apple//apple:macos.bzl", "macos_command_line_application")
load("@rules_cc//cc:defs.bzl", "objc_library")
load("//:helper.bzl", "SANTA_MINIMUM_OS_VERSION", "santa_unit_test")

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
        "//Source/common:NSData+Zlib",
        "//Source/common:SNTLogging",
        "//Source/common:SNTXxhash",
        "//Source/common:ScopedFile",
        "//Source/common:santa_cc_proto",
        "//Source/santad/Logs/EndpointSecurity/Writers/FSSpool:SpoolBatchers",
        "//Source/santad/Logs/EndpointSecurity/Writers/FSSpool:binaryproto_cc_proto",
        "@abseil-cpp//absl/status:statusor",
        "@protobuf//src/google/protobuf/json",
        "@zstd",
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
    name = "SNTCommandCommand",
    srcs = ["Commands/SNTCommandCommand.mm"],
    deps = [
        ":santactl_cmd",
        "//Source/common:MOLXPCConnection",
        "//Source/common:SNTKillCommand",
        "//Source/common:SNTLogging",
        "//Source/common:SNTXPCControlInterface",
    ],
)

objc_library(
    name = "SNTCommandMonitorMode",
    srcs = ["Commands/SNTCommandMonitorMode.mm"],
    deps = [
        ":santactl_cmd",
        "//Source/common:MOLXPCConnection",
        "//Source/common:SNTLogging",
        "//Source/common:SNTXPCControlInterface",
    ],
)

objc_library(
    name = "SNTCommandSandbox",
    srcs = ["Commands/SNTCommandSandbox.mm"],
    deps = [
        ":santactl_cmd",
        "//Source/common:MOLCodesignChecker",
        "//Source/common:MOLXPCConnection",
        "//Source/common:SNTFileInfo",
        "//Source/common:SNTRuleIdentifiers",
        "//Source/common:SNTSandboxExecRequest",
        "//Source/common:SNTXPCControlInterface",
        "//Source/common:SigningIDHelpers",
    ],
)

objc_library(
    name = "SNTCommandCheckCache",
    srcs = ["Commands/SNTCommandCheckCache.mm"],
    deps = [
        ":santactl_cmd",
        "//Source/common:MOLXPCConnection",
        "//Source/common:SNTLogging",
        "//Source/common:SNTXPCControlInterface",
    ],
)

objc_library(
    name = "SNTCommandDoctor",
    srcs = ["Commands/SNTCommandDoctor.mm"],
    sdk_frameworks = ["SystemConfiguration"],
    deps = [
        ":santactl_cmd",
        "//Source/common:MOLCertificate",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTLogging",
        "//Source/common:SNTXPCControlInterface",
        "//Source/common:SNTXPCSyncServiceInterface",
        "//Source/common:SNTXPCUnprivilegedControlInterface",
        "//Source/common:SystemResources",
        "//Source/common/faa:WatchItems",
    ],
)

objc_library(
    name = "SNTCommandFileInfo",
    srcs = ["Commands/SNTCommandFileInfo.mm"],
    deps = [
        ":santactl_cmd",
        "//Source/common:CertificateHelpers",
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
    ],
)

objc_library(
    name = "SNTCommandFlushCache",
    srcs = ["Commands/SNTCommandFlushCache.mm"],
    deps = [
        ":santactl_cmd",
        "//Source/common:MOLXPCConnection",
        "//Source/common:SNTLogging",
        "//Source/common:SNTXPCControlInterface",
    ],
)

objc_library(
    name = "SNTCommandInventory",
    srcs = ["Commands/SNTCommandInventory.mm"],
    deps = [
        ":santactl_cmd",
        "//Source/common:CertificateHelpers",
        "//Source/common:MOLCodesignChecker",
        "//Source/common:MOLXPCConnection",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTFileInfo",
        "//Source/common:SNTLogging",
        "//Source/common:SNTStoredExecutionEvent",
        "//Source/common:SNTXPCBundleServiceInterface",
        "//Source/common:SNTXPCControlInterface",
        "//Source/common:SNTXPCSyncServiceInterface",
        "//Source/common:SigningIDHelpers",
    ],
)

objc_library(
    name = "SNTCommandMetrics",
    srcs = ["Commands/SNTCommandMetrics.mm"],
    hdrs = ["Commands/SNTCommandMetrics.h"],
    deps = [
        ":santactl_cmd",
        "//Source/common:MOLXPCConnection",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTLogging",
        "//Source/common:SNTMetricSet",
        "//Source/common:SNTXPCControlInterface",
    ],
)

objc_library(
    name = "SNTCommandRule",
    srcs = ["Commands/SNTCommandRule.mm"],
    deps = [
        ":santactl_cmd",
        "//Source/common:MOLCertificate",
        "//Source/common:MOLCodesignChecker",
        "//Source/common:MOLXPCConnection",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTDropRootPrivs",
        "//Source/common:SNTFileInfo",
        "//Source/common:SNTLogging",
        "//Source/common:SNTRule",
        "//Source/common:SNTRuleIdentifiers",
        "//Source/common:SNTXPCControlInterface",
        "//Source/common/faa:WatchItems",
    ],
)

objc_library(
    name = "SNTCommandStatus",
    srcs = ["Commands/SNTCommandStatus.mm"],
    deps = [
        ":santactl_cmd",
        "//Source/common:MOLXPCConnection",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTXPCControlInterface",
        "//Source/common/faa:WatchItems",
    ],
)

objc_library(
    name = "SNTCommandSync",
    srcs = ["Commands/SNTCommandSync.mm"],
    deps = [
        ":santactl_cmd",
        "//Source/common:MOLXPCConnection",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTDropRootPrivs",
        "//Source/common:SNTLogging",
        "//Source/common:SNTXPCSyncServiceInterface",
    ],
)

objc_library(
    name = "SNTCommandVersion",
    srcs = ["Commands/SNTCommandVersion.mm"],
    deps = [
        ":santactl_cmd",
        "//Source/common:MOLXPCConnection",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTFileInfo",
        "//Source/common:SNTLiteDetector",
        "//Source/common:SNTXPCUnprivilegedControlInterface",
    ],
)

objc_library(
    name = "SNTCommandBundleInfo",
    srcs = ["Commands/SNTCommandBundleInfo.mm"],
    deps = [
        ":santactl_cmd",
        "//Source/common:MOLXPCConnection",
        "//Source/common:SNTFileInfo",
        "//Source/common:SNTLogging",
        "//Source/common:SNTStoredExecutionEvent",
        "//Source/common:SNTXPCBundleServiceInterface",
    ],
)

objc_library(
    name = "santactl_lib",
    srcs = ["main.mm"],
    sdk_dylibs = ["libz"],
    sdk_frameworks = [
        "IOKit",
        "SystemConfiguration",
    ],
    deps = [
        ":SNTCommandCheckCache",
        ":SNTCommandCommand",
        ":SNTCommandDoctor",
        ":SNTCommandFileInfo",
        ":SNTCommandFlushCache",
        ":SNTCommandInstall",
        ":SNTCommandInventory",
        ":SNTCommandMetrics",
        ":SNTCommandMonitorMode",
        ":SNTCommandPrintLog",
        ":SNTCommandRule",
        ":SNTCommandSandbox",
        ":SNTCommandStatus",
        ":SNTCommandSync",
        ":SNTCommandTelemetry",
        ":SNTCommandVersion",
        ":santactl_cmd",
        "//Source/common:MOLAuthenticatingURLSession",
    ] + select({
        "//:opt_build": [],
        "//conditions:default": [
            ":SNTCommandBundleInfo",
        ],
    }),
)

macos_command_line_application(
    name = "santactl",
    bundle_id = "com.northpolesec.santa.ctl",
    codesignopts = [
        "--timestamp=none",
        "--force",
        "--options library,kill,runtime",
    ],
    infoplists = [
        "Info.plist",
        "//Source/common:CommitHash",
    ],
    minimum_os_version = SANTA_MINIMUM_OS_VERSION,
    provisioning_profile = select({
        "//:adhoc_build": None,
        "//conditions:default": "@profiles//:santa_dev",
    }),
    version = "//:version",
    visibility = ["//:santa_package_group"],
    deps = [":santactl_lib"],
)

santa_unit_test(
    name = "SNTCommandFileInfoTest",
    srcs = ["Commands/SNTCommandFileInfoTest.mm"],
    deps = [
        ":SNTCommandFileInfo",
        ":santactl_cmd",
        "//Source/common:MOLCertificate",
        "//Source/common:MOLCodesignChecker",
        "//Source/common:MOLXPCConnection",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommonEnums",
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
    srcs = ["Commands/SNTCommandMetricsTest.mm"],
    structured_resources = glob(["Commands/testdata/*"]),
    visibility = ["//:santa_package_group"],
    deps = [
        ":SNTCommandMetrics",
        ":santactl_cmd",
        "//Source/common:MOLXPCConnection",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTMetricSet",
        "//Source/common:SNTXPCControlInterface",
        "//Source/santametricservice/Formats:SNTMetricFormatTestHelper",
        "@OCMock",
    ],
)

santa_unit_test(
    name = "SNTCommandDoctorTest",
    srcs = [
        "Commands/SNTCommandDoctorTest.mm",
    ],
    resources = [
        "Commands/testdata/example_org_client_cert.pem",
    ],
    visibility = ["//:santa_package_group"],
    deps = [
        ":SNTCommandDoctor",
        "//Source/common:MOLCertificate",
    ],
)

test_suite(
    name = "unit_tests",
    tests = [
        ":SNTCommandDoctorTest",
        ":SNTCommandFileInfoTest",
        ":SNTCommandMetricsTest",
    ],
    visibility = ["//:santa_package_group"],
)
