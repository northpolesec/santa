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
        "//src/common:MOLXPCConnection",
        "//src/common:SNTLogging",
        "//src/common:SNTXPCControlInterface",
    ],
)

objc_library(
    name = "SNTCommandPrintLog",
    srcs = ["commands/SNTCommandPrintLog.mm"],
    deps = [
        ":santactl_cmd",
        "//src/common:NSData+Zlib",
        "//src/common:SNTLogging",
        "//src/common:SNTXxhash",
        "//src/common:ScopedFile",
        "//src/common:santa_cc_proto_library_wrapper",
        "//src/santad/logs/endpoint_security/writers/fsspool:SpoolBatchers",
        "//src/santad/logs/endpoint_security/writers/fsspool:binaryproto_cc_proto_library_wrapper",
        "@abseil-cpp//absl/status:statusor",
        "@protobuf//src/google/protobuf/json",
        "@zstd",
    ],
)

objc_library(
    name = "SNTCommandInstall",
    srcs = ["commands/SNTCommandInstall.mm"],
    deps = [
        ":santactl_cmd",
        "//src/common:MOLXPCConnection",
        "//src/common:SNTLogging",
        "//src/common:SNTXPCControlInterface",
    ],
)

objc_library(
    name = "SNTCommandTelemetry",
    srcs = ["commands/SNTCommandTelemetry.mm"],
    deps = [
        ":santactl_cmd",
        "//src/common:MOLXPCConnection",
        "//src/common:SNTLogging",
        "//src/common:SNTXPCControlInterface",
    ],
)

objc_library(
    name = "SNTCommandCommand",
    srcs = ["commands/SNTCommandCommand.mm"],
    deps = [
        ":santactl_cmd",
        "//src/common:MOLXPCConnection",
        "//src/common:SNTKillCommand",
        "//src/common:SNTLogging",
        "//src/common:SNTXPCControlInterface",
    ],
)

objc_library(
    name = "SNTCommandMonitorMode",
    srcs = ["commands/SNTCommandMonitorMode.mm"],
    deps = [
        ":santactl_cmd",
        "//src/common:MOLXPCConnection",
        "//src/common:SNTLogging",
        "//src/common:SNTXPCControlInterface",
    ],
)

objc_library(
    name = "santactl_lib",
    srcs = [
        "commands/SNTCommandCheckCache.mm",
        "commands/SNTCommandDoctor.mm",
        "commands/SNTCommandEventUpload.mm",
        "commands/SNTCommandFileInfo.mm",
        "commands/SNTCommandFlushCache.mm",
        "commands/SNTCommandMetrics.h",
        "commands/SNTCommandMetrics.mm",
        "commands/SNTCommandRule.mm",
        "commands/SNTCommandStatus.mm",
        "commands/SNTCommandSync.mm",
        "commands/SNTCommandVersion.mm",
        "main.mm",
    ] + select({
        "//:opt_build": [],
        "//conditions:default": [
            "commands/SNTCommandBundleInfo.mm",
        ],
    }),
    sdk_dylibs = ["libz"],
    sdk_frameworks = ["IOKit"],
    deps = [
        ":SNTCommandCommand",
        ":SNTCommandInstall",
        ":SNTCommandMonitorMode",
        ":SNTCommandPrintLog",
        ":SNTCommandTelemetry",
        ":santactl_cmd",
        "//src/common:CertificateHelpers",
        "//src/common:MOLAuthenticatingURLSession",
        "//src/common:MOLCertificate",
        "//src/common:MOLCodesignChecker",
        "//src/common:MOLXPCConnection",
        "//src/common:SNTCachedDecision",
        "//src/common:SNTCommonEnums",
        "//src/common:SNTConfigurator",
        "//src/common:SNTDropRootPrivs",
        "//src/common:SNTFileInfo",
        "//src/common:SNTLogging",
        "//src/common:SNTMetricSet",
        "//src/common:SNTRule",
        "//src/common:SNTRuleIdentifiers",
        "//src/common:SNTStoredExecutionEvent",
        "//src/common:SNTStrengthify",
        "//src/common:SNTSystemInfo",
        "//src/common:SNTXPCBundleServiceInterface",
        "//src/common:SNTXPCControlInterface",
        "//src/common:SNTXPCSyncServiceInterface",
        "//src/common:SNTXPCUnprivilegedControlInterface",
        "//src/common:SigningIDHelpers",
        "//src/common:SystemResources",
        "//src/common/faa:WatchItems",
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
        "//src/common:CommitHash",
    ],
    minimum_os_version = SANTA_MINIMUM_OS_VERSION,
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
        "commands/SNTCommandFileInfo.mm",
        "commands/SNTCommandFileInfoTest.mm",
        "SNTCommand.h",
        "SNTCommand.mm",
        "SNTCommandController.h",
        "SNTCommandController.mm",
    ],
    deps = [
        "//src/common:MOLCertificate",
        "//src/common:MOLCodesignChecker",
        "//src/common:MOLXPCConnection",
        "//src/common:SNTCachedDecision",
        "//src/common:SNTCommonEnums",
        "//src/common:SNTFileInfo",
        "//src/common:SNTLogging",
        "//src/common:SNTRule",
        "//src/common:SNTRuleIdentifiers",
        "//src/common:SNTStoredExecutionEvent",
        "//src/common:SNTXPCBundleServiceInterface",
        "//src/common:SNTXPCControlInterface",
        "//src/common:SigningIDHelpers",
        "@OCMock",
    ],
)

santa_unit_test(
    name = "SNTCommandMetricsTest",
    srcs = [
        "commands/SNTCommandMetrics.h",
        "commands/SNTCommandMetricsTest.mm",
        "SNTCommand.h",
        "SNTCommandController.h",
    ],
    structured_resources = glob(["commands/testdata/*"]),
    visibility = ["//:santa_package_group"],
    deps = [
        ":santactl_lib",
        "//src/common:MOLXPCConnection",
        "//src/common:SNTCommonEnums",
        "//src/common:SNTConfigurator",
        "//src/common:SNTMetricSet",
        "//src/common:SNTXPCControlInterface",
        "//src/santametricservice/formats:SNTMetricFormatTestHelper",
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
