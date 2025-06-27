load("@rules_apple//apple:macos.bzl", "macos_command_line_application")
load("@rules_swift//swift:swift_library.bzl", "swift_library")
load("//:helper.bzl", "santa_swift_unit_test")

licenses(["notice"])

swift_library(
    name = "santactl_lib",
    srcs = [
        "bundleinfo.swift",
        "doctor.swift",
        "eventupload.swift",
        "fileinfo.swift",
        "flushcache.swift",
        "install.swift",
        "metrics.swift",
        "printlog.swift",
        "rule.swift",
        "santactl.swift",
        "status.swift",
        "sync.swift",
        "telemetry.swift",
        "version.swift",
    ],
    module_name = "santactl",
    deps = [
        "//Source/common:CertificateHelpers",
        "//Source/common:MOLCertificate",
        "//Source/common:MOLCodesignChecker",
        "//Source/common:MOLXPCConnection",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTDropRootPrivs",
        "//Source/common:SNTFileInfo",
        "//Source/common:SNTMetricSet",
        "//Source/common:SNTRule",
        "//Source/common:SNTRuleIdentifiers",
        "//Source/common:SNTXPCBundleServiceInterface",
        "//Source/common:SNTXPCControlInterface",
        "//Source/common:SNTXPCSyncServiceInterface",
        "//Source/common:SigningIDHelpers",
        "@swift_argument_parser//:ArgumentParser",
    ],
)

santa_swift_unit_test(
    name = "rule_test",
    srcs = ["rule_test.swift"],
    deps = [
        ":santactl_lib",
        "@swift_argument_parser//:ArgumentParser",
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

test_suite(
    name = "unit_tests",
    tests = [
    ],
    visibility = ["//:santa_package_group"],
)
