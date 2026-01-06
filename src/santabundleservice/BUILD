load("@rules_apple//apple:macos.bzl", "macos_command_line_application")
load("@rules_cc//cc:defs.bzl", "objc_library")
load("//:helper.bzl", "SANTA_MINIMUM_OS_VERSION")

licenses(["notice"])

objc_library(
    name = "santabs_lib",
    srcs = [
        "SNTBundleService.h",
        "SNTBundleService.mm",
        "main.mm",
    ],
    deps = [
        "//src/common:MOLCodesignChecker",
        "//src/common:MOLXPCConnection",
        "//src/common:SNTFileInfo",
        "//src/common:SNTLogging",
        "//src/common:SNTStoredExecutionEvent",
        "//src/common:SNTXPCBundleServiceInterface",
        "//src/common:SNTXPCNotifierInterface",
        "//src/common:SigningIDHelpers",
        "@FMDB",
    ],
)

macos_command_line_application(
    name = "santabundleservice",
    bundle_id = "com.northpolesec.santa.bundleservice",
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
    deps = [":santabs_lib"],
)
