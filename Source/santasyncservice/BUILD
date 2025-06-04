load("@rules_apple//apple:macos.bzl", "macos_command_line_application")
load("@rules_cc//cc:defs.bzl", "objc_library")
load("//:helper.bzl", "santa_unit_test")

licenses(["notice"])

objc_library(
    name = "FCM_lib",
    srcs = ["SNTSyncFCM.m"],
    hdrs = ["SNTSyncFCM.h"],
    sdk_frameworks = ["Network"],
    deps = [
        "//Source/common:MOLAuthenticatingURLSession",
    ],
)

objc_library(
    name = "polaris_lib",
    srcs = [
        "SNTPolaris.h",
        "SNTPolaris.mm",
    ],
    deps = [
        "//Source/common:SNTLogging",
        "//Source/common:SNTSystemInfo",
        "//Source/common:String",
        "@northpolesec_protos//stats:v1_cc_proto",
    ],
)

objc_library(
    name = "SNTSyncState",
    srcs = ["SNTSyncState.m"],
    hdrs = ["SNTSyncState.h"],
    deps = [
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTExportConfiguration",
    ],
)

objc_library(
    name = "SNTSyncConfigBundle",
    srcs = ["SNTSyncConfigBundle.mm"],
    hdrs = ["SNTSyncConfigBundle.h"],
    deps = [
        ":SNTSyncState",
        "//Source/common:SNTConfigBundle",
        "//Source/common:SNTExportConfiguration",
    ],
)

santa_unit_test(
    name = "SNTSyncConfigBundleTest",
    srcs = ["SNTSyncConfigBundleTest.mm"],
    deps = [
        ":SNTSyncConfigBundle",
        ":SNTSyncState",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigBundle",
    ],
)

# This setting is used to enable storing all sync requests as JSON files on disk.
# This can be useful for debugging purposes.
config_setting(
    name = "store_json_uploads",
    values = {"define": "SANTA_STORE_SYNC_JSON=1"},
)

objc_library(
    name = "sync_lib",
    srcs = [
        "NSData+Zlib.h",
        "NSData+Zlib.m",
        "SNTPushClientAPNS.h",
        "SNTPushClientAPNS.m",
        "SNTPushClientFCM.h",
        "SNTPushClientFCM.m",
        "SNTPushNotifications.h",
        "SNTPushNotificationsTracker.h",
        "SNTPushNotificationsTracker.m",
        "SNTSyncEventUpload.h",
        "SNTSyncEventUpload.mm",
        "SNTSyncLogging.h",
        "SNTSyncLogging.m",
        "SNTSyncManager.m",
        "SNTSyncPostflight.h",
        "SNTSyncPostflight.mm",
        "SNTSyncPreflight.h",
        "SNTSyncPreflight.mm",
        "SNTSyncRuleDownload.h",
        "SNTSyncRuleDownload.mm",
        "SNTSyncStage.h",
        "SNTSyncStage.mm",
    ],
    hdrs = ["SNTSyncManager.h"],
    defines = select({
        ":store_json_uploads": ["SANTA_STORE_SYNC_JSON"],
        "//conditions:default": [],
    }),
    sdk_dylibs = ["libz"],
    sdk_frameworks = ["Network"],
    deps = [
        ":FCM_lib",
        ":SNTSyncConfigBundle",
        ":SNTSyncState",
        ":broadcaster_lib",
        ":polaris_lib",
        "//Source/common:EncodeEntitlements",
        "//Source/common:MOLAuthenticatingURLSession",
        "//Source/common:MOLCertificate",
        "//Source/common:MOLXPCConnection",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTError",
        "//Source/common:SNTFileInfo",
        "//Source/common:SNTLogging",
        "//Source/common:SNTRule",
        "//Source/common:SNTSIPStatus",
        "//Source/common:SNTStoredEvent",
        "//Source/common:SNTStrengthify",
        "//Source/common:SNTSyncConstants",
        "//Source/common:SNTSystemInfo",
        "//Source/common:SNTXPCControlInterface",
        "//Source/common:SNTXPCSyncServiceInterface",
        "//Source/common:String",
        "@northpolesec_protos//sync:v1_cc_proto",
        "@protobuf//src/google/protobuf/json",
    ],
)

# Using :sync_lib breaks the Zlib category hack used in the tests to
# disable compression, in turn failing the tests. Re-compile here to keep
# the "override" category behavior.
santa_unit_test(
    name = "SNTSyncTest",
    srcs = [
        "NSData+Zlib.h",
        "NSData+Zlib.m",
        "SNTPushClientAPNS.h",
        "SNTPushClientAPNS.m",
        "SNTPushClientFCM.h",
        "SNTPushClientFCM.m",
        "SNTPushNotifications.h",
        "SNTPushNotificationsTracker.h",
        "SNTPushNotificationsTracker.m",
        "SNTSyncEventUpload.h",
        "SNTSyncEventUpload.mm",
        "SNTSyncLogging.h",
        "SNTSyncLogging.m",
        "SNTSyncPostflight.h",
        "SNTSyncPostflight.mm",
        "SNTSyncPreflight.h",
        "SNTSyncPreflight.mm",
        "SNTSyncRuleDownload.h",
        "SNTSyncRuleDownload.mm",
        "SNTSyncStage.h",
        "SNTSyncStage.mm",
        "SNTSyncTest.mm",
    ],
    resources = glob([
        "testdata/*.json",
        "testdata/*.plist",
    ]),
    sdk_dylibs = ["libz"],
    deps = [
        ":FCM_lib",
        ":SNTSyncConfigBundle",
        ":SNTSyncState",
        ":broadcaster_lib",
        "//Source/common:EncodeEntitlements",
        "//Source/common:MOLAuthenticatingURLSession",
        "//Source/common:MOLCertificate",
        "//Source/common:MOLXPCConnection",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTDropRootPrivs",
        "//Source/common:SNTFileInfo",
        "//Source/common:SNTLogging",
        "//Source/common:SNTRule",
        "//Source/common:SNTSIPStatus",
        "//Source/common:SNTStoredEvent",
        "//Source/common:SNTStrengthify",
        "//Source/common:SNTSyncConstants",
        "//Source/common:SNTSystemInfo",
        "//Source/common:SNTXPCControlInterface",
        "//Source/common:String",
        "@OCMock",
        "@northpolesec_protos//sync:v1_cc_proto",
        "@protobuf//src/google/protobuf/json",
    ],
)

santa_unit_test(
    name = "NSDataZlibTest",
    srcs = [
        "NSData+Zlib.h",
        "NSData+Zlib.m",
        "NSDataZlibTest.m",
    ],
    resources = glob(["testdata/sync_preflight_basic.*"]),
    sdk_dylibs = ["libz"],
)

objc_library(
    name = "broadcaster_lib",
    srcs = ["SNTSyncBroadcaster.m"],
    hdrs = ["SNTSyncBroadcaster.h"],
    deps = [
        "//Source/common:MOLXPCConnection",
        "//Source/common:SNTXPCSyncServiceInterface",
    ],
)

objc_library(
    name = "santass_lib",
    srcs = [
        "SNTSyncService.h",
        "SNTSyncService.mm",
        "main.m",
    ],
    deps = [
        ":broadcaster_lib",
        ":sync_lib",
        "//Source/common:MOLCodesignChecker",
        "//Source/common:MOLXPCConnection",
        "//Source/common:SNTDropRootPrivs",
        "//Source/common:SNTExportConfiguration",
        "//Source/common:SNTLogging",
        "//Source/common:SNTStrengthify",
        "//Source/common:SNTXPCControlInterface",
        "//Source/common:SNTXPCSyncServiceInterface",
    ],
)

macos_command_line_application(
    name = "santasyncservice",
    bundle_id = "com.northpolesec.santa.syncservice",
    codesignopts = [
        "--force",
        "--options library,kill,runtime",
    ],
    infoplists = ["Info.plist"],
    minimum_os_version = "13.0",
    provisioning_profile = select({
        "//:adhoc_build": None,
        "//conditions:default": "//profiles:santa_dev",
    }),
    version = "//:version",
    visibility = ["//:santa_package_group"],
    deps = [":santass_lib"],
)

test_suite(
    name = "unit_tests",
    tests = [
        ":NSDataZlibTest",
        ":SNTSyncConfigBundleTest",
        ":SNTSyncTest",
    ],
    visibility = ["//:santa_package_group"],
)
