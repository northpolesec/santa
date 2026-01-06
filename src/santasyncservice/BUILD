load("@rules_apple//apple:macos.bzl", "macos_command_line_application")
load("@rules_cc//cc:defs.bzl", "objc_library")
load("//:helper.bzl", "SANTA_MINIMUM_OS_VERSION", "santa_unit_test")

licenses(["notice"])

objc_library(
    name = "FCM_lib",
    srcs = ["SNTSyncFCM.mm"],
    hdrs = ["SNTSyncFCM.h"],
    sdk_frameworks = ["Network"],
    deps = [
        "//src/common:MOLAuthenticatingURLSession",
    ],
)

objc_library(
    name = "NATS_lib",
    srcs = [
        "SNTPushClientNATS.mm",
        "SNTPushClientNATS+Commands.mm",
    ],
    hdrs = [
        "SNTPushClientNATS.h",
        "SNTPushClientNATS+Commands.h",
        "SNTPushNotifications.h",
    ],
    deps = [
        ":SNTSyncState",
        "//src/common:MOLXPCConnection",
        "//src/common:SNTConfigurator",
        "//src/common:SNTKillCommand",
        "//src/common:SNTLogging",
        "//src/common:SNTSyncConstants",
        "//src/common:SNTSystemInfo",
        "//src/common:SNTXPCControlInterface",
        "//src/common:String",
        "@abseil-cpp//absl/cleanup:cleanup",
        "@nats_c//:nats",
        "@northpolesec_protos//commands:v1_cc_proto",
    ],
)

objc_library(
    name = "polaris_lib",
    srcs = [
        "SNTPolaris.h",
        "SNTPolaris.mm",
    ],
    deps = [
        "//src/common:SNTLogging",
        "//src/common:SNTSystemInfo",
        "//src/common:String",
        "@northpolesec_protos//stats:v1_cc_proto",
    ],
)

objc_library(
    name = "SNTSyncState",
    srcs = ["SNTSyncState.mm"],
    hdrs = ["SNTSyncState.h"],
    deps = [
        "//src/common:SNTCommonEnums",
        "//src/common:SNTExportConfiguration",
        "//src/common:SNTModeTransition",
    ],
)

objc_library(
    name = "SNTSyncConfigBundle",
    srcs = ["SNTSyncConfigBundle.mm"],
    hdrs = ["SNTSyncConfigBundle.h"],
    deps = [
        ":SNTSyncState",
        "//src/common:SNTConfigBundle",
        "//src/common:SNTExportConfiguration",
        "//src/common:SNTModeTransition",
    ],
)

santa_unit_test(
    name = "SNTSyncConfigBundleTest",
    srcs = ["SNTSyncConfigBundleTest.mm"],
    deps = [
        ":SNTSyncConfigBundle",
        ":SNTSyncState",
        "//src/common:SNTCommonEnums",
        "//src/common:SNTConfigBundle",
        "//src/common:SNTModeTransition",
    ],
)

# This setting is used to enable storing all sync requests as JSON files on disk.
# This can be useful for debugging purposes.
config_setting(
    name = "store_json_uploads",
    values = {"define": "SANTA_STORE_SYNC_JSON=1"},
)

objc_library(
    name = "SNTSyncLogging",
    srcs = ["SNTSyncLogging.mm"],
    hdrs = ["SNTSyncLogging.h"],
    deps = [
        ":broadcaster_lib",
        "//src/common:SNTLogging",
    ],
)

objc_library(
    name = "SNTSyncStage",
    srcs = ["SNTSyncStage.mm"],
    hdrs = ["SNTSyncStage.h"],
    defines = select({
        ":store_json_uploads": ["SANTA_STORE_SYNC_JSON"],
        "//conditions:default": [],
    }),
    deps = [
        ":SNTSyncLogging",
        ":SNTSyncState",
        "//src/common:MOLXPCConnection",
        "//src/common:NSData+Zlib",
        "//src/common:SNTCommonEnums",
        "//src/common:SNTConfigurator",
        "//src/common:SNTError",
        "//src/common:SNTLogging",
        "//src/common:SNTSyncConstants",
        "//src/common:SNTXPCControlInterface",
        "//src/common:String",
        "@protobuf//src/google/protobuf/json",
    ],
)

objc_library(
    name = "SNTPushNotificationsTracker",
    srcs = ["SNTPushNotificationsTracker.mm"],
    hdrs = ["SNTPushNotificationsTracker.h"],
    deps = [
        "//src/common:SNTLogging",
        "//src/common:SNTSyncConstants",
    ],
)

objc_library(
    name = "ProtoTraits",
    hdrs = ["ProtoTraits.h"],
    deps = [
        "@northpolesec_protos//sync:v1_cc_proto",
        "@northpolesec_protos//syncv2:v2_cc_proto",
    ],
)

objc_library(
    name = "SNTSyncRuleDownload",
    srcs = ["SNTSyncRuleDownload.mm"],
    hdrs = ["SNTSyncRuleDownload.h"],
    deps = [
        ":ProtoTraits",
        ":SNTPushNotificationsTracker",
        ":SNTSyncConfigBundle",
        ":SNTSyncLogging",
        ":SNTSyncStage",
        ":SNTSyncState",
        "//src/common:SNTCommonEnums",
        "//src/common:SNTFileAccessRule",
        "//src/common:SNTRule",
        "//src/common:SNTSyncConstants",
        "//src/common:SNTXPCControlInterface",
        "//src/common:String",
        "//src/common/faa:WatchItemPolicy",
        "//src/common/faa:WatchItems",
        "@northpolesec_protos//syncv2:v2_cc_proto",
    ],
)

santa_unit_test(
    name = "SNTSyncRuleDownloadTest",
    srcs = [
        "SNTSyncRuleDownloadTest.mm",
    ],
    deps = [
        ":SNTSyncRuleDownload",
        "//src/common:SNTFileAccessRule",
        "//src/common:TestUtils",
        "//src/common/faa:WatchItemPolicy",
        "//src/common/faa:WatchItems",
        "@northpolesec_protos//syncv2:v2_cc_proto",
    ],
)

objc_library(
    name = "sync_lib",
    srcs = [
        "SNTPushClientAPNS.h",
        "SNTPushClientAPNS.mm",
        "SNTPushClientFCM.h",
        "SNTPushClientFCM.mm",
        "SNTStreamingMultipartFormData.h",
        "SNTStreamingMultipartFormData.mm",
        "SNTSyncEventUpload.h",
        "SNTSyncEventUpload.mm",
        "SNTSyncManager.mm",
        "SNTSyncPostflight.h",
        "SNTSyncPostflight.mm",
        "SNTSyncPreflight.h",
        "SNTSyncPreflight.mm",
    ],
    hdrs = ["SNTSyncManager.h"],
    sdk_dylibs = ["libz"],
    sdk_frameworks = ["Network"],
    deps = [
        ":FCM_lib",
        ":NATS_lib",
        ":ProtoTraits",
        ":SNTPushNotificationsTracker",
        ":SNTSyncConfigBundle",
        ":SNTSyncLogging",
        ":SNTSyncRuleDownload",
        ":SNTSyncStage",
        ":SNTSyncState",
        ":broadcaster_lib",
        ":polaris_lib",
        "//src/common:EncodeEntitlements",
        "//src/common:MOLAuthenticatingURLSession",
        "//src/common:MOLCertificate",
        "//src/common:MOLXPCConnection",
        "//src/common:NSData+Zlib",
        "//src/common:Pinning",
        "//src/common:SNTCommonEnums",
        "//src/common:SNTConfigurator",
        "//src/common:SNTError",
        "//src/common:SNTFileInfo",
        "//src/common:SNTLogging",
        "//src/common:SNTModeTransition",
        "//src/common:SNTRule",
        "//src/common:SNTSIPStatus",
        "//src/common:SNTStoredEvent",
        "//src/common:SNTStoredExecutionEvent",
        "//src/common:SNTStoredFileAccessEvent",
        "//src/common:SNTStoredTemporaryMonitorModeAuditEvent",
        "//src/common:SNTStrengthify",
        "//src/common:SNTSyncConstants",
        "//src/common:SNTSystemInfo",
        "//src/common:SNTXPCControlInterface",
        "//src/common:SNTXPCSyncServiceInterface",
        "//src/common:String",
        "@northpolesec_protos//syncv2:v2_cc_proto",
        "@protobuf//src/google/protobuf/json",
    ],
)

# Using :sync_lib breaks the Zlib category hack used in the tests to
# disable compression, in turn failing the tests. Re-compile here to keep
# the "override" category behavior.
santa_unit_test(
    name = "SNTSyncTest",
    srcs = [
        "SNTPushClientAPNS.h",
        "SNTPushClientAPNS.mm",
        "SNTPushClientFCM.h",
        "SNTPushClientFCM.mm",
        "SNTPushNotifications.h",
        "SNTSyncEventUpload.h",
        "SNTSyncEventUpload.mm",
        "SNTSyncManager.h",
        "SNTSyncManager.mm",
        "SNTSyncPostflight.h",
        "SNTSyncPostflight.mm",
        "SNTSyncPreflight.h",
        "SNTSyncPreflight.mm",
        "SNTSyncTest.mm",
    ],
    resources = glob([
        "testdata/*.json",
        "testdata/*.plist",
    ]),
    sdk_dylibs = ["libz"],
    deps = [
        ":FCM_lib",
        ":NATS_lib",
        ":SNTPushNotificationsTracker",
        ":SNTSyncConfigBundle",
        ":SNTSyncLogging",
        ":SNTSyncRuleDownload",
        ":SNTSyncStage",
        ":SNTSyncState",
        ":broadcaster_lib",
        "//src/common:EncodeEntitlements",
        "//src/common:MOLAuthenticatingURLSession",
        "//src/common:MOLCertificate",
        "//src/common:MOLXPCConnection",
        "//src/common:NSData+Zlib",
        "//src/common:Pinning",
        "//src/common:SNTCommonEnums",
        "//src/common:SNTConfigurator",
        "//src/common:SNTDropRootPrivs",
        "//src/common:SNTFileInfo",
        "//src/common:SNTLogging",
        "//src/common:SNTModeTransition",
        "//src/common:SNTRule",
        "//src/common:SNTSIPStatus",
        "//src/common:SNTStoredEvent",
        "//src/common:SNTStoredExecutionEvent",
        "//src/common:SNTStoredFileAccessEvent",
        "//src/common:SNTStoredTemporaryMonitorModeAuditEvent",
        "//src/common:SNTStrengthify",
        "//src/common:SNTSyncConstants",
        "//src/common:SNTSystemInfo",
        "//src/common:SNTXPCControlInterface",
        "//src/common:String",
        "@OCMock",
        "@northpolesec_protos//sync:v1_cc_proto",
        "@northpolesec_protos//syncv2:v2_cc_proto",
        "@protobuf//src/google/protobuf/json",
    ],
)

santa_unit_test(
    name = "SNTStreamingMultipartFormDataTest",
    srcs = [
        "SNTStreamingMultipartFormDataTest.mm",
    ],
    deps = [
        ":sync_lib",
        "//src/common:SNTLogging",
        "//src/common:ScopedFile",
    ],
)

santa_unit_test(
    name = "SNTSyncManagerTest",
    srcs = [
        "ProtoTraits.h",
        "SNTPushClientAPNS.h",
        "SNTPushClientAPNS.mm",
        "SNTPushClientFCM.h",
        "SNTPushClientFCM.mm",
        "SNTPushNotifications.h",
        "SNTSyncEventUpload.h",
        "SNTSyncEventUpload.mm",
        "SNTSyncManager.h",
        "SNTSyncManager.mm",
        "SNTSyncManagerTest.mm",
        "SNTSyncPostflight.h",
        "SNTSyncPostflight.mm",
        "SNTSyncPreflight.h",
        "SNTSyncPreflight.mm",
        "SNTSyncRuleDownload.h",
        "SNTSyncRuleDownload.mm",
    ],
    sdk_dylibs = ["libz"],
    deps = [
        ":FCM_lib",
        ":NATS_lib",
        ":SNTPushNotificationsTracker",
        ":SNTSyncConfigBundle",
        ":SNTSyncLogging",
        ":SNTSyncStage",
        ":SNTSyncState",
        ":broadcaster_lib",
        "//src/common:EncodeEntitlements",
        "//src/common:MOLAuthenticatingURLSession",
        "//src/common:MOLCertificate",
        "//src/common:MOLXPCConnection",
        "//src/common:NSData+Zlib",
        "//src/common:Pinning",
        "//src/common:SNTCommonEnums",
        "//src/common:SNTConfigurator",
        "//src/common:SNTDropRootPrivs",
        "//src/common:SNTFileInfo",
        "//src/common:SNTLogging",
        "//src/common:SNTRule",
        "//src/common:SNTSIPStatus",
        "//src/common:SNTStoredEvent",
        "//src/common:SNTStoredExecutionEvent",
        "//src/common:SNTStoredFileAccessEvent",
        "//src/common:SNTStoredTemporaryMonitorModeAuditEvent",
        "//src/common:SNTStrengthify",
        "//src/common:SNTSyncConstants",
        "//src/common:SNTSystemInfo",
        "//src/common:SNTXPCControlInterface",
        "//src/common:String",
        "@OCMock",
        "@northpolesec_protos//sync:v1_cc_proto",
        "@northpolesec_protos//syncv2:v2_cc_proto",
        "@protobuf//src/google/protobuf/json",
    ],
)

objc_library(
    name = "broadcaster_lib",
    srcs = ["SNTSyncBroadcaster.mm"],
    hdrs = ["SNTSyncBroadcaster.h"],
    deps = [
        "//src/common:MOLXPCConnection",
        "//src/common:SNTXPCSyncServiceInterface",
    ],
)

objc_library(
    name = "santass_lib",
    srcs = [
        "SNTSyncService.h",
        "SNTSyncService.mm",
        "main.mm",
    ],
    deps = [
        ":broadcaster_lib",
        ":sync_lib",
        "//src/common:MOLCodesignChecker",
        "//src/common:MOLXPCConnection",
        "//src/common:SNTDropRootPrivs",
        "//src/common:SNTExportConfiguration",
        "//src/common:SNTKVOManager",
        "//src/common:SNTLogging",
        "//src/common:SNTStrengthify",
        "//src/common:SNTXPCControlInterface",
        "//src/common:SNTXPCSyncServiceInterface",
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
    minimum_os_version = SANTA_MINIMUM_OS_VERSION,
    provisioning_profile = select({
        "//:adhoc_build": None,
        "//conditions:default": "//profiles:santa_dev",
    }),
    version = "//:version",
    visibility = ["//:santa_package_group"],
    deps = [":santass_lib"],
)

santa_unit_test(
    name = "SNTPushClientNATSTest",
    srcs = ["SNTPushClientNATSTest.mm"],
    deps = [
        ":NATS_lib",
        ":SNTSyncState",
        "//src/common:SNTConfigurator",
        "//src/common:SNTSyncConstants",
        "//src/common:SNTSystemInfo",
        "@OCMock",
    ],
)

santa_unit_test(
    name = "SNTPushClientNATSCommandTest",
    srcs = ["SNTPushClientNATSCommandTest.mm"],
    deps = [
        ":NATS_lib",
        "//src/common:SNTConfigurator",
        "//src/common:SNTSyncConstants",
        "@OCMock",
        "@northpolesec_protos//commands:v1_cc_proto",
    ],
)

santa_unit_test(
    name = "SNTPushClientNATSIntegrationTest",
    srcs = ["SNTPushClientNATSIntegrationTest.mm"],
    env = {
        "NATS_INTEGRATION_TEST": "1",
        "SANTA_NATS_DISABLE_TLS": "1",
        "SANTA_NATS_DISABLE_DOMAIN_SUFFIX": "1",
    },
    tags = ["manual"],  # Only run when explicitly requested
    deps = [
        ":NATS_lib",
        ":SNTSyncState",
        "//src/common:SNTConfigurator",
        "//src/common:SNTSyncConstants",
        "@OCMock",
        "@nats_c//:nats",
    ],
)

santa_unit_test(
    name = "SNTPushClientNATSConnectionTest",
    srcs = ["SNTPushClientNATSConnectionTest.mm"],
    env = {
        "NATS_INTEGRATION_TEST": "1",
        "SANTA_NATS_DISABLE_TLS": "1",
        "SANTA_NATS_DISABLE_DOMAIN_SUFFIX": "1",
    },
    tags = ["manual"],  # Only run when explicitly requested
    deps = [
        ":NATS_lib",
        "//src/common:SNTConfigurator",
        "@OCMock",
        "@nats_c//:nats",
    ],
)

santa_unit_test(
    name = "SNTSyncManagerNATSTest",
    srcs = ["SNTSyncManagerNATSTest.mm"],
    deps = [
        ":sync_lib",
        "//src/common:MOLXPCConnection",
        "//src/common:SNTConfigurator",
        "@OCMock",
    ],
)

test_suite(
    name = "unit_tests",
    tests = [
        ":SNTPushClientNATSCommandTest",
        ":SNTPushClientNATSConnectionTest",
        ":SNTPushClientNATSTest",
        ":SNTStreamingMultipartFormDataTest",
        ":SNTSyncConfigBundleTest",
        ":SNTSyncManagerNATSTest",
        ":SNTSyncManagerTest",
        ":SNTSyncRuleDownloadTest",
        ":SNTSyncTest",
    ],
    visibility = ["//:santa_package_group"],
)
