load("@rules_apple//apple:macos.bzl", "macos_application")
load("@rules_cc//cc:defs.bzl", "objc_library")
load("@rules_swift//swift:swift.bzl", "swift_library")
load("//:helper.bzl", "SANTA_MINIMUM_OS_VERSION", "santa_unit_test")

licenses(["notice"])

# Hook for build-time injection of Santa's network capabilities from external repo.
label_flag(
    name = "network_extension_bundle",
    build_setting_default = ":no_network_extension",
)

# Empty filegroup used to keep Santa buildable without access to the external repo.
filegroup(
    name = "no_network_extension",
    srcs = [],
    visibility = ["//visibility:public"],
)

objc_library(
    name = "SNTAuthorizationHelper",
    srcs = ["SNTAuthorizationHelper.mm"],
    hdrs = ["SNTAuthorizationHelper.h"],
    module_name = "santa_gui_SNTAuthorizationHelper",
    sdk_frameworks = ["LocalAuthentication"],
    deps = [
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTStoredExecutionEvent",
    ],
)

swift_library(
    name = "SNTMessageView",
    srcs = [
        "MoonLandingIcon.swift",
        "SNTMessageView.swift",
    ],
    generates_header = 1,
    module_name = "santa_gui_SNTMessageView",
    deps = [
        ":SNTAuthorizationHelper",
        "//Source/common:SNTConfigBundle",
        "//Source/common:SNTConfigurator",
    ],
)

swift_library(
    name = "SNTAboutWindowView",
    srcs = ["SNTAboutWindowView.swift"],
    generates_header = 1,
    deps = [
        ":SNTMessageView",
        "//Source/common:MOLXPCConnection",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTLiteDetector",
        "//Source/common:SNTXPCSyncServiceInterface",
    ],
)

swift_library(
    name = "SNTFileInfoView",
    srcs = [
        "SNTFileInfoView.swift",
    ],
    generates_header = 1,
    module_name = "santa_gui_SNTFileInfoView",
    deps = [
        ":SNTMessageView",
        "//Source/common:MOLCodesignChecker",
        "//Source/common:SNTFileInfo",
        "//Source/common:SigningIDHelpers",
    ],
)

swift_library(
    name = "SNTBinaryMessageWindowView",
    srcs = ["SNTBinaryMessageWindowView.swift"],
    generates_header = 1,
    deps = [
        ":SNTAuthorizationHelper",
        ":SNTMessageView",
        "//Source/common:CertificateHelpers",
        "//Source/common:SNTBlockMessage_SantaGUI",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigState",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTStoredExecutionEvent",
    ],
)

swift_library(
    name = "SNTDeviceMessageWindowView",
    srcs = [
        "SNTDeviceMessageWindowView.swift",
    ],
    generates_header = 1,
    deps = [
        ":SNTMessageView",
        "//Source/common:SNTBlockMessage_SantaGUI",
        "//Source/common:SNTConfigBundle",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTDeviceEvent",
    ],
)

swift_library(
    name = "SNTFileAccessMessageWindowView",
    srcs = [
        "SNTFileAccessMessageWindowView.swift",
    ],
    generates_header = 1,
    deps = [
        ":SNTMessageView",
        "//Source/common:SNTBlockMessage_SantaGUI",
        "//Source/common:SNTConfigState",
        "//Source/common:SNTStoredFileAccessEvent",
    ],
)

swift_library(
    name = "SNTNetworkFlowMessageWindowView",
    srcs = [
        "SNTNetworkFlowMessageWindowView.swift",
    ],
    generates_header = 1,
    deps = [
        ":SNTMessageView",
        "//Source/common:SNTBlockMessage_SantaGUI",
        "//Source/common:SNTConfigBundle",
        "//Source/common:SNTStoredNetworkFlowEvent",
    ],
)

swift_library(
    name = "SNTNetworkMountMessageWindowView",
    srcs = [
        "SNTNetworkMountMessageWindowView.swift",
    ],
    generates_header = 1,
    deps = [
        ":SNTMessageView",
        "//Source/common:SNTBlockMessage_SantaGUI",
        "//Source/common:SNTConfigBundle",
        "//Source/common:SNTStoredNetworkMountEvent",
    ],
)

objc_library(
    name = "SNTSystemExtensionDelegate",
    srcs = ["SNTSystemExtensionDelegate.mm"],
    hdrs = ["SNTSystemExtensionDelegate.h"],
    sdk_frameworks = [
        "SystemExtensions",
    ],
    deps = [
        "//Source/common:MOLXPCConnection",
        "//Source/common:SNTLogging",
        "//Source/common:SNTXPCControlInterface",
        "//Source/common:SNTXPCUnprivilegedControlInterface",
        "@santanetd//src/santanetd:SNDFilterConfigurationHelper",
    ],
)

objc_library(
    name = "SNTAboutWindowController",
    srcs = ["SNTAboutWindowController.mm"],
    hdrs = ["SNTAboutWindowController.h"],
    deps = [
        ":SNTAboutWindowView",
        "//Source/common:SNTBlockMessage_SantaGUI",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTXPCControlInterface",
    ],
)

objc_library(
    name = "SNTAppDelegate",
    srcs = ["SNTAppDelegate.mm"],
    hdrs = ["SNTAppDelegate.h"],
    sdk_frameworks = [
        "UserNotifications",
    ],
    deps = [
        ":SNTAboutWindowController",
        ":SNTFileInfoView",
        ":SNTNotificationManager",
        ":SNTStatusItemManager",
        "//Source/common:MOLXPCConnection",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTFileInfo",
        "//Source/common:SNTKVOManager",
        "//Source/common:SNTLogging",
        "//Source/common:SNTStrengthify",
        "//Source/common:SNTXPCControlInterface",
        "//Source/common:SNTXPCSyncServiceInterface",
    ],
)

objc_library(
    name = "SNTBinaryMessageWindowController",
    srcs = ["SNTBinaryMessageWindowController.mm"],
    hdrs = ["SNTBinaryMessageWindowController.h"],
    sdk_frameworks = [
        "SecurityInterface",
    ],
    deps = [
        ":SNTAuthorizationHelper",
        ":SNTBinaryMessageWindowView",
        ":SNTMessageWindowController",
        "//Source/common:CertificateHelpers",
        "//Source/common:MOLCertificate",
        "//Source/common:SNTBlockMessage_SantaGUI",
        "//Source/common:SNTConfigState",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTStoredExecutionEvent",
        "//Source/common:SNTXPCControlInterface",
    ],
)

objc_library(
    name = "SNTDeviceMessageWindowController",
    srcs = ["SNTDeviceMessageWindowController.mm"],
    hdrs = ["SNTDeviceMessageWindowController.h"],
    deps = [
        ":SNTDeviceMessageWindowView",
        ":SNTMessageWindowController",
        "//Source/common:SNTBlockMessage_SantaGUI",
        "//Source/common:SNTConfigBundle",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTDeviceEvent",
        "//Source/common:SNTStrengthify",
        "//Source/common:SNTXPCControlInterface",
    ],
)

objc_library(
    name = "SNTFileAccessMessageWindowController",
    srcs = ["SNTFileAccessMessageWindowController.mm"],
    hdrs = ["SNTFileAccessMessageWindowController.h"],
    deps = [
        ":SNTFileAccessMessageWindowView",
        ":SNTMessageWindowController",
        "//Source/common:SNTBlockMessage_SantaGUI",
        "//Source/common:SNTConfigState",
        "//Source/common:SNTLogging",
        "//Source/common:SNTStoredFileAccessEvent",
        "//Source/common:SNTXPCControlInterface",
    ],
)

objc_library(
    name = "SNTMessageWindowController",
    srcs = ["SNTMessageWindowController.mm"],
    hdrs = ["SNTMessageWindowController.h"],
    deps = [
        "//Source/common:SNTBlockMessage_SantaGUI",
        "//Source/common:SNTXPCControlInterface",
    ],
)

objc_library(
    name = "SNTNetworkFlowMessageWindowController",
    srcs = ["SNTNetworkFlowMessageWindowController.mm"],
    hdrs = ["SNTNetworkFlowMessageWindowController.h"],
    deps = [
        ":SNTMessageWindowController",
        ":SNTNetworkFlowMessageWindowView",
        "//Source/common:SNTConfigBundle",
        "//Source/common:SNTStoredNetworkFlowEvent",
        "//Source/common:SNTStrengthify",
        "//Source/common:SNTXPCControlInterface",
        "//Source/common:SigningIDHelpers",
    ],
)

objc_library(
    name = "SNTNetworkMountMessageWindowController",
    srcs = ["SNTNetworkMountMessageWindowController.mm"],
    hdrs = ["SNTNetworkMountMessageWindowController.h"],
    deps = [
        ":SNTMessageWindowController",
        ":SNTNetworkMountMessageWindowView",
        "//Source/common:SNTConfigBundle",
        "//Source/common:SNTStoredNetworkMountEvent",
        "//Source/common:SNTStrengthify",
        "//Source/common:SNTXPCControlInterface",
    ],
)

# Header-only target for SNTNotificationManager.h, used to break the
# SNTNotificationManager <-> SNTStatusItemManager dependency cycle:
# SNTStatusItemManager.mm has an unused #import of SNTNotificationManager.h,
# while SNTNotificationManager.mm genuinely depends on SNTStatusItemManager.
objc_library(
    name = "SNTNotificationManager_hdr",
    hdrs = ["SNTNotificationManager.h"],
    deps = [
        ":SNTMessageWindowController",
        "//Source/common:SNTXPCBundleServiceInterface",
        "//Source/common:SNTXPCNotifierInterface",
    ],
)

objc_library(
    name = "SNTNotificationManager",
    srcs = ["SNTNotificationManager.mm"],
    hdrs = ["SNTNotificationManager.h"],
    sdk_frameworks = [
        "UserNotifications",
    ],
    deps = [
        ":SNTAuthorizationHelper",
        ":SNTBinaryMessageWindowController",
        ":SNTBinaryMessageWindowView",
        ":SNTDeviceMessageWindowController",
        ":SNTFileAccessMessageWindowController",
        ":SNTMessageWindowController",
        ":SNTNetworkFlowMessageWindowController",
        ":SNTNetworkMountMessageWindowController",
        ":SNTStatusItemManager",
        "//Source/common:MOLCertificate",
        "//Source/common:MOLXPCConnection",
        "//Source/common:SNTBlockMessage_SantaGUI",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigState",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTDeviceEvent",
        "//Source/common:SNTLogging",
        "//Source/common:SNTStoredExecutionEvent",
        "//Source/common:SNTStoredFileAccessEvent",
        "//Source/common:SNTStoredNetworkFlowEvent",
        "//Source/common:SNTStoredNetworkMountEvent",
        "//Source/common:SNTStrengthify",
        "//Source/common:SNTSyncConstants",
        "//Source/common:SNTXPCBundleServiceInterface",
        "//Source/common:SNTXPCControlInterface",
        "//Source/common:SNTXPCNotifierInterface",
        "//Source/common:SNTXPCSyncServiceInterface",
        "@santanetd//src/santanetd:SNDFilterConfigurationHelper",
    ],
)

objc_library(
    name = "SNTStatusItemManager",
    srcs = ["SNTStatusItemManager.mm"],
    hdrs = ["SNTStatusItemManager.h"],
    sdk_frameworks = [
        "UserNotifications",
    ],
    deps = [
        ":SNTAboutWindowController",
        ":SNTNotificationManager_hdr",
        "//Source/common:MOLXPCConnection",
        "//Source/common:SNTBlockMessage_SantaGUI",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTError",
        "//Source/common:SNTKVOManager",
        "//Source/common:SNTLiteDetector",
        "//Source/common:SNTStrengthify",
        "//Source/common:SNTXPCControlInterface",
        "//Source/common:SNTXPCSyncServiceInterface",
    ],
)

objc_library(
    name = "SantaGUI_lib",
    srcs = ["main.mm"],
    sdk_frameworks = [
        "LocalAuthentication",
        "IOKit",
        "SecurityInterface",
        "SystemExtensions",
        "UserNotifications",
    ],
    deps = [
        ":SNTAboutWindowController",
        ":SNTAppDelegate",
        ":SNTAuthorizationHelper",
        ":SNTBinaryMessageWindowController",
        ":SNTDeviceMessageWindowController",
        ":SNTFileAccessMessageWindowController",
        ":SNTMessageWindowController",
        ":SNTNetworkFlowMessageWindowController",
        ":SNTNetworkMountMessageWindowController",
        ":SNTNotificationManager",
        ":SNTStatusItemManager",
        ":SNTSystemExtensionDelegate",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTLogging",
    ],
)

macos_application(
    name = "Santa",
    additional_contents = {
        "//Source/santactl": "MacOS",
        "//Source/santabundleservice": "MacOS",
        "//Source/santametricservice": "MacOS",
        "//Source/santasyncservice": "MacOS",
        "@sleigh//:sleigh": "MacOS",
        "//Source/santad:com.northpolesec.santa.daemon": "Library/SystemExtensions",
        ":network_extension_bundle": "Library/SystemExtensions",
        "Resources/Fonts/StarJedi.ttf": ".",
    },
    app_icons = glob(["Resources/Assets.xcassets/**"]),
    bundle_id = "com.northpolesec.santa",
    bundle_name = "Santa",
    codesignopts = [
        "--timestamp=none",
        "--force",
        "--options library,kill,runtime",
    ],
    entitlements = select({
        "//:adhoc_build": "Santa.app-adhoc.entitlements",
        # Non-adhoc builds get thier entitlements from the provisioning profile.
        "//conditions:default": None,
    }),
    infoplists = [
        "Info.plist",
        "//Source/common:CommitHash",
    ],
    minimum_os_version = SANTA_MINIMUM_OS_VERSION,
    provisioning_profile = select({
        "//:adhoc_build": None,
        "//conditions:default": "@profiles//:santa_dev",
    }),
    resources = [
        "Resources/SantaLicense.txt",
        "Resources/ThirdPartyLicenses.txt",
    ],
    strings = glob(["Resources/**/*.strings"]),
    version = "//:version",
    visibility = ["//:santa_package_group"],
    deps = [":SantaGUI_lib"],
)

swift_library(
    name = "SNTTestGUI_lib",
    srcs = ["SNTTestGUI.swift"],
    deps = [
        ":SNTAboutWindowView",
        ":SNTBinaryMessageWindowView",
        ":SNTDeviceMessageWindowView",
        ":SNTFileAccessMessageWindowView",
        ":SNTMessageView",
        ":SNTNetworkFlowMessageWindowView",
        "//Source/common:SNTConfigBundle",
        "//Source/common:SNTDeviceEvent",
    ],
)

macos_application(
    name = "SNTTestGUI",
    additional_contents = {
        "Resources/Fonts/StarJedi.ttf": ".",
    },
    app_icons = glob(["Resources/Assets.xcassets/**"]),
    bundle_id = "com.northpolesec.santatestgui",
    bundle_name = "SantaTestGUI",
    infoplists = ["Info.plist"],
    minimum_os_version = SANTA_MINIMUM_OS_VERSION,
    strings = glob(["Resources/**/*.strings"]),
    version = "//:version",
    deps = [":SNTTestGUI_lib"],
)

santa_unit_test(
    name = "SNTNotificationManagerTest",
    srcs = [
        "SNTNotificationManagerTest.mm",
    ],
    sdk_frameworks = [
        "Cocoa",
    ],
    deps = [
        ":SNTNotificationManager",
        "//Source/common:SNTConfigBundle",
        "//Source/common:SNTStoredExecutionEvent",
        "//Source/common:SNTStoredNetworkFlowEvent",
        "@OCMock",
    ],
)

santa_unit_test(
    name = "SNTSystemExtensionDelegateTest",
    srcs = [
        "SNTSystemExtensionDelegateTest.mm",
    ],
    sdk_frameworks = [
        "SystemExtensions",
    ],
    deps = [
        ":SNTSystemExtensionDelegate",
        "//Source/common:SNTXPCControlInterface",
        "//Source/common:TestUtils",
        "@OCMock",
    ],
)

test_suite(
    name = "unit_tests",
    tests = [
        ":SNTNotificationManagerTest",
        ":SNTSystemExtensionDelegateTest",
    ],
    visibility = ["//:santa_package_group"],
)
