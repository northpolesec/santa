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
    srcs = ["SNTMessageView.swift"],
    generates_header = 1,
    module_name = "santa_gui_SNTMessageView",
    deps = [
        ":SNTAuthorizationHelper",
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
    name = "SantaGUI_lib",
    srcs = [
        "SNTAboutWindowController.h",
        "SNTAboutWindowController.mm",
        "SNTAppDelegate.h",
        "SNTAppDelegate.mm",
        "SNTBinaryMessageWindowController.h",
        "SNTBinaryMessageWindowController.mm",
        "SNTDeviceMessageWindowController.h",
        "SNTDeviceMessageWindowController.mm",
        "SNTFileAccessMessageWindowController.h",
        "SNTFileAccessMessageWindowController.mm",
        "SNTMessageWindowController.h",
        "SNTMessageWindowController.mm",
        "SNTNetworkMountMessageWindowController.h",
        "SNTNetworkMountMessageWindowController.mm",
        "SNTNotificationManager.h",
        "SNTNotificationManager.mm",
        "SNTStatusItemManager.h",
        "SNTStatusItemManager.mm",
        "main.mm",
    ],
    sdk_frameworks = [
        "LocalAuthentication",
        "IOKit",
        "SecurityInterface",
        "SystemExtensions",
        "UserNotifications",
    ],
    deps = [
        ":SNTAboutWindowView",
        ":SNTAuthorizationHelper",
        ":SNTBinaryMessageWindowView",
        ":SNTDeviceMessageWindowView",
        ":SNTFileAccessMessageWindowView",
        ":SNTFileInfoView",
        ":SNTNetworkMountMessageWindowView",
        ":SNTSystemExtensionDelegate",
        "//Source/common:CertificateHelpers",
        "//Source/common:MOLCertificate",
        "//Source/common:MOLCodesignChecker",
        "//Source/common:MOLXPCConnection",
        "//Source/common:SNTBlockMessage_SantaGUI",
        "//Source/common:SNTConfigBundle",
        "//Source/common:SNTConfigState",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTDeviceEvent",
        "//Source/common:SNTFileInfo",
        "//Source/common:SNTKVOManager",
        "//Source/common:SNTLogging",
        "//Source/common:SNTStoredExecutionEvent",
        "//Source/common:SNTStoredFileAccessEvent",
        "//Source/common:SNTStoredNetworkMountEvent",
        "//Source/common:SNTStrengthify",
        "//Source/common:SNTSyncConstants",
        "//Source/common:SNTXPCControlInterface",
        "//Source/common:SNTXPCNotifierInterface",
        "//Source/common:SNTXPCSyncServiceInterface",
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
        ":SantaGUI_lib",
        "//Source/common:SNTStoredExecutionEvent",
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
