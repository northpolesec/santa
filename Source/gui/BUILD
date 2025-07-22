load("@rules_apple//apple:macos.bzl", "macos_application")
load("@rules_cc//cc:defs.bzl", "objc_library")
load("@rules_swift//swift:swift.bzl", "swift_library")
load("//:helper.bzl", "santa_unit_test")

licenses(["notice"])

swift_library(
    name = "SNTMessageView",
    srcs = ["SNTMessageView.swift"],
    module_name = "santa_gui_SNTMessageView",
    deps = ["//Source/common:SNTConfigurator"],
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
        "SNTNotificationManager.h",
        "SNTNotificationManager.mm",
        "main.mm",
    ],
    hdrs = [
        "SNTNotificationManager.h",
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
        ":SNTBinaryMessageWindowView",
        ":SNTDeviceMessageWindowView",
        ":SNTFileAccessMessageWindowView",
        ":SNTFileInfoView",
        "//Source/common:CertificateHelpers",
        "//Source/common:MOLCertificate",
        "//Source/common:MOLCodesignChecker",
        "//Source/common:MOLXPCConnection",
        "//Source/common:SNTBlockMessage_SantaGUI",
        "//Source/common:SNTConfigState",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTDeviceEvent",
        "//Source/common:SNTFileInfo",
        "//Source/common:SNTKVOManager",
        "//Source/common:SNTLogging",
        "//Source/common:SNTStoredExecutionEvent",
        "//Source/common:SNTStoredFileAccessEvent",
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
        "//Source/santad:com.northpolesec.santa.daemon": "Library/SystemExtensions",
        "Resources/Fonts/StarJedi.ttf": ".",
    },
    app_icons = glob(["Resources/Images.xcassets/**"]),
    bundle_id = "com.northpolesec.santa",
    bundle_name = "Santa",
    codesignopts = [
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
    minimum_os_version = "13.0",
    provisioning_profile = select({
        "//:adhoc_build": None,
        "//conditions:default": "//profiles:santa_dev",
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
    app_icons = glob(["Resources/Images.xcassets/**"]),
    bundle_id = "com.northpolesec.santatestgui",
    bundle_name = "SantaTestGUI",
    infoplists = ["Info.plist"],
    minimum_os_version = "14.0",
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

test_suite(
    name = "unit_tests",
    tests = [
        ":SNTNotificationManagerTest",
    ],
    visibility = ["//:santa_package_group"],
)
