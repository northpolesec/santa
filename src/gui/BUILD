load("@rules_apple//apple:macos.bzl", "macos_application")
load("@rules_cc//cc:defs.bzl", "objc_library")
load("@rules_swift//swift:swift.bzl", "swift_library")
load("//:helper.bzl", "SANTA_MINIMUM_OS_VERSION", "santa_unit_test")

licenses(["notice"])

swift_library(
    name = "SNTMessageView",
    srcs = ["SNTMessageView.swift"],
    generates_header = 1,
    module_name = "santa_gui_SNTMessageView",
    deps = ["//src/common:SNTConfigurator"],
)

swift_library(
    name = "SNTAboutWindowView",
    srcs = ["SNTAboutWindowView.swift"],
    generates_header = 1,
    deps = [
        ":SNTMessageView",
        "//src/common:MOLXPCConnection",
        "//src/common:SNTConfigurator",
        "//src/common:SNTXPCSyncServiceInterface",
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
        "//src/common:MOLCodesignChecker",
        "//src/common:SNTFileInfo",
        "//src/common:SigningIDHelpers",
    ],
)

swift_library(
    name = "SNTBinaryMessageWindowView",
    srcs = ["SNTBinaryMessageWindowView.swift"],
    generates_header = 1,
    deps = [
        ":SNTMessageView",
        "//src/common:CertificateHelpers",
        "//src/common:SNTBlockMessage_SantaGUI",
        "//src/common:SNTCommonEnums",
        "//src/common:SNTConfigState",
        "//src/common:SNTConfigurator",
        "//src/common:SNTStoredExecutionEvent",
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
        "//src/common:SNTBlockMessage_SantaGUI",
        "//src/common:SNTConfigurator",
        "//src/common:SNTDeviceEvent",
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
        "//src/common:SNTBlockMessage_SantaGUI",
        "//src/common:SNTConfigState",
        "//src/common:SNTStoredFileAccessEvent",
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
        "//src/common:SNTBlockMessage_SantaGUI",
        "//src/common:SNTConfigBundle",
        "//src/common:SNTStoredNetworkMountEvent",
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
        ":SNTNetworkMountMessageWindowView",
        "//src/common:CertificateHelpers",
        "//src/common:MOLCertificate",
        "//src/common:MOLCodesignChecker",
        "//src/common:MOLXPCConnection",
        "//src/common:SNTBlockMessage_SantaGUI",
        "//src/common:SNTConfigBundle",
        "//src/common:SNTConfigState",
        "//src/common:SNTConfigurator",
        "//src/common:SNTDeviceEvent",
        "//src/common:SNTFileInfo",
        "//src/common:SNTKVOManager",
        "//src/common:SNTLogging",
        "//src/common:SNTStoredExecutionEvent",
        "//src/common:SNTStoredFileAccessEvent",
        "//src/common:SNTStoredNetworkMountEvent",
        "//src/common:SNTStrengthify",
        "//src/common:SNTSyncConstants",
        "//src/common:SNTXPCControlInterface",
        "//src/common:SNTXPCNotifierInterface",
        "//src/common:SNTXPCSyncServiceInterface",
    ],
)

macos_application(
    name = "Santa",
    additional_contents = {
        "//src/santactl": "MacOS",
        "//src/santabundleservice": "MacOS",
        "//src/santametricservice": "MacOS",
        "//src/santasyncservice": "MacOS",
        "//src/santad:com.northpolesec.santa.daemon": "Library/SystemExtensions",
        "resources/Fonts/StarJedi.ttf": ".",
    },
    app_icons = glob(["resources/Images.xcassets/**"]),
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
        "//src/common:CommitHash",
    ],
    minimum_os_version = SANTA_MINIMUM_OS_VERSION,
    provisioning_profile = select({
        "//:adhoc_build": None,
        "//conditions:default": "//profiles:santa_dev",
    }),
    resources = [
        "resources/SantaLicense.txt",
        "resources/ThirdPartyLicenses.txt",
    ],
    strings = glob(["resources/**/*.strings"]),
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
        "//src/common:SNTDeviceEvent",
    ],
)

macos_application(
    name = "SNTTestGUI",
    additional_contents = {
        "resources/Fonts/StarJedi.ttf": ".",
    },
    app_icons = glob(["resources/Images.xcassets/**"]),
    bundle_id = "com.northpolesec.santatestgui",
    bundle_name = "SantaTestGUI",
    infoplists = ["Info.plist"],
    minimum_os_version = SANTA_MINIMUM_OS_VERSION,
    strings = glob(["resources/**/*.strings"]),
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
        "//src/common:SNTStoredExecutionEvent",
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
