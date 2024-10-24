load("@build_bazel_rules_apple//apple:macos.bzl", "macos_application")
load("@build_bazel_rules_swift//swift:swift.bzl", "swift_library")
load("//:helper.bzl", "santa_unit_test")

licenses(["notice"])

package(
    default_visibility = ["//:santa_package_group"],
)

exports_files([
    "Resources/Images.xcassets/AppIcon.appiconset/santa-hat-icon-256.png",
])

swift_library(
    name = "SNTMessageView",
    srcs = ["SNTMessageView.swift"],
    module_name = "santa_gui_SNTMessageView",
)

swift_library(
    name = "SNTAboutWindowView",
    srcs = ["SNTAboutWindowView.swift"],
    generates_header = 1,
    deps = ["//Source/common:SNTConfigurator"],
)

swift_library(
    name = "SNTBinaryMessageWindowView",
    srcs = ["SNTBinaryMessageWindowView.swift"],
    generates_header = 1,
    deps = [
        ":SNTMessageView",
        "//Source/common:SNTBlockMessage_SantaGUI",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTStoredEvent",
    ],
)

swift_library(
    name = "SNTDeviceMessageWindowView",
    srcs = [
        "SNTDeviceMessageWindowView.swift",
    ],
    generates_header = 1,
    deps = [
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
        "//Source/common:SNTFileAccessEvent",
    ],
)

objc_library(
    name = "SantaGUI_lib",
    srcs = [
        "SNTAboutWindowController.h",
        "SNTAboutWindowController.m",
        "SNTAppDelegate.h",
        "SNTAppDelegate.m",
        "SNTBinaryMessageWindowController.h",
        "SNTBinaryMessageWindowController.m",
        "SNTDeviceMessageWindowController.h",
        "SNTDeviceMessageWindowController.m",
        "SNTFileAccessMessageWindowController.h",
        "SNTFileAccessMessageWindowController.m",
        "SNTMessageWindowController.h",
        "SNTMessageWindowController.m",
        "SNTNotificationManager.h",
        "SNTNotificationManager.m",
        "main.m",
    ],
    hdrs = [
        "SNTNotificationManager.h",
    ],
    sdk_frameworks = [
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
        "//Source/common:CertificateHelpers",
        "//Source/common:SNTBlockMessage_SantaGUI",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTDeviceEvent",
        "//Source/common:SNTFileAccessEvent",
        "//Source/common:SNTLogging",
        "//Source/common:SNTStoredEvent",
        "//Source/common:SNTStrengthify",
        "//Source/common:SNTSyncConstants",
        "//Source/common:SNTXPCControlInterface",
        "//Source/common:SNTXPCNotifierInterface",
        "@MOLCertificate",
        "@MOLCodesignChecker",
        "@MOLXPCConnection",
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
    },
    app_icons = glob(["Resources/Images.xcassets/**"]),
    bundle_id = "com.northpolesec.santa",
    bundle_name = "Santa",
    codesignopts = [
        "--timestamp",
        "--force",
        "--options library,kill,runtime",
    ],
    entitlements = select({
        "//:adhoc_build": "Santa.app-adhoc.entitlements",
        # Non-adhoc builds get thier entitlements from the provisioning profile.
        "//conditions:default": None,
    }),
    infoplists = ["Info.plist"],
    minimum_os_version = "12.0",
    provisioning_profile = select({
        "//:adhoc_build": None,
        "//conditions:default": "//profiles:santa_dev",
    }),
    strings = glob(["Resources/**/*.strings"]),
    version = "//:version",
    visibility = ["//:santa_package_group"],
    deps = [":SantaGUI_lib"],
)

santa_unit_test(
    name = "SNTNotificationManagerTest",
    srcs = [
        "SNTNotificationManagerTest.m",
    ],
    sdk_frameworks = [
        "Cocoa",
    ],
    deps = [
        ":SantaGUI_lib",
        "//Source/common:SNTStoredEvent",
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
