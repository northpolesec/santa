load("@rules_apple//apple:macos.bzl", "macos_command_line_application")
load("@rules_cc//cc:cc_library.bzl", "cc_library")

licenses(["notice"])

config_setting(
    name = "adhoc_build",
    values = {"define": "SANTA_BUILD_TYPE=adhoc"},
)

cc_library(
    name = "sleigh_lib",
    srcs = ["main.cc"],
)

macos_command_line_application(
    name = "sleigh",
    bundle_id = "com.northpolesec.santa.sleigh",
    codesignopts = [
        "--timestamp=none",
        "--force",
        "--options library,kill,runtime",
    ],
    minimum_os_version = "14.0",
    provisioning_profile = select({
        ":adhoc_build": None,
        "//conditions:default": "@profiles//:santa_dev",
    }),
    visibility = ["//visibility:public"],
    deps = [":sleigh_lib"],
)
