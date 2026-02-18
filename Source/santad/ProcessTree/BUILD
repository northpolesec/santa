load("@protobuf//bazel:cc_proto_library.bzl", "cc_proto_library")
load("@protobuf//bazel:proto_library.bzl", "proto_library")
load("@rules_cc//cc:defs.bzl", "cc_library", "objc_library")
load("//:helper.bzl", "santa_unit_test")

package(
    default_visibility = ["//:santa_package_group"],
)

cc_library(
    name = "process",
    hdrs = ["process.h"],
    deps = [
        "//Source/santad/ProcessTree/annotations:annotator",
        "@abseil-cpp//absl/container:flat_hash_map",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/synchronization",
    ],
)

objc_library(
    name = "process_tree",
    srcs = [
        "process_tree.cc",
        "process_tree_macos.mm",
    ],
    hdrs = [
        "process_tree.h",
        "process_tree_macos.h",
    ],
    sdk_dylibs = [
        "bsm",
    ],
    deps = [
        ":process",
        "//Source/common:SystemResources",
        "//Source/santad:CSOpsHelper",
        "//Source/santad/ProcessTree:process_tree_cc_proto",
        "//Source/santad/ProcessTree/annotations:annotator",
        "@abseil-cpp//absl/container:flat_hash_map",
        "@abseil-cpp//absl/container:flat_hash_set",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/synchronization",
    ],
)

proto_library(
    name = "process_tree_proto",
    srcs = ["process_tree.proto"],
)

cc_proto_library(
    name = "process_tree_cc_proto",
    deps = [":process_tree_proto"],
)

objc_library(
    name = "SNTEndpointSecurityAdapter",
    srcs = ["SNTEndpointSecurityAdapter.mm"],
    hdrs = ["SNTEndpointSecurityAdapter.h"],
    sdk_dylibs = [
        "bsm",
    ],
    deps = [
        ":process_tree",
        "//Source/common:String",
        "//Source/santad:EndpointSecurityAPI",
        "//Source/santad:EndpointSecurityMessage",
        "@abseil-cpp//absl/status:statusor",
    ],
)

objc_library(
    name = "process_tree_test_helpers",
    srcs = ["process_tree_test_helpers.mm"],
    hdrs = ["process_tree_test_helpers.h"],
    deps = [
        ":process",
        ":process_tree",
        "@abseil-cpp//absl/synchronization",
    ],
)

santa_unit_test(
    name = "process_tree_test",
    srcs = ["process_tree_test.mm"],
    deps = [
        ":process",
        ":process_tree_test_helpers",
        "//Source/santad/ProcessTree/annotations:annotator",
        "@abseil-cpp//absl/synchronization",
    ],
)
