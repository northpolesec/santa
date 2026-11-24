load("@rules_cc//cc:defs.bzl", "cc_library", "objc_library")
load("//:helper.bzl", "santa_unit_test")

package(
    default_visibility = ["//visibility:public"],
)

cc_library(
    name = "process",
    hdrs = ["process.h"],
    deps = [
        "//Source/common/processtree/annotations:annotator",
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
        "//Source/common:CSOpsHelper",
        "//Source/common:ScopedMachPort",
        "//Source/common:SystemResources",
        "//Source/common/processtree/annotations:annotator",
        "@abseil-cpp//absl/container:flat_hash_map",
        "@abseil-cpp//absl/container:flat_hash_set",
        "@abseil-cpp//absl/container:inlined_vector",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/synchronization",
        "@northpolesec_protos//telemetry:v1_cc_proto",
    ],
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
        "//Source/common/es:EndpointSecurityAPI",
        "//Source/common/es:EndpointSecurityMessage",
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
        "//Source/common/processtree/annotations:annotator",
        "//Source/common/processtree/annotations:cel",
        "//Source/common/processtree/annotations:originator",
        "@abseil-cpp//absl/synchronization",
        "@northpolesec_protos//telemetry:v1_cc_proto",
    ],
)
