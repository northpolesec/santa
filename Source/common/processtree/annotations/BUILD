load("@rules_cc//cc:defs.bzl", "cc_library")
load("//:helper.bzl", "santa_unit_test")

package(
    default_visibility = ["//visibility:public"],
)

cc_library(
    name = "annotator",
    hdrs = ["annotator.h"],
    deps = [
        "@northpolesec_protos//telemetry:v1_cc_proto",
    ],
)

cc_library(
    name = "originator",
    srcs = ["originator.cc"],
    hdrs = ["originator.h"],
    deps = [
        ":annotator",
        "//Source/common/processtree:process",
        "//Source/common/processtree:process_tree",
        "@abseil-cpp//absl/container:flat_hash_map",
        "@northpolesec_protos//telemetry:v1_cc_proto",
    ],
)

cc_library(
    name = "cel",
    srcs = ["cel.cc"],
    hdrs = ["cel.h"],
    deps = [
        ":annotator",
        "//Source/common/processtree:process",
        "//Source/common/processtree:process_tree",
        "@abseil-cpp//absl/container:flat_hash_map",
        "@cel-cpp//internal:utf8",
        "@northpolesec_protos//telemetry:v1_cc_proto",
    ],
)

santa_unit_test(
    name = "cel_test",
    srcs = ["cel_test.mm"],
    deps = [
        ":cel",
        "//Source/common/processtree:process",
        "//Source/common/processtree:process_tree_test_helpers",
        "@northpolesec_protos//telemetry:v1_cc_proto",
    ],
)

santa_unit_test(
    name = "originator_test",
    srcs = ["originator_test.mm"],
    deps = [
        ":originator",
        "//Source/common/processtree:process",
        "//Source/common/processtree:process_tree_test_helpers",
        "@northpolesec_protos//telemetry:v1_cc_proto",
    ],
)
