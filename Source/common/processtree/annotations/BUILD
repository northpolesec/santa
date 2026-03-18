load("@rules_cc//cc:defs.bzl", "cc_library")
load("//:helper.bzl", "santa_unit_test")

package(
    default_visibility = ["//visibility:public"],
)

cc_library(
    name = "annotator",
    hdrs = ["annotator.h"],
    deps = [
        "//Source/common/processtree:process_tree_cc_proto",
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
        "//Source/common/processtree:process_tree_cc_proto",
        "@abseil-cpp//absl/container:flat_hash_map",
    ],
)

santa_unit_test(
    name = "originator_test",
    srcs = ["originator_test.mm"],
    deps = [
        ":originator",
        "//Source/common/processtree:process",
        "//Source/common/processtree:process_tree_cc_proto",
        "//Source/common/processtree:process_tree_test_helpers",
    ],
)
