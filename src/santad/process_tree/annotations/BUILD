load("@rules_cc//cc:defs.bzl", "cc_library")
load("//:helper.bzl", "santa_unit_test")

package(
    default_visibility = ["//:santa_package_group"],
)

cc_library(
    name = "annotator",
    hdrs = ["annotator.h"],
    deps = [
        "//src/santad/process_tree:process_tree_cc_proto",
    ],
)

cc_library(
    name = "originator",
    srcs = ["originator.cc"],
    hdrs = ["originator.h"],
    deps = [
        ":annotator",
        "//src/santad/process_tree:process",
        "//src/santad/process_tree:process_tree",
        "//src/santad/process_tree:process_tree_cc_proto",
        "@abseil-cpp//absl/container:flat_hash_map",
    ],
)

santa_unit_test(
    name = "originator_test",
    srcs = ["originator_test.mm"],
    deps = [
        ":originator",
        "//src/santad/process_tree:process",
        "//src/santad/process_tree:process_tree_cc_proto",
        "//src/santad/process_tree:process_tree_test_helpers",
    ],
)
