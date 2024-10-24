load("//:helper.bzl", "santa_unit_test")

package(
    default_visibility = ["//:santa_package_group"],
)

cc_library(
    name = "annotator",
    hdrs = ["annotator.h"],
    deps = [
        "@northpole_protos//telemetry:cc_proto_library_wrapper",
    ],
)

cc_library(
    name = "originator",
    srcs = ["originator.cc"],
    hdrs = ["originator.h"],
    deps = [
        ":annotator",
        "//Source/santad/ProcessTree:process",
        "//Source/santad/ProcessTree:process_tree",
        "@com_google_absl//absl/container:flat_hash_map",
        "@northpole_protos//telemetry:cc_proto_library_wrapper",
    ],
)

santa_unit_test(
    name = "originator_test",
    srcs = ["originator_test.mm"],
    deps = [
        ":originator",
        "//Source/santad/ProcessTree:process",
        "//Source/santad/ProcessTree:process_tree_test_helpers",
        "@northpole_protos//telemetry:cc_proto_library_wrapper",
    ],
)
