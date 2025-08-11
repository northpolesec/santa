load("@protobuf//bazel:cc_proto_library.bzl", "cc_proto_library")
load("@protobuf//bazel:proto_library.bzl", "proto_library")
load("@rules_cc//cc:defs.bzl", "cc_library")
load("//:helper.bzl", "santa_unit_test")

package(
    default_visibility = ["//:santa_package_group"],
)

proto_library(
    name = "binaryproto_proto",
    srcs = ["binaryproto.proto"],
    deps = [
        "@protobuf//:any_proto",
        "@protobuf//:timestamp_proto",
    ],
)

cc_proto_library(
    name = "binaryproto_cc_proto",
    deps = [
        ":binaryproto_proto",
    ],
)

cc_library(
    name = "binaryproto_cc_proto_library_wrapper",
    hdrs = ["binaryproto_proto_include_wrapper.h"],
    deps = [
        ":binaryproto_cc_proto",
    ],
)

cc_library(
    name = "fsspool_nowindows",
    srcs = ["fsspool_nowindows.cc"],
    hdrs = ["fsspool_platform_specific.h"],
    deps = [
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
    ],
)

cc_library(
    name = "fsspool",
    hdrs = [
        "fsspool.h",
    ],
    deps = [
        ":SpoolBatchers",
        ":fsspool_nowindows",
        "@abseil-cpp//absl/cleanup",
        "@abseil-cpp//absl/container:flat_hash_set",
        "@abseil-cpp//absl/random",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/strings:str_format",
        "@abseil-cpp//absl/time",
    ],
)

cc_library(
    name = "SpoolBatchers",
    srcs = [
        "AnyBatcher.cc",
        "StreamBatcher.cc",
    ],
    hdrs = [
        "AnyBatcher.h",
        "StreamBatcher.h",
    ],
    deps = [
        ":binaryproto_cc_proto",
        ":fsspool_nowindows",
        "//Source/common:santa_cc_proto_library_wrapper",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/synchronization",
    ],
)

santa_unit_test(
    name = "fsspool_test",
    srcs = ["fsspool_test.mm"],
    deps = [
        ":SpoolBatchers",
        ":fsspool",
        "//Source/common:TestUtils",
        "@OCMock",
    ],
)
