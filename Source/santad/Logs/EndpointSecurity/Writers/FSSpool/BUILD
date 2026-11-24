load("@rules_cc//cc:defs.bzl", "cc_library", "objc_library")
load("//:helper.bzl", "santa_unit_test")

package(
    default_visibility = ["//:santa_package_group"],
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

objc_library(
    name = "ZstdOutputStream",
    srcs = ["ZstdOutputStream.mm"],
    hdrs = ["ZstdOutputStream.h"],
    deps = [
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@protobuf//src/google/protobuf/io",
        "@zstd",
    ],
)

objc_library(
    name = "SpoolBatchers",
    srcs = ["AnyBatcher.mm"],
    hdrs = [
        "AnyBatcher.h",
        "StreamBatcher.h",
    ],
    deps = [
        ":ZstdOutputStream",
        ":fsspool_nowindows",
        "//Source/common:SNTXxhash",
        "//Source/common:Unit",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/synchronization",
        "@northpolesec_protos//telemetry:v1_cc_proto",
    ],
)

santa_unit_test(
    name = "StreamBatchersTest",
    srcs = ["StreamBatcherTest.mm"],
    deps = [
        ":SpoolBatchers",
        "//Source/common:NSData+Zlib",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
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
