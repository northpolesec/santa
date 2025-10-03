load("@rules_cc//cc:defs.bzl", "objc_library")
load("//:helper.bzl", "santa_unit_test")

package(
    default_visibility = ["//:santa_package_group"],
)

licenses(["notice"])

objc_library(
    name = "WatchItemPolicy",
    hdrs = ["WatchItemPolicy.h"],
    deps = [
        "//Source/common:Glob",
        "//Source/common:PrefixTree",
        "//Source/common:SNTError",
        "//Source/common:String",
        "//Source/common:Unit",
        "@abseil-cpp//absl/container:flat_hash_set",
    ],
)

santa_unit_test(
    name = "WatchItemPolicyTest",
    srcs = ["WatchItemPolicyTest.mm"],
    deps = [
        ":WatchItemPolicy",
        "//Source/common:TestUtils",
        "@abseil-cpp//absl/container:flat_hash_set",
    ],
)

objc_library(
    name = "WatchItems",
    srcs = ["WatchItems.mm"],
    hdrs = ["WatchItems.h"],
    deps = [
        ":WatchItemPolicy",
        "//Source/common:Glob",
        "//Source/common:PrefixTree",
        "//Source/common:SNTError",
        "//Source/common:SNTLogging",
        "//Source/common:String",
        "//Source/common:Timer",
        "//Source/common:Unit",
        "@abseil-cpp//absl/container:flat_hash_set",
    ],
)

santa_unit_test(
    name = "WatchItemsTest",
    srcs = ["WatchItemsTest.mm"],
    deps = [
        # ":FAAPolicyProcessor",
        ":WatchItemPolicy",
        "//Source/common/faa:WatchItems",
        "//Source/common:PrefixTree",
        "//Source/common:TestUtils",
        "//Source/common:Unit",
        "@OCMock",
        "@abseil-cpp//absl/container:flat_hash_set",
    ],
)

test_suite(
    name = "unit_tests",
    tests = [
        ":WatchItemPolicyTest",
        ":WatchItemsTest",
    ],
    visibility = ["//:santa_package_group"],
)
