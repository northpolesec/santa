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
        "//src/common:CodeSigningIdentifierUtils",
        "//src/common:Glob",
        "//src/common:PrefixTree",
        "//src/common:SNTError",
        "//src/common:String",
        "//src/common:Unit",
        "@abseil-cpp//absl/container:flat_hash_set",
    ],
)

santa_unit_test(
    name = "WatchItemPolicyTest",
    srcs = ["WatchItemPolicyTest.mm"],
    deps = [
        ":WatchItemPolicy",
        "//src/common:TestUtils",
        "@abseil-cpp//absl/container:flat_hash_set",
    ],
)

objc_library(
    name = "WatchItems",
    srcs = ["WatchItems.mm"],
    hdrs = ["WatchItems.h"],
    deps = [
        ":WatchItemPolicy",
        "//src/common:Glob",
        "//src/common:PassKey",
        "//src/common:PrefixTree",
        "//src/common:SNTError",
        "//src/common:SNTLogging",
        "//src/common:String",
        "//src/common:Timer",
        "//src/common:Unit",
        "@abseil-cpp//absl/container:flat_hash_set",
    ],
)

santa_unit_test(
    name = "WatchItemsTest",
    srcs = ["WatchItemsTest.mm"],
    deps = [
        # ":FAAPolicyProcessor",
        ":WatchItemPolicy",
        "//src/common/faa:WatchItems",
        "//src/common:PrefixTree",
        "//src/common:TestUtils",
        "//src/common:Unit",
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
