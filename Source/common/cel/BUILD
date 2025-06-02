load("@protobuf//bazel:cc_proto_library.bzl", "cc_proto_library")
load("@protobuf//bazel:proto_library.bzl", "proto_library")
load("@rules_cc//cc:defs.bzl", "objc_library")
load("//:helper.bzl", "santa_unit_test")

package(
    default_visibility = ["//:santa_package_group"],
)

licenses(["notice"])

proto_library(
    name = "cel_proto",
    srcs = ["cel.proto"],
    deps = [
        "@protobuf//:timestamp_proto",
    ],
)

cc_proto_library(
    name = "cel_cc_proto",
    deps = [":cel_proto"],
)

objc_library(
    name = "CEL",
    srcs = [
        "context.h",
        "context.mm",
        "evaluator.mm",
        "memoizer.h",
    ],
    hdrs = ["evaluator.h"],
    deps = [
        ":cel_cc_proto",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@cel-cpp//checker:validation_result",
        "@cel-cpp//common:ast_proto",
        "@cel-cpp//common:function_descriptor",
        "@cel-cpp//compiler",
        "@cel-cpp//compiler:compiler_factory",
        "@cel-cpp//compiler:standard_library",
        "@cel-cpp//eval/public:activation",
        "@cel-cpp//eval/public:activation_bind_helper",
        "@cel-cpp//eval/public:builtin_func_registrar",
        "@cel-cpp//eval/public:cel_expr_builder_factory",
        "@cel-cpp//eval/public:cel_expression",
        "@cel-cpp//eval/public:cel_function",
        "@cel-cpp//eval/public:cel_function_adapter",
        "@cel-cpp//eval/public:cel_options",
        "@cel-cpp//eval/public:cel_value",
        "@cel-cpp//eval/public:transform_utility",
        "@cel-cpp//eval/public/containers:container_backed_list_impl",
        "@cel-cpp//eval/public/containers:container_backed_map_impl",
        "@cel-cpp//eval/public/containers:field_access",
        "@cel-cpp//eval/public/structs:cel_proto_wrapper",
        "@cel-cpp//internal:status_macros",
        "@cel-cpp//parser",
    ],
)

santa_unit_test(
    name = "CELTest",
    srcs = ["test.mm"],
    deps = [
        ":CEL",
        ":cel_cc_proto",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
    ],
)
