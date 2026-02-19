load("@rules_cc//cc:defs.bzl", "objc_library")

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

objc_library(
    name = "SNDFilterConfigurationHelper",
    srcs = ["SNDFilterConfigurationHelper.mm"],
    hdrs = ["SNDFilterConfigurationHelper.h"],
)

objc_library(
    name = "SNDFlowInfo",
    srcs = ["SNDFlowInfo.mm"],
    hdrs = ["SNDFlowInfo.h"],
)

objc_library(
    name = "SNDProcessInfo",
    srcs = ["SNDProcessInfo.mm"],
    hdrs = ["SNDProcessInfo.h"],
)

objc_library(
    name = "SNDNetworkFlowsSerializer",
    srcs = ["SNDNetworkFlowsSerializer.mm"],
    hdrs = ["SNDNetworkFlowsSerializer.h"],
    deps = [
        "@protobuf",
    ],
)

objc_library(
    name = "SNDProcessFlows",
    srcs = ["SNDProcessFlows.mm"],
    hdrs = ["SNDProcessFlows.h"],
    deps = [
        ":SNDFlowInfo",
        ":SNDProcessInfo",
    ],
)
