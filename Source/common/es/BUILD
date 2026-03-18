load("@rules_cc//cc:defs.bzl", "objc_library")

package(
    default_visibility = ["//visibility:public"],
)

licenses(["notice"])

objc_library(
    name = "ESMetricsObserver",
    hdrs = ["ESMetricsObserver.h"],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
)
