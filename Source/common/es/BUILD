load("@rules_cc//cc:defs.bzl", "objc_library")

package(
    default_visibility = ["//:santa_package_group"],
)

licenses(["notice"])

objc_library(
    name = "ESMetricsObserver",
    hdrs = ["ESMetricsObserver.h"],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
)
