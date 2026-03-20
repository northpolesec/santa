load("@rules_cc//cc:defs.bzl", "objc_library")
load("//:helper.bzl", "santa_unit_test")

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

objc_library(
    name = "EndpointSecurityClient",
    hdrs = ["Client.h"],
)

objc_library(
    name = "EndpointSecurityMessage",
    srcs = [
        "EndpointSecurityAPI.h",
        "Message.mm",
    ],
    hdrs = ["Message.h"],
    deps = [
        ":EndpointSecurityClient",
        "//Source/common:String",
        "//Source/common/faa:WatchItemPolicy",
        "//Source/common/processtree:process_tree",
    ],
)

objc_library(
    name = "EndpointSecurityAPI",
    srcs = ["EndpointSecurityAPI.mm"],
    hdrs = ["EndpointSecurityAPI.h"],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
    deps = [
        ":EndpointSecurityClient",
        ":EndpointSecurityMessage",
        "//Source/common:Platform",
        "//Source/common/faa:WatchItemPolicy",
    ],
)

objc_library(
    name = "EndpointSecurityEnrichedTypes",
    hdrs = ["EnrichedTypes.h"],
    deps = [
        ":EndpointSecurityMessage",
        "//Source/common:Platform",
        "//Source/common:TelemetryEventMap",
        "//Source/common/processtree:process_tree_cc_proto",
    ],
)

objc_library(
    name = "EndpointSecurityEnricher",
    srcs = ["Enricher.mm"],
    hdrs = ["Enricher.h"],
    deps = [
        ":EndpointSecurityEnrichedTypes",
        "//Source/common:Platform",
        "//Source/common:SNTLogging",
        "//Source/common:SantaCache",
        "//Source/common:String",
        "//Source/common/processtree:SNTEndpointSecurityAdapter",
        "//Source/common/processtree:process_tree",
    ],
)

objc_library(
    name = "MockEndpointSecurityAPI",
    testonly = 1,
    hdrs = ["MockEndpointSecurityAPI.h"],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
    deps = [
        ":EndpointSecurityAPI",
        ":EndpointSecurityClient",
        ":EndpointSecurityMessage",
        "//Source/common/faa:WatchItemPolicy",
        "@googletest//:gtest",
    ],
)

objc_library(
    name = "MockEnricher",
    testonly = 1,
    hdrs = ["MockEnricher.h"],
    deps = [
        ":EndpointSecurityEnrichedTypes",
        ":EndpointSecurityEnricher",
        "@googletest//:gtest",
    ],
)

santa_unit_test(
    name = "EndpointSecurityClientTest",
    srcs = ["ClientTest.mm"],
    deps = [
        ":EndpointSecurityClient",
        "@OCMock",
    ],
)

santa_unit_test(
    name = "EndpointSecurityEnricherTest",
    srcs = ["EnricherTest.mm"],
    sdk_dylibs = [
        "bsm",
    ],
    deps = [
        ":EndpointSecurityEnricher",
        "//Source/common:TestUtils",
        "@OCMock",
    ],
)

santa_unit_test(
    name = "EndpointSecurityMessageTest",
    srcs = ["MessageTest.mm"],
    sdk_dylibs = [
        "bsm",
        "EndpointSecurity",
    ],
    deps = [
        ":EndpointSecurityMessage",
        ":MockEndpointSecurityAPI",
        "//Source/common:AuditUtilities",
        "//Source/common:TestUtils",
        "@OCMock",
        "@googletest//:gtest",
    ],
)

objc_library(
    name = "SNTEndpointSecurityEventHandler",
    hdrs = ["SNTEndpointSecurityEventHandler.h"],
    deps = [
        ":ESMetricsObserver",
        ":EndpointSecurityMessage",
        "//Source/common:SNTStoredFileAccessEvent",
        "//Source/common/faa:WatchItemPolicy",
    ],
)

objc_library(
    name = "SNTEndpointSecurityClientBase",
    hdrs = ["SNTEndpointSecurityClientBase.h"],
    deps = [
        ":ESMetricsObserver",
        ":EndpointSecurityAPI",
        ":EndpointSecurityClient",
        ":EndpointSecurityEnrichedTypes",
        ":EndpointSecurityMessage",
        "//Source/common/faa:WatchItemPolicy",
    ],
)

objc_library(
    name = "SNTEndpointSecurityClient",
    srcs = ["SNTEndpointSecurityClient.mm"],
    hdrs = ["SNTEndpointSecurityClient.h"],
    deps = [
        ":ESMetricsObserver",
        ":EndpointSecurityAPI",
        ":EndpointSecurityClient",
        ":EndpointSecurityEnrichedTypes",
        ":EndpointSecurityMessage",
        ":SNTEndpointSecurityClientBase",
        "//Source/common:AuditUtilities",
        "//Source/common:BranchPrediction",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTLogging",
        "//Source/common:SystemResources",
        "//Source/common/faa:WatchItemPolicy",
    ],
)

santa_unit_test(
    name = "SNTEndpointSecurityClientTest",
    srcs = ["SNTEndpointSecurityClientTest.mm"],
    sdk_dylibs = [
        "bsm",
        "EndpointSecurity",
    ],
    deps = [
        ":EndpointSecurityClient",
        ":EndpointSecurityEnrichedTypes",
        ":EndpointSecurityMessage",
        ":MockEndpointSecurityAPI",
        ":SNTEndpointSecurityClient",
        "//Source/common:AuditUtilities",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SystemResources",
        "//Source/common:TestUtils",
        "//Source/common/faa:WatchItemPolicy",
        "@OCMock",
        "@googletest//:gtest",
    ],
)
