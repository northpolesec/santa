load("@com_google_protobuf//bazel:proto_library.bzl", "proto_library")
load("@rules_cc//cc:defs.bzl", "cc_library", "cc_proto_library", "objc_library")
load("//:helper.bzl", "santa_unit_test")

package(
    default_visibility = ["//:santa_package_group"],
)

licenses(["notice"])

proto_library(
    name = "santa_proto",
    srcs = ["santa.proto"],
    deps = [
        "//Source/santad/ProcessTree:process_tree_proto",
        "@com_google_protobuf//:any_proto",
        "@com_google_protobuf//:timestamp_proto",
    ],
)

cc_proto_library(
    name = "santa_cc_proto",
    deps = [":santa_proto"],
)

# Note: Simple wrapper for a `cc_proto_library` target which cannot be directly
# depended upon by an `objc_library` target.
cc_library(
    name = "santa_cc_proto_library_wrapper",
    hdrs = ["santa_proto_include_wrapper.h"],
    deps = [
        ":santa_cc_proto",
    ],
)

objc_library(
    name = "SystemResources",
    srcs = ["SystemResources.mm"],
    hdrs = ["SystemResources.h"],
    deps = [
        ":SNTLogging",
    ],
)

objc_library(
    name = "SNTDeepCopy",
    srcs = ["SNTDeepCopy.m"],
    hdrs = ["SNTDeepCopy.h"],
)

cc_library(
    name = "SantaCache",
    hdrs = ["SantaCache.h"],
    deps = [
        ":BranchPrediction",
        "@com_google_absl//absl/hash",
    ],
)

cc_library(
    name = "SantaSetCache",
    hdrs = ["SantaSetCache.h"],
    deps = [
        ":SantaCache",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/hash",
        "@com_google_absl//absl/synchronization",
    ],
)

cc_library(
    name = "AuditUtilities",
    hdrs = ["AuditUtilities.h"],
)

santa_unit_test(
    name = "SantaCacheTest",
    srcs = ["SantaCacheTest.mm"],
    deps = [
        ":SantaCache",
    ],
)

santa_unit_test(
    name = "SantaSetCacheTest",
    srcs = ["SantaSetCacheTest.mm"],
    deps = [
        ":SantaSetCache",
    ],
)

# This target shouldn't be used directly.
# Use a more specific scoped type instead.
objc_library(
    name = "ScopedTypeRef",
    hdrs = ["ScopedTypeRef.h"],
    visibility = ["//Source/common:__pkg__"],
)

objc_library(
    name = "ScopedCFTypeRef",
    hdrs = ["ScopedCFTypeRef.h"],
    deps = [
        ":ScopedTypeRef",
    ],
)

santa_unit_test(
    name = "ScopedCFTypeRefTest",
    srcs = ["ScopedCFTypeRefTest.mm"],
    sdk_frameworks = [
        "Security",
    ],
    deps = [
        ":ScopedCFTypeRef",
    ],
)

objc_library(
    name = "ScopedIOObjectRef",
    hdrs = ["ScopedIOObjectRef.h"],
    sdk_frameworks = [
        "IOKit",
    ],
    deps = [
        ":ScopedTypeRef",
    ],
)

santa_unit_test(
    name = "ScopedIOObjectRefTest",
    srcs = ["ScopedIOObjectRefTest.mm"],
    sdk_frameworks = [
        "IOKit",
    ],
    deps = [
        ":ScopedIOObjectRef",
        "//Source/santad:EndpointSecuritySerializerUtilities",
    ],
)

objc_library(
    name = "BranchPrediction",
    hdrs = ["BranchPrediction.h"],
)

objc_library(
    name = "SantaVnode",
    hdrs = ["SantaVnode.h"],
    deps = [
        "@com_google_absl//absl/hash",
    ],
)

objc_library(
    name = "Platform",
    hdrs = ["Platform.h"],
)

objc_library(
    name = "String",
    hdrs = ["String.h"],
)

objc_library(
    name = "CertificateHelpers",
    srcs = ["CertificateHelpers.m"],
    hdrs = ["CertificateHelpers.h"],
    module_name = "santa_common_CertificateHelpers",
    deps = [
        ":MOLCertificate",
    ],
)

objc_library(
    name = "EncodeEntitlements",
    srcs = ["EncodeEntitlements.mm"],
    hdrs = ["EncodeEntitlements.h"],
    deps = [
        ":SNTLogging",
    ],
)

santa_unit_test(
    name = "EncodeEntitlementsTest",
    srcs = ["EncodeEntitlementsTest.mm"],
    deps = [
        ":EncodeEntitlements",
    ],
)

objc_library(
    name = "SigningIDHelpers",
    srcs = ["SigningIDHelpers.m"],
    hdrs = ["SigningIDHelpers.h"],
    deps = [
        ":MOLCodesignChecker",
        ":SNTLogging",
    ],
)

objc_library(
    name = "RingBuffer",
    hdrs = ["RingBuffer.h"],
    deps = [
        ":SNTLogging",
    ],
)

santa_unit_test(
    name = "RingBufferTest",
    srcs = ["RingBufferTest.mm"],
    deps = [":RingBuffer"],
)

objc_library(
    name = "TelemetryEventMap",
    srcs = ["TelemetryEventMap.mm"],
    hdrs = ["TelemetryEventMap.h"],
    deps = [
        ":Platform",
        ":String",
        "@com_google_absl//absl/container:flat_hash_map",
    ],
)

santa_unit_test(
    name = "TelemetryEventMapTest",
    srcs = ["TelemetryEventMapTest.mm"],
    deps = [
        ":Platform",
        ":TelemetryEventMap",
    ],
)

objc_library(
    name = "SNTBlockMessage",
    srcs = ["SNTBlockMessage.m"],
    hdrs = ["SNTBlockMessage.h"],
    deps = [
        ":SNTConfigurator",
        ":SNTDeviceEvent",
        ":SNTFileAccessEvent",
        ":SNTLogging",
        ":SNTStoredEvent",
        ":SNTSystemInfo",
    ],
)

objc_library(
    name = "SNTBlockMessage_SantaGUI",
    srcs = ["SNTBlockMessage.m"],
    hdrs = ["SNTBlockMessage.h"],
    defines = ["SANTAGUI"],
    module_name = "santa_common_SNTBlockMessage",
    deps = [
        ":SNTConfigurator",
        ":SNTDeviceEvent",
        ":SNTFileAccessEvent",
        ":SNTLogging",
        ":SNTStoredEvent",
        ":SNTSystemInfo",
    ],
)

objc_library(
    name = "SNTCachedDecision",
    srcs = ["SNTCachedDecision.mm"],
    hdrs = ["SNTCachedDecision.h"],
    deps = [
        ":SNTCommonEnums",
        ":SantaVnode",
    ],
)

objc_library(
    name = "SNTDeviceEvent",
    srcs = ["SNTDeviceEvent.m"],
    hdrs = ["SNTDeviceEvent.h"],
    module_name = "santa_common_SNTDeviceEvent",
    sdk_frameworks = [
        "Foundation",
    ],
    deps = [
        ":CoderMacros",
        ":SNTCommonEnums",
    ],
)

objc_library(
    name = "SNTFileAccessEvent",
    srcs = ["SNTFileAccessEvent.m"],
    hdrs = ["SNTFileAccessEvent.h"],
    module_name = "santa_common_SNTFileAccessEvent",
    sdk_frameworks = [
        "Foundation",
    ],
    deps = [
        ":CoderMacros",
        ":SNTStoredEvent",
    ],
)

objc_library(
    name = "SNTCommonEnums",
    module_name = "santa_common_SNTCommonEnums",
    textual_hdrs = ["SNTCommonEnums.h"],
)

objc_library(
    name = "SNTConfigurator",
    srcs = ["SNTConfigurator.m"],
    hdrs = ["SNTConfigurator.h"],
    module_name = "santa_common_SNTConfigurator",
    sdk_frameworks = [
        "Foundation",
    ],
    deps = [
        ":SNTCommonEnums",
        ":SNTRule",
        ":SNTStrengthify",
        ":SNTSystemInfo",
    ],
)

objc_library(
    name = "SNTKVOManager",
    srcs = ["SNTKVOManager.mm"],
    hdrs = ["SNTKVOManager.h"],
    deps = [
        ":SNTLogging",
    ],
)

objc_library(
    name = "SNTPostflightResult",
    srcs = ["SNTPostflightResult.mm"],
    hdrs = ["SNTPostflightResult.h"],
    deps = [
        ":CoderMacros",
        ":SNTCommonEnums",
        "//Source/santasyncservice:SNTSyncState",
    ],
)

santa_unit_test(
    name = "SNTPostflightResultTest",
    srcs = ["SNTPostflightResultTest.mm"],
    deps = [
        ":SNTCommonEnums",
        ":SNTPostflightResult",
        "//Source/santasyncservice:SNTSyncState",
    ],
)

santa_unit_test(
    name = "SNTKVOManagerTest",
    srcs = ["SNTKVOManagerTest.mm"],
    deps = [
        ":SNTKVOManager",
    ],
)

objc_library(
    name = "SNTDropRootPrivs",
    srcs = ["SNTDropRootPrivs.m"],
    hdrs = ["SNTDropRootPrivs.h"],
)

objc_library(
    name = "SNTFileInfo",
    srcs = ["SNTFileInfo.m"],
    hdrs = ["SNTFileInfo.h"],
    deps = [
        ":MOLCodesignChecker",
        ":SNTLogging",
        ":SantaVnode",
        "@FMDB",
    ],
)

objc_library(
    name = "SNTLogging",
    srcs = ["SNTLogging.m"],
    hdrs = ["SNTLogging.h"],
    deps = [":SNTConfigurator"],
)

objc_library(
    name = "PrefixTree",
    hdrs = ["PrefixTree.h"],
    deps = [
        ":SNTLogging",
        "@com_google_absl//absl/synchronization",
    ],
)

objc_library(
    name = "Unit",
    hdrs = ["Unit.h"],
)

objc_library(
    name = "SNTRule",
    srcs = ["SNTRule.m"],
    hdrs = ["SNTRule.h"],
    sdk_frameworks = [
        "Foundation",
    ],
    deps = [
        ":CoderMacros",
        ":SNTCommonEnums",
        ":SNTSyncConstants",
    ],
)

santa_unit_test(
    name = "SNTRuleTest",
    srcs = ["SNTRuleTest.m"],
    deps = [
        ":SNTCommonEnums",
        ":SNTRule",
        ":SNTSyncConstants",
    ],
)

objc_library(
    name = "SNTRuleIdentifiers",
    srcs = ["SNTRuleIdentifiers.m"],
    hdrs = ["SNTRuleIdentifiers.h"],
    deps = [
        ":CoderMacros",
    ],
)

objc_library(
    name = "CoderMacros",
    hdrs = ["CoderMacros.h"],
)

objc_library(
    name = "SNTStoredEvent",
    srcs = ["SNTStoredEvent.m"],
    hdrs = ["SNTStoredEvent.h"],
    module_name = "santa_common_SNTStoredEvent",
    deps = [
        ":CertificateHelpers",
        ":CoderMacros",
        ":MOLCertificate",
        ":SNTCommonEnums",
    ],
)

objc_library(
    name = "SNTConfigState",
    srcs = ["SNTConfigState.m"],
    hdrs = ["SNTConfigState.h"],
    module_name = "santa_common_SNTConfigState",
    deps = [
        ":CoderMacros",
        ":SNTCommonEnums",
        ":SNTConfigurator",
    ],
)

cc_library(
    name = "SNTStrengthify",
    hdrs = ["SNTStrengthify.h"],
)

objc_library(
    name = "SNTSyncConstants",
    srcs = ["SNTSyncConstants.m"],
    hdrs = ["SNTSyncConstants.h"],
    sdk_frameworks = [
        "Foundation",
    ],
)

objc_library(
    name = "SNTSystemInfo",
    srcs = ["SNTSystemInfo.m"],
    hdrs = ["SNTSystemInfo.h"],
    sdk_frameworks = [
        "Foundation",
        "IOKit",
    ],
)

objc_library(
    name = "SNTXPCBundleServiceInterface",
    srcs = ["SNTXPCBundleServiceInterface.m"],
    hdrs = ["SNTXPCBundleServiceInterface.h"],
    deps = [
        ":MOLXPCConnection",
        ":SNTStoredEvent",
    ],
)

objc_library(
    name = "SNTXPCMetricServiceInterface",
    srcs = ["SNTXPCMetricServiceInterface.m"],
    hdrs = ["SNTXPCMetricServiceInterface.h"],
    deps = [
        ":MOLXPCConnection",
    ],
)

objc_library(
    name = "SNTXPCControlInterface",
    srcs = ["SNTXPCControlInterface.m"],
    hdrs = ["SNTXPCControlInterface.h"],
    defines = select({
        "//:adhoc_build": ["SANTAADHOC"],
        "//conditions:default": None,
    }),
    deps = [
        ":MOLCodesignChecker",
        ":MOLXPCConnection",
        ":SNTCommonEnums",
        ":SNTConfigurator",
        ":SNTPostflightResult",
        ":SNTRule",
        ":SNTRuleIdentifiers",
        ":SNTStoredEvent",
        ":SNTXPCUnprivilegedControlInterface",
    ],
)

objc_library(
    name = "SNTXPCNotifierInterface",
    srcs = ["SNTXPCNotifierInterface.m"],
    hdrs = ["SNTXPCNotifierInterface.h"],
    deps = [
        ":SNTCommonEnums",
        ":SNTConfigState",
        ":SNTXPCBundleServiceInterface",
    ],
)

objc_library(
    name = "SNTMetricSet",
    srcs = ["SNTMetricSet.m"],
    hdrs = ["SNTMetricSet.h"],
    deps = [":SNTCommonEnums"],
)

objc_library(
    name = "SNTXPCSyncServiceInterface",
    srcs = ["SNTXPCSyncServiceInterface.m"],
    hdrs = ["SNTXPCSyncServiceInterface.h"],
    deps = [
        ":MOLXPCConnection",
        ":SNTCommonEnums",
        ":SNTStoredEvent",
    ],
)

objc_library(
    name = "SNTXPCUnprivilegedControlInterface",
    srcs = ["SNTXPCUnprivilegedControlInterface.m"],
    hdrs = ["SNTXPCUnprivilegedControlInterface.h"],
    deps = [
        ":MOLCertificate",
        ":MOLXPCConnection",
        ":SNTCommonEnums",
        ":SNTRule",
        ":SNTRuleIdentifiers",
        ":SNTStoredEvent",
        ":SNTXPCBundleServiceInterface",
        ":SantaVnode",
    ],
)

santa_unit_test(
    name = "SNTFileInfoTest",
    srcs = ["SNTFileInfoTest.m"],
    resources = [
        "testdata/32bitplist",
        "testdata/bad_pagezero",
        "testdata/missing_pagezero",
    ],
    structured_resources = glob([
        "testdata/BundleExample.app/**",
        "testdata/DirectoryBundle/**",
    ]),
    deps = [":SNTFileInfo"],
)

santa_unit_test(
    name = "PrefixTreeTest",
    srcs = ["PrefixTreeTest.mm"],
    deps = [
        ":PrefixTree",
        ":Unit",
    ],
)

santa_unit_test(
    name = "SNTMetricSetTest",
    srcs = ["SNTMetricSetTest.m"],
    deps = [":SNTMetricSet"],
)

santa_unit_test(
    name = "SNTCachedDecisionTest",
    srcs = ["SNTCachedDecisionTest.mm"],
    deps = [
        ":SNTCachedDecision",
        ":TestUtils",
        "@OCMock",
    ],
)

santa_unit_test(
    name = "SNTBlockMessageTest",
    srcs = ["SNTBlockMessageTest.m"],
    sdk_frameworks = [
        "AppKit",
    ],
    deps = [
        ":SNTBlockMessage_SantaGUI",
        ":SNTConfigurator",
        ":SNTFileAccessEvent",
        ":SNTStoredEvent",
        ":SNTSystemInfo",
        "@OCMock",
    ],
)

santa_unit_test(
    name = "SNTConfiguratorTest",
    srcs = ["SNTConfiguratorTest.m"],
    deps = [
        ":SNTCommonEnums",
        ":SNTConfigurator",
        "@OCMock",
    ],
)

test_suite(
    name = "unit_tests",
    tests = [
        ":EncodeEntitlementsTest",
        ":MOLAuthenticatingURLSessionTest",
        ":MOLCertificateTest",
        ":MOLCodesignCheckerTest",
        ":MOLXPCConnectionTest",
        ":PrefixTreeTest",
        ":RingBufferTest",
        ":SNTBlockMessageTest",
        ":SNTCachedDecisionTest",
        ":SNTConfiguratorTest",
        ":SNTFileInfoTest",
        ":SNTKVOManagerTest",
        ":SNTMetricSetTest",
        ":SNTRuleTest",
        ":SantaCacheTest",
        ":SantaSetCacheTest",
        ":ScopedCFTypeRefTest",
        ":ScopedIOObjectRefTest",
        ":TelemetryEventMapTest",
    ],
    visibility = ["//:santa_package_group"],
)

objc_library(
    name = "TestUtils",
    testonly = 1,
    srcs = ["TestUtils.mm"],
    hdrs = ["TestUtils.h"],
    sdk_dylibs = [
        "bsm",
    ],
    deps = [
        ":Platform",
        ":SystemResources",
        "@OCMock",
        "@com_google_googletest//:gtest",
    ],
)

genrule(
    name = "CommitHash",
    outs = ["CommitHash.plist"],
    cmd = """
    STABLE_GIT_COMMIT=$$(awk '/STABLE_GIT_COMMIT/ { print $$2 }' bazel-out/stable-status.txt)
    defaults write $${PWD}/$(@) SNTCommitHash -string $${STABLE_GIT_COMMIT:-unset}
    """,
    local = 1,
    message = "Generating CommitHash.plist",
    stamp = 1,
)

objc_library(
    name = "MOLCertificate",
    srcs = ["MOLCertificate.m"],
    hdrs = ["MOLCertificate.h"],
    sdk_frameworks = [
        "Foundation",
        "Security",
    ],
)

santa_unit_test(
    name = "MOLCertificateTest",
    srcs = ["MOLCertificateTest.m"],
    resources = glob([
        "testdata/*.pem",
        "testdata/*.crt",
    ]),
    deps = [":MOLCertificate"],
)

objc_library(
    name = "MOLCodesignChecker",
    srcs = ["MOLCodesignChecker.m"],
    hdrs = ["MOLCodesignChecker.h"],
    sdk_frameworks = [
        "Foundation",
        "Security",
    ],
    deps = [":MOLCertificate"],
)

santa_unit_test(
    name = "MOLCodesignCheckerTest",
    srcs = ["MOLCodesignCheckerTest.m"],
    resources = [
        "testdata/cal-yikes-universal",
        "testdata/cal-yikes-universal_adhoc",
        "testdata/cal-yikes-universal_signed",
        "testdata/signed-with-teamid",
        "testdata/yikes-universal",
        "testdata/yikes-universal_adhoc",
        "testdata/yikes-universal_signed",
    ],
    deps = [":MOLCodesignChecker"],
)

objc_library(
    name = "MOLXPCConnection",
    srcs = ["MOLXPCConnection.m"],
    hdrs = ["MOLXPCConnection.h"],
    sdk_frameworks = ["Security"],
    deps = [":MOLCodesignChecker"],
)

santa_unit_test(
    name = "MOLXPCConnectionTest",
    srcs = ["MOLXPCConnectionTest.m"],
    deps = [
        ":MOLXPCConnection",
        "@OCMock",
    ],
)

objc_library(
    name = "MOLAuthenticatingURLSession",
    srcs = [
        "MOLAuthenticatingURLSession.m",
        "MOLDERDecoder.h",
        "MOLDERDecoder.m",
    ],
    hdrs = ["MOLAuthenticatingURLSession.h"],
    sdk_frameworks = ["Security"],
    deps = [":MOLCertificate"],
)

santa_unit_test(
    name = "MOLAuthenticatingURLSessionTest",
    srcs = [
        "MOLAuthenticatingURLSessionTest.m",
        "MOLDERDecoder.h",
        "MOLDERDecoderTest.m",
    ],
    resources = [
        "testdata/dn.plist",
        "testdata/example_org_client_cert.pem",
        "testdata/example_org_client_cert_old.pem",
        "testdata/internet_widgits_client_cert.pem",
    ],
    deps = [
        ":MOLAuthenticatingURLSession",
    ],
)
