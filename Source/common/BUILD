load("@protobuf//bazel:cc_proto_library.bzl", "cc_proto_library")
load("@protobuf//bazel:proto_library.bzl", "proto_library")
load("@rules_cc//cc:defs.bzl", "cc_library", "objc_library")
load("//:helper.bzl", "santa_unit_test")

# Common is the folder containing all the code that's shared between multiple
# components, so every library in this package is visible to the whole group.
package(
    default_visibility = ["//:santa_package_group"],
)

licenses(["notice"])

proto_library(
    name = "santa_proto",
    srcs = ["santa.proto"],
    deps = [
        "//Source/santad/ProcessTree:process_tree_proto",
        "@protobuf//:any_proto",
        "@protobuf//:timestamp_proto",
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
    name = "NSData+Zlib",
    srcs = ["NSData+Zlib.mm"],
    hdrs = ["NSData+Zlib.h"],
    deps = [
        ":SNTLogging",
    ],
)

santa_unit_test(
    name = "NSDataZlibTest",
    srcs = [
        "NSDataZlibTest.mm",
    ],
    resources = glob(["testdata/compression_test_*.*"]),
    sdk_dylibs = ["libz"],
    deps = [
        ":NSData+Zlib",
    ],
)

objc_library(
    name = "SNTDeepCopy",
    srcs = ["SNTDeepCopy.mm"],
    hdrs = ["SNTDeepCopy.h"],
)

cc_library(
    name = "SantaCache",
    hdrs = ["SantaCache.h"],
    deps = [
        ":BranchPrediction",
        "@abseil-cpp//absl/hash",
    ],
)

santa_unit_test(
    name = "SantaCacheTest",
    srcs = ["SantaCacheTest.mm"],
    deps = [
        ":SantaCache",
    ],
)

cc_library(
    name = "SantaSetCache",
    hdrs = ["SantaSetCache.h"],
    deps = [
        ":SantaCache",
        "@abseil-cpp//absl/container:flat_hash_map",
        "@abseil-cpp//absl/container:flat_hash_set",
        "@abseil-cpp//absl/hash",
        "@abseil-cpp//absl/synchronization",
    ],
)

santa_unit_test(
    name = "SantaSetCacheTest",
    srcs = ["SantaSetCacheTest.mm"],
    deps = [
        ":SantaSetCache",
    ],
)

cc_library(
    name = "AuditUtilities",
    hdrs = ["AuditUtilities.h"],
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
    name = "ScopedFile",
    hdrs = ["ScopedFile.h"],
    deps = [
        ":SNTLogging",
        "@abseil-cpp//absl/status:statusor",
    ],
)

santa_unit_test(
    name = "ScopedFileTest",
    srcs = ["ScopedFileTest.mm"],
    deps = [
        ":ScopedFile",
        ":TestUtils",
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
        "@abseil-cpp//absl/hash",
    ],
)

objc_library(
    name = "Memoizer",
    hdrs = ["Memoizer.h"],
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
    srcs = ["CertificateHelpers.mm"],
    hdrs = ["CertificateHelpers.h"],
    module_name = "santa_common_CertificateHelpers",
    deps = [
        ":MOLCertificate",
        ":MOLCodesignChecker",
        ":SNTCommonEnums",
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
    srcs = ["SigningIDHelpers.mm"],
    hdrs = ["SigningIDHelpers.h"],
    module_name = "santa_common_SigningIDHelpers",
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
    name = "Glob",
    srcs = ["Glob.mm"],
    hdrs = ["Glob.h"],
    deps = [
        ":SNTLogging",
        "@abseil-cpp//absl/cleanup:cleanup",
    ],
)

objc_library(
    name = "Keychain",
    srcs = ["Keychain.mm"],
    hdrs = ["Keychain.h"],
    sdk_frameworks = [
        "Security",
    ],
    deps = [
        ":SNTLogging",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
    ],
)

santa_unit_test(
    name = "KeychainTest",
    srcs = ["KeychainTest.mm"],
    deps = [
        ":Keychain",
        ":TestUtils",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
    ],
)

objc_library(
    name = "TelemetryEventMap",
    srcs = ["TelemetryEventMap.mm"],
    hdrs = ["TelemetryEventMap.h"],
    deps = [
        ":Platform",
        ":String",
        "@abseil-cpp//absl/container:flat_hash_map",
    ],
)

objc_library(
    name = "PassKey",
    hdrs = ["PassKey.h"],
)

objc_library(
    name = "Timer",
    hdrs = ["Timer.h"],
    deps = [
        ":SNTLogging",
    ],
)

objc_library(
    name = "SNTXxhash",
    hdrs = ["SNTXxhash.h"],
    deps = [
        "@xxhash",
    ],
)

santa_unit_test(
    name = "SNTXxhashTest",
    srcs = ["SNTXxhashTest.mm"],
    deps = [
        ":SNTXxhash",
        ":String",
        ":TestUtils",
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
    srcs = ["SNTBlockMessage.mm"],
    hdrs = ["SNTBlockMessage.h"],
    deps = [
        ":SNTConfigurator",
        ":SNTDeviceEvent",
        ":SNTLogging",
        ":SNTStoredExecutionEvent",
        ":SNTStoredFileAccessEvent",
        ":SNTSystemInfo",
    ],
)

objc_library(
    name = "SNTBlockMessage_SantaGUI",
    srcs = ["SNTBlockMessage.mm"],
    hdrs = ["SNTBlockMessage.h"],
    defines = ["SANTAGUI"],
    module_name = "santa_common_SNTBlockMessage",
    deps = [
        ":SNTConfigurator",
        ":SNTDeviceEvent",
        ":SNTLogging",
        ":SNTStoredExecutionEvent",
        ":SNTStoredFileAccessEvent",
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
    srcs = ["SNTDeviceEvent.mm"],
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
    name = "SNTCommonEnums",
    module_name = "santa_common_SNTCommonEnums",
    textual_hdrs = ["SNTCommonEnums.h"],
)

objc_library(
    name = "SNTConfigurator",
    srcs = ["SNTConfigurator.mm"],
    hdrs = ["SNTConfigurator.h"],
    module_name = "santa_common_SNTConfigurator",
    sdk_frameworks = [
        "Foundation",
    ],
    deps = [
        ":SNTCommonEnums",
        ":SNTExportConfiguration",
        ":SNTLogging",
        ":SNTModeTransition",
        ":SNTRule",
        ":SNTStrengthify",
        ":SNTSystemInfo",
    ],
)

objc_library(
    name = "SNTConfigBundle",
    srcs = ["SNTConfigBundle.mm"],
    hdrs = ["SNTConfigBundle.h"],
    deps = [
        ":CoderMacros",
        ":SNTCommonEnums",
        ":SNTExportConfiguration",
        ":SNTModeTransition",
    ],
)

santa_unit_test(
    name = "SNTConfigBundleTest",
    srcs = ["SNTConfigBundleTest.mm"],
    deps = [
        ":SNTCommonEnums",
        ":SNTConfigBundle",
        ":SNTExportConfiguration",
        ":SNTModeTransition",
    ],
)

objc_library(
    name = "SNTExportConfiguration",
    srcs = ["SNTExportConfiguration.mm"],
    hdrs = ["SNTExportConfiguration.h"],
    deps = [
        ":CoderMacros",
        ":SNTCommonEnums",
        ":SNTLogging",
    ],
)

santa_unit_test(
    name = "SNTExportConfigurationTest",
    srcs = ["SNTExportConfigurationTest.mm"],
    deps = [
        ":SNTExportConfiguration",
    ],
)

objc_library(
    name = "SNTModeTransition",
    srcs = ["SNTModeTransition.mm"],
    hdrs = ["SNTModeTransition.h"],
    deps = [
        ":CoderMacros",
        ":SNTLogging",
    ],
)

santa_unit_test(
    name = "SNTModeTransitionTest",
    srcs = ["SNTModeTransitionTest.mm"],
    deps = [
        ":SNTModeTransition",
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

santa_unit_test(
    name = "SNTKVOManagerTest",
    srcs = ["SNTKVOManagerTest.mm"],
    deps = [
        ":SNTKVOManager",
    ],
)

objc_library(
    name = "SNTDropRootPrivs",
    srcs = ["SNTDropRootPrivs.mm"],
    hdrs = ["SNTDropRootPrivs.h"],
)

objc_library(
    name = "SNTFileInfo",
    srcs = ["SNTFileInfo.mm"],
    hdrs = ["SNTFileInfo.h"],
    module_name = "santa_common_SNTFileInfo",
    deps = [
        ":CertificateHelpers",
        ":MOLCodesignChecker",
        ":SNTError",
        ":SNTLogging",
        ":SantaVnode",
        "@FMDB",
    ],
)

objc_library(
    name = "SNTLogging",
    hdrs = ["SNTLogging.h"],
)

objc_library(
    name = "PrefixTree",
    hdrs = ["PrefixTree.h"],
    deps = [
        ":SNTLogging",
        "@abseil-cpp//absl/synchronization",
    ],
)

objc_library(
    name = "Unit",
    hdrs = ["Unit.h"],
)

objc_library(
    name = "SNTRule",
    srcs = ["SNTRule.mm"],
    hdrs = ["SNTRule.h"],
    sdk_frameworks = [
        "Foundation",
    ],
    deps = [
        ":CoderMacros",
        ":SNTCommonEnums",
        ":SNTError",
        ":SNTSyncConstants",
    ],
)

objc_library(
    name = "SNTFileAccessRule",
    srcs = ["SNTFileAccessRule.mm"],
    hdrs = ["SNTFileAccessRule.h"],
    deps = [
        ":CoderMacros",
    ],
)

santa_unit_test(
    name = "SNTRuleTest",
    srcs = ["SNTRuleTest.mm"],
    deps = [
        ":SNTCommonEnums",
        ":SNTError",
        ":SNTRule",
        ":SNTSyncConstants",
    ],
)

objc_library(
    name = "SNTRuleIdentifiers",
    srcs = ["SNTRuleIdentifiers.mm"],
    hdrs = ["SNTRuleIdentifiers.h"],
    deps = [
        ":CoderMacros",
        ":SNTCommonEnums",
    ],
)

objc_library(
    name = "CoderMacros",
    hdrs = ["CoderMacros.h"],
)

objc_library(
    name = "SNTStoredEvent",
    srcs = ["SNTStoredEvent.mm"],
    hdrs = ["SNTStoredEvent.h"],
    module_name = "santa_common_SNTStoredEvent",
    deps = [
        ":CoderMacros",
    ],
)

objc_library(
    name = "SNTStoredExecutionEvent",
    srcs = ["SNTStoredExecutionEvent.mm"],
    hdrs = ["SNTStoredExecutionEvent.h"],
    module_name = "santa_common_SNTStoredExecutionEvent",
    deps = [
        ":CertificateHelpers",
        ":CoderMacros",
        ":MOLCertificate",
        ":MOLCodesignChecker",
        ":SNTCommonEnums",
        ":SNTFileInfo",
        ":SNTStoredEvent",
        ":SigningIDHelpers",
    ],
)

objc_library(
    name = "SNTStoredFileAccessEvent",
    srcs = ["SNTStoredFileAccessEvent.mm"],
    hdrs = ["SNTStoredFileAccessEvent.h"],
    module_name = "santa_common_SNTStoredFileAccessEvent",
    deps = [
        ":CertificateHelpers",
        ":CoderMacros",
        ":MOLCertificate",
        ":SNTCommonEnums",
        ":SNTStoredEvent",
    ],
)

santa_unit_test(
    name = "SNTStoredEventTest",
    srcs = ["SNTStoredEventTest.mm"],
    deps = [
        ":SNTStoredEvent",
        ":SNTStoredExecutionEvent",
        ":SNTStoredFileAccessEvent",
    ],
)

santa_unit_test(
    name = "SNTStoredExecutionEventTest",
    srcs = ["SNTStoredExecutionEventTest.mm"],
    resources = [
        "testdata/signed-with-teamid",
    ],
    structured_resources = glob([
        "testdata/BundleExample.app/**",
    ]),
    deps = [
        ":SNTFileInfo",
        ":SNTStoredExecutionEvent",
    ],
)

objc_library(
    name = "SNTConfigState",
    srcs = ["SNTConfigState.mm"],
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
    srcs = ["SNTSyncConstants.mm"],
    hdrs = ["SNTSyncConstants.h"],
    sdk_frameworks = [
        "Foundation",
    ],
)

objc_library(
    name = "SNTSystemInfo",
    srcs = ["SNTSystemInfo.mm"],
    hdrs = ["SNTSystemInfo.h"],
    sdk_frameworks = [
        "Foundation",
        "IOKit",
    ],
)

objc_library(
    name = "SNTSIPStatus",
    srcs = ["SNTSIPStatus.mm"],
    hdrs = ["SNTSIPStatus.h"],
    sdk_frameworks = [
        "Foundation",
    ],
    deps = [
        ":SNTLogging",
    ],
)

objc_library(
    name = "SNTXPCBundleServiceInterface",
    srcs = ["SNTXPCBundleServiceInterface.mm"],
    hdrs = ["SNTXPCBundleServiceInterface.h"],
    deps = [
        ":MOLXPCConnection",
        ":SNTStoredEvent",
        ":SNTStoredExecutionEvent",
    ],
)

objc_library(
    name = "SNTXPCMetricServiceInterface",
    srcs = ["SNTXPCMetricServiceInterface.mm"],
    hdrs = ["SNTXPCMetricServiceInterface.h"],
    deps = [
        ":MOLXPCConnection",
    ],
)

objc_library(
    name = "SNTXPCControlInterface",
    srcs = ["SNTXPCControlInterface.mm"],
    hdrs = ["SNTXPCControlInterface.h"],
    defines = select({
        "//:adhoc_build": ["SANTAADHOC"],
        "//conditions:default": None,
    }),
    deps = [
        ":MOLCodesignChecker",
        ":MOLXPCConnection",
        ":SNTCommonEnums",
        ":SNTConfigBundle",
        ":SNTConfigurator",
        ":SNTFileAccessRule",
        ":SNTRule",
        ":SNTRuleIdentifiers",
        ":SNTStoredEvent",
        ":SNTStoredExecutionEvent",
        ":SNTXPCUnprivilegedControlInterface",
    ],
)

objc_library(
    name = "SNTXPCNotifierInterface",
    srcs = ["SNTXPCNotifierInterface.mm"],
    hdrs = ["SNTXPCNotifierInterface.h"],
    deps = [
        ":SNTCommonEnums",
        ":SNTConfigState",
        ":SNTXPCBundleServiceInterface",
    ],
)

objc_library(
    name = "SNTMetricSet",
    srcs = ["SNTMetricSet.mm"],
    hdrs = ["SNTMetricSet.h"],
    deps = [":SNTCommonEnums"],
)

objc_library(
    name = "SNTXPCSyncServiceInterface",
    srcs = ["SNTXPCSyncServiceInterface.mm"],
    hdrs = ["SNTXPCSyncServiceInterface.h"],
    module_name = "santa_common_SNTXPCSyncServiceInterface",
    deps = [
        ":MOLXPCConnection",
        ":SNTCommonEnums",
        ":SNTExportConfiguration",
        ":SNTStoredEvent",
        ":SNTStoredExecutionEvent",
        ":SNTStoredFileAccessEvent",
    ],
)

objc_library(
    name = "SNTXPCUnprivilegedControlInterface",
    srcs = ["SNTXPCUnprivilegedControlInterface.mm"],
    hdrs = ["SNTXPCUnprivilegedControlInterface.h"],
    deps = [
        ":MOLCertificate",
        ":MOLXPCConnection",
        ":SNTCommonEnums",
        ":SNTRule",
        ":SNTRuleIdentifiers",
        ":SNTStoredEvent",
        ":SNTStoredExecutionEvent",
        ":SNTXPCBundleServiceInterface",
        ":SantaVnode",
        "//Source/common/faa:WatchItems",
    ],
)

objc_library(
    name = "SNTError",
    srcs = ["SNTError.mm"],
    hdrs = ["SNTError.h"],
)

santa_unit_test(
    name = "SNTFileInfoTest",
    srcs = ["SNTFileInfoTest.mm"],
    resources = [
        "testdata/32bitplist",
        "testdata/bad_pagezero",
        "testdata/cal-yikes-universal",
        "testdata/missing_pagezero",
        "testdata/yikes-universal_adhoc",
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
    srcs = ["SNTMetricSetTest.mm"],
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
    srcs = ["SNTBlockMessageTest.mm"],
    sdk_frameworks = [
        "AppKit",
    ],
    deps = [
        ":SNTBlockMessage_SantaGUI",
        ":SNTConfigurator",
        ":SNTStoredExecutionEvent",
        ":SNTStoredFileAccessEvent",
        ":SNTSystemInfo",
        "@OCMock",
    ],
)

santa_unit_test(
    name = "SNTConfiguratorTest",
    srcs = ["SNTConfiguratorTest.mm"],
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
        ":KeychainTest",
        ":MOLAuthenticatingURLSessionTest",
        ":MOLCertificateTest",
        ":MOLCodesignCheckerTest",
        ":MOLXPCConnectionTest",
        ":NSDataZlibTest",
        ":PrefixTreeTest",
        ":RingBufferTest",
        ":SNTBlockMessageTest",
        ":SNTCachedDecisionTest",
        ":SNTConfigBundleTest",
        ":SNTConfiguratorTest",
        ":SNTExportConfigurationTest",
        ":SNTFileInfoTest",
        ":SNTKVOManagerTest",
        ":SNTMetricSetTest",
        ":SNTModeTransitionTest",
        ":SNTRuleTest",
        ":SNTStoredEventTest",
        ":SNTStoredExecutionEventTest",
        ":SNTXxhashTest",
        ":SantaCacheTest",
        ":SantaSetCacheTest",
        ":ScopedCFTypeRefTest",
        ":ScopedFileTest",
        ":ScopedIOObjectRefTest",
        ":TelemetryEventMapTest",
        "//Source/common/cel:CELTest",
        "//Source/common/faa:unit_tests",
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
        "@googletest//:gtest",
    ],
)

genrule(
    name = "CommitHash",
    outs = ["CommitHash.plist"],
    cmd = """
    STABLE_GIT_COMMIT=$$(awk '/STABLE_GIT_COMMIT/ { print $$2 }' bazel-out/stable-status.txt)
    defaults write $${PWD}/$(@) SNTCommitHash -string $${STABLE_GIT_COMMIT:-unset}
    """,
    local = True,
    message = "Generating CommitHash.plist",
    stamp = 1,
)

objc_library(
    name = "MOLCertificate",
    srcs = ["MOLCertificate.mm"],
    hdrs = ["MOLCertificate.h"],
    sdk_frameworks = [
        "Foundation",
        "Security",
    ],
)

santa_unit_test(
    name = "MOLCertificateTest",
    srcs = ["MOLCertificateTest.mm"],
    resources = glob([
        "testdata/*.pem",
        "testdata/*.crt",
    ]),
    deps = [":MOLCertificate"],
)

objc_library(
    name = "MOLCodesignChecker",
    srcs = ["MOLCodesignChecker.mm"],
    hdrs = ["MOLCodesignChecker.h"],
    module_name = "santa_common_MOLCodesignChecker",
    sdk_frameworks = [
        "Foundation",
        "Security",
    ],
    deps = [
        ":MOLCertificate",
        "//Source/common:ScopedCFTypeRef",
        "//Source/common:String",
    ],
)

santa_unit_test(
    name = "MOLCodesignCheckerTest",
    srcs = ["MOLCodesignCheckerTest.mm"],
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
    srcs = ["MOLXPCConnection.mm"],
    hdrs = ["MOLXPCConnection.h"],
    module_name = "santa_common_MOLXPCConnection",
    sdk_frameworks = ["Security"],
    deps = [":MOLCodesignChecker"],
)

santa_unit_test(
    name = "MOLXPCConnectionTest",
    srcs = ["MOLXPCConnectionTest.mm"],
    deps = [
        ":MOLXPCConnection",
        "@OCMock",
    ],
)

objc_library(
    name = "MOLAuthenticatingURLSession",
    srcs = [
        "MOLAuthenticatingURLSession.mm",
        "MOLDERDecoder.h",
        "MOLDERDecoder.mm",
    ],
    hdrs = ["MOLAuthenticatingURLSession.h"],
    sdk_frameworks = ["Security"],
    deps = [
        ":MOLCertificate",
        ":ScopedCFTypeRef",
    ],
)

santa_unit_test(
    name = "MOLAuthenticatingURLSessionTest",
    srcs = [
        "MOLAuthenticatingURLSessionTest.mm",
        "MOLDERDecoder.h",
        "MOLDERDecoderTest.mm",
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
