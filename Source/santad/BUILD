load("@rules_apple//apple:macos.bzl", "macos_bundle")
load("@rules_cc//cc:defs.bzl", "objc_library")
load("//:helper.bzl", "SANTA_MINIMUM_OS_VERSION", "santa_unit_test")

package(
    default_visibility = [":__subpackages__"],
)

licenses(["notice"])

objc_library(
    name = "SNTDatabaseTable",
    srcs = ["DataLayer/SNTDatabaseTable.mm"],
    hdrs = ["DataLayer/SNTDatabaseTable.h"],
    deps = [
        "//Source/common:SNTLogging",
        "@FMDB",
    ],
)

objc_library(
    name = "SNTRuleTable",
    srcs = ["DataLayer/SNTRuleTable.mm"],
    hdrs = ["DataLayer/SNTRuleTable.h"],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
    deps = [
        ":SNTDatabaseTable",
        "//Source/common:CertificateHelpers",
        "//Source/common:MOLCertificate",
        "//Source/common:MOLCodesignChecker",
        "//Source/common:Platform",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTError",
        "//Source/common:SNTFileAccessRule",
        "//Source/common:SNTFileInfo",
        "//Source/common:SNTLogging",
        "//Source/common:SNTRule",
        "//Source/common:SNTRuleIdentifiers",
        "//Source/common:SNTXxhash",
        "//Source/common:SigningIDHelpers",
        "//Source/common:String",
        "//Source/common/cel:CEL",
    ],
)

objc_library(
    name = "SNTEventTable",
    srcs = ["DataLayer/SNTEventTable.mm"],
    hdrs = ["DataLayer/SNTEventTable.h"],
    deps = [
        ":SNTDatabaseTable",
        "//Source/common:MOLCertificate",
        "//Source/common:SNTLogging",
        "//Source/common:SNTStoredExecutionEvent",
        "//Source/common:SNTStoredFileAccessEvent",
        "//Source/common:SNTStoredTemporaryMonitorModeAuditEvent",
        "//Source/common:SantaCache",
        "//Source/common:String",
    ],
)

objc_library(
    name = "SNTDatabaseController",
    srcs = ["SNTDatabaseController.mm"],
    hdrs = ["SNTDatabaseController.h"],
    deps = [
        ":SNTEventTable",
        ":SNTRuleTable",
        "//Source/common:SNTLogging",
        "@FMDB",
    ],
)

objc_library(
    name = "SNTApplicationCoreMetrics",
    srcs = ["SNTApplicationCoreMetrics.mm"],
    hdrs = ["SNTApplicationCoreMetrics.h"],
    deps = [
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTMetricSet",
        "//Source/common:SNTSystemInfo",
        "//Source/common:SystemResources",
    ],
)

objc_library(
    name = "DiskArbitrationTestLib",
    testonly = 1,
    srcs = ["EventProviders/DiskArbitrationTestUtil.mm"],
    hdrs = ["EventProviders/DiskArbitrationTestUtil.h"],
    sdk_dylibs = [
        "EndpointSecurity",
        "bsm",
    ],
    sdk_frameworks = [
        "DiskArbitration",
        "IOKit",
    ],
)

objc_library(
    name = "SNTDecisionCache",
    srcs = ["SNTDecisionCache.mm"],
    hdrs = ["SNTDecisionCache.h"],
    deps = [
        ":EntitlementsFilter",
        ":SNTDatabaseController",
        ":SNTRuleTable",
        "//Source/common:AuditUtilities",
        "//Source/common:CodeSigningIdentifierUtils",
        "//Source/common:MOLCertificate",
        "//Source/common:MOLCodesignChecker",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTLogging",
        "//Source/common:SNTRule",
        "//Source/common:SantaCache",
        "//Source/common:SantaVnode",
        "//Source/common:SystemResources",
    ],
)

objc_library(
    name = "SNTCompilerController",
    srcs = ["SNTCompilerController.mm"],
    hdrs = ["SNTCompilerController.h"],
    deps = [
        ":EndpointSecurityLogger",
        ":SNTDatabaseController",
        ":SNTDecisionCache",
        ":SNTRuleTable",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTFileInfo",
        "//Source/common:SNTLogging",
        "//Source/common:SNTRule",
        "//Source/common:String",
        "//Source/common/es:EndpointSecurityMessage",
    ],
)

objc_library(
    name = "SNTNotificationQueue",
    srcs = ["SNTNotificationQueue.mm"],
    hdrs = ["SNTNotificationQueue.h"],
    deps = [
        "//Source/common:MOLXPCConnection",
        "//Source/common:RingBuffer",
        "//Source/common:SNTConfigState",
        "//Source/common:SNTLogging",
        "//Source/common:SNTStoredExecutionEvent",
        "//Source/common:SNTStrengthify",
        "//Source/common:SNTXPCNotifierInterface",
    ],
)

santa_unit_test(
    name = "SNTNotificationQueueTest",
    srcs = ["SNTNotificationQueueTest.mm"],
    deps = [
        ":SNTNotificationQueue",
        "//Source/common:MOLXPCConnection",
        "//Source/common:SNTConfigState",
        "//Source/common:SNTStoredExecutionEvent",
        "//Source/common:SNTXPCNotifierInterface",
        "//Source/common:TestUtils",
        "@OCMock",
    ],
)

objc_library(
    name = "SNTSyncdQueue",
    srcs = ["SNTSyncdQueue.mm"],
    hdrs = ["SNTSyncdQueue.h"],
    deps = [
        "//Source/common:MOLXPCConnection",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTExportConfiguration",
        "//Source/common:SNTLogging",
        "//Source/common:SNTStoredExecutionEvent",
        "//Source/common:SNTStoredFileAccessEvent",
        "//Source/common:SNTXPCSyncServiceInterface",
        "//Source/common:SantaCache",
        "//Source/common:String",
    ],
)

santa_unit_test(
    name = "SNTSyncdQueueTest",
    srcs = ["SNTSyncdQueueTest.mm"],
    deps = [
        ":SNTSyncdQueue",
        "//Source/common:SNTStoredExecutionEvent",
        "@OCMock",
    ],
)

objc_library(
    name = "SNTNetworkExtensionQueue",
    srcs = ["SNTNetworkExtensionQueue.mm"],
    hdrs = ["SNTNetworkExtensionQueue.h"],
    deps = [
        ":EndpointSecurityLogger",
        ":SNTNotificationQueue",
        ":SNTSyncdQueue",
        "//Source/common:MOLXPCConnection",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTError",
        "//Source/common:SNTFileInfo",
        "//Source/common:SNTKVOManager",
        "//Source/common:SNTLogging",
        "//Source/common:SNTStrengthify",
        "//Source/common:SNTXPCNotifierInterface",
        "//Source/common/ne:SNTNetworkExtensionSettings",
        "//Source/common/ne:SNTSyncNetworkExtensionSettings",
        "//Source/common/ne:SNTXPCNetworkExtensionInterface",
        "@santanetd//src/santanetd:SNDProcessFlows",
    ],
)

objc_library(
    name = "SNTPolicyProcessor",
    srcs = ["SNTPolicyProcessor.mm"],
    hdrs = ["SNTPolicyProcessor.h"],
    deps = [
        ":EntitlementsFilter",
        ":SNTRuleTable",
        "//Source/common:CertificateHelpers",
        "//Source/common:MOLCertificate",
        "//Source/common:MOLCodesignChecker",
        "//Source/common:MOLXPCConnection",
        "//Source/common:SNTCELFallbackRule",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigState",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTDeepCopy",
        "//Source/common:SNTFileInfo",
        "//Source/common:SNTKVOManager",
        "//Source/common:SNTLogging",
        "//Source/common:SNTRule",
        "//Source/common:SNTRuleIdentifiers",
        "//Source/common:SigningIDHelpers",
        "//Source/common:String",
        "//Source/common/cel:CEL",
        "//Source/common/processtree:process_tree",
        "@FMDB",
        "@abseil-cpp//absl/container:flat_hash_map",
        "@northpolesec_protos//cel:v1_cc_proto",
    ],
)

santa_unit_test(
    name = "SNTPolicyProcessorTest",
    srcs = ["SNTPolicyProcessorTest.mm"],
    deps = [
        ":SNTPolicyProcessor",
        "//Source/common:SNTCELFallbackRule",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTRule",
        "//Source/common:TestUtils",
    ],
)

objc_library(
    name = "TemporaryMonitorMode",
    srcs = ["TemporaryMonitorMode.mm"],
    hdrs = ["TemporaryMonitorMode.h"],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
    deps = [
        ":SNTNotificationQueue",
        "//Source/common:PassKey",
        "//Source/common:Pinning",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTError",
        "//Source/common:SNTKVOManager",
        "//Source/common:SNTModeTransition",
        "//Source/common:SNTStoredTemporaryMonitorModeAuditEvent",
        "//Source/common:SNTSystemInfo",
        "//Source/common:SystemResources",
        "//Source/common:Timer",
        "@abseil-cpp//absl/synchronization",
    ],
)

santa_unit_test(
    name = "TemporaryMonitorModeTest",
    srcs = ["TemporaryMonitorModeTest.mm"],
    deps = [
        ":SNTNotificationQueue",
        ":TemporaryMonitorMode",
        "//Source/common:SNTModeTransition",
        "//Source/common:SystemResources",
        "@OCMock",
    ],
)

objc_library(
    name = "TTYWriter",
    srcs = ["TTYWriter.mm"],
    hdrs = ["TTYWriter.h"],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
    deps = [
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTLogging",
        "//Source/common:String",
    ],
)

objc_library(
    name = "ProcessControl",
    srcs = ["ProcessControl.mm"],
    hdrs = ["ProcessControl.h"],
    deps = [
        "//Source/common:SNTLogging",
    ],
)

objc_library(
    name = "DaemonConfigBundle",
    srcs = ["DaemonConfigBundle.mm"],
    hdrs = ["DaemonConfigBundle.h"],
    deps = [
        "//Source/common:SNTConfigBundle",
        "//Source/common:SNTConfigurator",
    ],
)

santa_unit_test(
    name = "DaemonConfigBundleTest",
    srcs = ["DaemonConfigBundleTest.mm"],
    deps = [
        ":DaemonConfigBundle",
        "@OCMock",
    ],
)

objc_library(
    name = "EntitlementsFilter",
    srcs = ["EntitlementsFilter.mm"],
    hdrs = ["EntitlementsFilter.h"],
    deps = [
        "//Source/common:PrefixTree",
        "//Source/common:SNTDeepCopy",
        "//Source/common:String",
        "//Source/common:Unit",
        "@abseil-cpp//absl/synchronization",
    ],
)

santa_unit_test(
    name = "EntitlementsFilterTest",
    srcs = ["EntitlementsFilterTest.mm"],
    deps = [
        ":EntitlementsFilter",
    ],
)

objc_library(
    name = "CELActivation",
    srcs = ["CELActivation.mm"],
    hdrs = ["CELActivation.h"],
    deps = [
        ":SNTPolicyProcessor",
        "//Source/common:MOLCodesignChecker",
        "//Source/common:SigningIDHelpers",
        "//Source/common:String",
        "//Source/common/cel:CEL",
        "//Source/common/es:EndpointSecurityAPI",
        "//Source/common/es:EndpointSecurityMessage",
        "//Source/common/processtree:process",
        "//Source/common/processtree:process_tree",
    ],
)

objc_library(
    name = "SNTExecutionController",
    srcs = ["SNTExecutionController.mm"],
    hdrs = ["SNTExecutionController.h"],
    deps = [
        ":CELActivation",
        ":ProcessControl",
        ":SNTDecisionCache",
        ":SNTEventTable",
        ":SNTNotificationQueue",
        ":SNTPolicyProcessor",
        ":SNTRuleTable",
        ":SNTSyncdQueue",
        ":TTYWriter",
        "//Source/common:BranchPrediction",
        "//Source/common:MOLCodesignChecker",
        "//Source/common:PrefixTree",
        "//Source/common:SNTBlockMessage",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigState",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTFileInfo",
        "//Source/common:SNTLogging",
        "//Source/common:SNTMetricSet",
        "//Source/common:SNTRule",
        "//Source/common:SNTStoredExecutionEvent",
        "//Source/common:SantaVnode",
        "//Source/common:String",
        "//Source/common:Unit",
        "//Source/common/es:EndpointSecurityAPI",
        "//Source/common/es:EndpointSecurityMessage",
        "//Source/common/processtree:process",
        "//Source/common/processtree:process_tree",
        "@abseil-cpp//absl/synchronization",
    ],
)

objc_library(
    name = "SNTEndpointSecurityTreeAwareClient",
    srcs = ["EventProviders/SNTEndpointSecurityTreeAwareClient.mm"],
    hdrs = ["EventProviders/SNTEndpointSecurityTreeAwareClient.h"],
    deps = [
        "//Source/common/es:ESMetricsObserver",
        "//Source/common/es:EndpointSecurityAPI",
        "//Source/common/es:EndpointSecurityMessage",
        "//Source/common/es:SNTEndpointSecurityClient",
        "//Source/common/processtree:SNTEndpointSecurityAdapter",
        "//Source/common/processtree:process_tree",
    ],
)

santa_unit_test(
    name = "SNTEndpointSecurityTreeAwareClientTest",
    srcs = ["EventProviders/SNTEndpointSecurityTreeAwareClientTest.mm"],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
    deps = [
        ":Metrics",
        ":SNTEndpointSecurityTreeAwareClient",
        "//Source/common:TestUtils",
        "//Source/common/es:EndpointSecurityMessage",
        "//Source/common/es:MockEndpointSecurityAPI",
        "@OCMock",
        "@googletest//:gtest",
    ],
)

objc_library(
    name = "SNTEndpointSecurityRecorder",
    srcs = ["EventProviders/SNTEndpointSecurityRecorder.mm"],
    hdrs = ["EventProviders/SNTEndpointSecurityRecorder.h"],
    deps = [
        ":AuthResultCache",
        ":EndpointSecurityLogger",
        ":SNTCompilerController",
        ":SNTEndpointSecurityTreeAwareClient",
        "//Source/common:Platform",
        "//Source/common:PrefixTree",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTLogging",
        "//Source/common:String",
        "//Source/common:TelemetryEventMap",
        "//Source/common:Unit",
        "//Source/common/es:ESMetricsObserver",
        "//Source/common/es:EndpointSecurityAPI",
        "//Source/common/es:EndpointSecurityEnrichedTypes",
        "//Source/common/es:EndpointSecurityEnricher",
        "//Source/common/es:EndpointSecurityMessage",
        "//Source/common/es:SNTEndpointSecurityEventHandler",
        "//Source/common/processtree:process_tree",
    ],
)

objc_library(
    name = "SNTEndpointSecurityTamperResistance",
    srcs = ["EventProviders/SNTEndpointSecurityTamperResistance.mm"],
    hdrs = ["EventProviders/SNTEndpointSecurityTamperResistance.h"],
    deps = [
        ":EndpointSecurityLogger",
        "//Source/common:SNTLogging",
        "//Source/common/es:ESMetricsObserver",
        "//Source/common/es:EndpointSecurityAPI",
        "//Source/common/es:EndpointSecurityMessage",
        "//Source/common/es:SNTEndpointSecurityClient",
        "//Source/common/es:SNTEndpointSecurityEventHandler",
        "//Source/common/faa:WatchItemPolicy",
    ],
)

objc_library(
    name = "SNTEndpointSecurityAuthorizer",
    srcs = ["EventProviders/SNTEndpointSecurityAuthorizer.mm"],
    hdrs = ["EventProviders/SNTEndpointSecurityAuthorizer.h"],
    deps = [
        ":AuthResultCache",
        ":SNTCompilerController",
        ":SNTExecutionController",
        ":TTYWriter",
        "//Source/common:BranchPrediction",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTLogging",
        "//Source/common/es:ESMetricsObserver",
        "//Source/common/es:EndpointSecurityAPI",
        "//Source/common/es:EndpointSecurityEnrichedTypes",
        "//Source/common/es:EndpointSecurityEnricher",
        "//Source/common/es:EndpointSecurityMessage",
        "//Source/common/es:SNTEndpointSecurityClient",
        "//Source/common/es:SNTEndpointSecurityEventHandler",
    ],
)

objc_library(
    name = "FAAPolicyProcessor",
    srcs = ["EventProviders/FAAPolicyProcessor.mm"],
    hdrs = ["EventProviders/FAAPolicyProcessor.h"],
    deps = [
        ":EndpointSecurityLogger",
        ":EntitlementsFilter",
        ":Metrics",
        ":RateLimiter",
        ":SNTDecisionCache",
        ":TTYWriter",
        "//Source/common:AuditUtilities",
        "//Source/common:MOLCertificate",
        "//Source/common:MOLCodesignChecker",
        "//Source/common:SNTBlockMessage",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTStoredFileAccessEvent",
        "//Source/common:SantaCache",
        "//Source/common:SantaSetCache",
        "//Source/common:SantaVnode",
        "//Source/common:String",
        "//Source/common/es:EndpointSecurityEnricher",
        "//Source/common/es:EndpointSecurityMessage",
        "//Source/common/es:SNTEndpointSecurityEventHandler",
        "//Source/common/faa:WatchItemPolicy",
    ],
)

objc_library(
    name = "SNTEndpointSecurityDataFileAccessAuthorizer",
    srcs = ["EventProviders/SNTEndpointSecurityDataFileAccessAuthorizer.mm"],
    hdrs = ["EventProviders/SNTEndpointSecurityDataFileAccessAuthorizer.h"],
    sdk_dylibs = [
        "bsm",
    ],
    deps = [
        ":EndpointSecurityLogger",
        ":FAAPolicyProcessor",
        "//Source/common:AuditUtilities",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTMetricSet",
        "//Source/common:SNTStrengthify",
        "//Source/common/es:ESMetricsObserver",
        "//Source/common/es:EndpointSecurityAPI",
        "//Source/common/es:EndpointSecurityMessage",
        "//Source/common/es:SNTEndpointSecurityClient",
        "//Source/common/es:SNTEndpointSecurityEventHandler",
        "//Source/common/faa:WatchItemPolicy",
        "//Source/common/faa:WatchItems",
    ],
)

objc_library(
    name = "SNTEndpointSecurityProcessFileAccessAuthorizer",
    srcs = ["EventProviders/SNTEndpointSecurityProcessFileAccessAuthorizer.mm"],
    hdrs = ["EventProviders/SNTEndpointSecurityProcessFileAccessAuthorizer.h"],
    deps = [
        ":FAAPolicyProcessor",
        "//Source/common:AuditUtilities",
        "//Source/common:SNTLogging",
        "//Source/common:SantaCache",
        "//Source/common:SantaSetCache",
        "//Source/common/es:ESMetricsObserver",
        "//Source/common/es:EndpointSecurityAPI",
        "//Source/common/es:EndpointSecurityMessage",
        "//Source/common/es:SNTEndpointSecurityClient",
        "//Source/common/es:SNTEndpointSecurityEventHandler",
        "//Source/common/faa:WatchItemPolicy",
        "//Source/common/faa:WatchItems",
    ],
)

objc_library(
    name = "SNTEndpointSecurityDeviceManager",
    srcs = ["EventProviders/SNTEndpointSecurityDeviceManager.mm"],
    hdrs = ["EventProviders/SNTEndpointSecurityDeviceManager.h"],
    sdk_frameworks = [
        "DiskArbitration",
    ],
    deps = [
        ":AuthResultCache",
        ":EndpointSecurityLogger",
        ":EndpointSecuritySerializerUtilities",
        "//Source/common:AuditUtilities",
        "//Source/common:Platform",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTDeviceEvent",
        "//Source/common:SNTLogging",
        "//Source/common:SNTMetricSet",
        "//Source/common:SNTProcessChain",
        "//Source/common:SNTStoredNetworkMountEvent",
        "//Source/common:SNTStoredUSBMountEvent",
        "//Source/common:String",
        "//Source/common/es:ESMetricsObserver",
        "//Source/common/es:EndpointSecurityAPI",
        "//Source/common/es:EndpointSecurityEnricher",
        "//Source/common/es:EndpointSecurityMessage",
        "//Source/common/es:SNTEndpointSecurityClient",
        "//Source/common/es:SNTEndpointSecurityEventHandler",
    ],
)

objc_library(
    name = "AuthResultCache",
    srcs = ["EventProviders/AuthResultCache.mm"],
    hdrs = ["EventProviders/AuthResultCache.h"],
    deps = [
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTLogging",
        "//Source/common:SNTMetricSet",
        "//Source/common:SantaCache",
        "//Source/common:SantaVnode",
        "//Source/common/es:EndpointSecurityAPI",
        "//Source/common/es:EndpointSecurityClient",
        "//Source/common/es:SNTEndpointSecurityClientBase",
    ],
)

objc_library(
    name = "RateLimiter",
    srcs = ["EventProviders/RateLimiter.mm"],
    hdrs = ["EventProviders/RateLimiter.h"],
    deps = [
        ":Metrics",
        "//Source/common:BranchPrediction",
        "//Source/common:SNTLogging",
        "//Source/common:SystemResources",
    ],
)

objc_library(
    name = "EndpointSecuritySerializer",
    srcs = ["Logs/EndpointSecurity/Serializers/Serializer.mm"],
    hdrs = ["Logs/EndpointSecurity/Serializers/Serializer.h"],
    deps = [
        ":SNTDecisionCache",
        "//Source/common:AuditUtilities",
        "//Source/common:Platform",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTSystemInfo",
        "//Source/common:SNTXxhash",
        "//Source/common:String",
        "//Source/common/es:EndpointSecurityEnrichedTypes",
        "//Source/common/es:EndpointSecurityMessage",
        "@santanetd//src/santanetd:SNDProcessFlows",
    ],
)

objc_library(
    name = "EndpointSecuritySerializerUtilities",
    srcs = ["Logs/EndpointSecurity/Serializers/Utilities.mm"],
    hdrs = ["Logs/EndpointSecurity/Serializers/Utilities.h"],
    sdk_dylibs = [
        "bsm",
    ],
    deps = [
        ":SNTDecisionCache",
        "//Source/common:SantaCache",
        "//Source/common:SantaVnode",
        "//Source/common:String",
        "//Source/common/es:EndpointSecurityMessage",
    ],
)

objc_library(
    name = "EndpointSecuritySerializerEmpty",
    srcs = ["Logs/EndpointSecurity/Serializers/Empty.mm"],
    hdrs = ["Logs/EndpointSecurity/Serializers/Empty.h"],
    deps = [
        ":EndpointSecuritySerializer",
        "//Source/common:Platform",
        "//Source/common:SNTCachedDecision",
    ],
)

objc_library(
    name = "EndpointSecuritySanitizableString",
    srcs = ["Logs/EndpointSecurity/Serializers/SanitizableString.mm"],
    hdrs = ["Logs/EndpointSecurity/Serializers/SanitizableString.h"],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
    deps = [
        "//Source/common:String",
        "//Source/common/es:EndpointSecurityMessage",
    ],
)

objc_library(
    name = "EndpointSecuritySerializerBasicString",
    srcs = ["Logs/EndpointSecurity/Serializers/BasicString.mm"],
    hdrs = ["Logs/EndpointSecurity/Serializers/BasicString.h"],
    sdk_frameworks = [
        "DiskArbitration",
    ],
    deps = [
        ":EndpointSecuritySanitizableString",
        ":EndpointSecuritySerializer",
        ":EndpointSecuritySerializerUtilities",
        ":SNTDecisionCache",
        "//Source/common:AuditUtilities",
        "//Source/common:Platform",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTLogging",
        "//Source/common:SNTStoredExecutionEvent",
        "//Source/common:String",
        "//Source/common/es:EndpointSecurityAPI",
        "@santanetd//src/santanetd:SNDNetworkFlowsSerializer",
    ],
)

objc_library(
    name = "EndpointSecuritySerializerProtobuf",
    srcs = ["Logs/EndpointSecurity/Serializers/Protobuf.mm"],
    hdrs = ["Logs/EndpointSecurity/Serializers/Protobuf.h"],
    sdk_frameworks = [
        "DiskArbitration",
    ],
    deps = [
        ":EndpointSecuritySerializer",
        ":EndpointSecuritySerializerUtilities",
        ":SNTDecisionCache",
        "//Source/common:AuditUtilities",
        "//Source/common:EncodeEntitlements",
        "//Source/common:Platform",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTLogging",
        "//Source/common:SNTStoredExecutionEvent",
        "//Source/common:SNTSystemInfo",
        "//Source/common:String",
        "//Source/common:santa_cc_proto",
        "//Source/common/es:EndpointSecurityAPI",
        "@abseil-cpp//absl/status",
        "@protobuf//src/google/protobuf/json",
        "@santanetd//src/santanetd:SNDNetworkFlowsSerializer",
    ],
)

objc_library(
    name = "EndpointSecurityWriter",
    hdrs = ["Logs/EndpointSecurity/Writers/Writer.h"],
    deps = [
        "@abseil-cpp//absl/container:flat_hash_map",
        "@abseil-cpp//absl/container:flat_hash_set",
    ],
)

objc_library(
    name = "EndpointSecurityWriterSyslog",
    srcs = ["Logs/EndpointSecurity/Writers/Syslog.mm"],
    hdrs = ["Logs/EndpointSecurity/Writers/Syslog.h"],
    deps = [
        ":EndpointSecurityWriter",
    ],
)

objc_library(
    name = "EndpointSecurityWriterFile",
    srcs = ["Logs/EndpointSecurity/Writers/File.mm"],
    hdrs = ["Logs/EndpointSecurity/Writers/File.h"],
    deps = [
        ":EndpointSecurityWriter",
        "//Source/common:BranchPrediction",
    ],
)

objc_library(
    name = "EndpointSecurityWriterSpool",
    hdrs = ["Logs/EndpointSecurity/Writers/Spool.h"],
    deps = [
        ":EndpointSecurityWriter",
        "//Source/common:SNTLogging",
        "//Source/common:santa_cc_proto",
        "//Source/santad/Logs/EndpointSecurity/Writers/FSSpool:fsspool",
        "@abseil-cpp//absl/container:flat_hash_map",
        "@abseil-cpp//absl/container:flat_hash_set",
        "@abseil-cpp//absl/strings",
    ],
)

objc_library(
    name = "EndpointSecurityWriterNull",
    srcs = ["Logs/EndpointSecurity/Writers/Null.mm"],
    hdrs = ["Logs/EndpointSecurity/Writers/Null.h"],
    deps = [
        ":EndpointSecurityWriter",
    ],
)

objc_library(
    name = "SleighLauncher",
    srcs = ["SleighLauncher.mm"],
    hdrs = ["SleighLauncher.h"],
    deps = [
        "//Source/common:MOLCodesignChecker",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTDropRootPrivs",
        "//Source/common:SNTExportConfiguration",
        "//Source/common:SNTLogging",
        "//Source/common:SNTSystemInfo",
        "//Source/common:String",
        "@abseil-cpp//absl/cleanup:cleanup",
        "@abseil-cpp//absl/status:statusor",
        "@northpolesec_protos//telemetry:sleighconfig_cc_proto",
    ],
)

objc_library(
    name = "EndpointSecurityLogger",
    srcs = ["Logs/EndpointSecurity/Logger.mm"],
    hdrs = ["Logs/EndpointSecurity/Logger.h"],
    deps = [
        ":EndpointSecuritySerializer",
        ":EndpointSecuritySerializerBasicString",
        ":EndpointSecuritySerializerEmpty",
        ":EndpointSecuritySerializerProtobuf",
        ":EndpointSecurityWriter",
        ":EndpointSecurityWriterFile",
        ":EndpointSecurityWriterNull",
        ":EndpointSecurityWriterSpool",
        ":EndpointSecurityWriterSyslog",
        ":SNTDecisionCache",
        ":SleighLauncher",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTExportConfiguration",
        "//Source/common:SNTLogging",
        "//Source/common:SNTStoredExecutionEvent",
        "//Source/common:SNTSystemInfo",
        "//Source/common:TelemetryEventMap",
        "//Source/common:Timer",
        "//Source/common/es:EndpointSecurityAPI",
        "//Source/common/es:EndpointSecurityEnrichedTypes",
        "//Source/common/es:EndpointSecurityMessage",
        "//Source/santad/Logs/EndpointSecurity/Writers/FSSpool:SpoolBatchers",
        "@abseil-cpp//absl/container:flat_hash_map",
        "@abseil-cpp//absl/container:flat_hash_set",
    ],
)

objc_library(
    name = "KillingMachine",
    srcs = ["KillingMachine.mm"],
    hdrs = ["KillingMachine.h"],
    deps = [
        "//Source/common:AuditUtilities",
        "//Source/common:CSOpsHelper",
        "//Source/common:CodeSigningIdentifierUtils",
        "//Source/common:SNTKillCommand",
        "//Source/common:SNTLogging",
        "//Source/common:SNTSystemInfo",
        "//Source/common:String",
        "//Source/common:SystemResources",
        "@abseil-cpp//absl/cleanup:cleanup",
    ],
)

santa_unit_test(
    name = "KillingMachineTest",
    srcs = [
        "KillingMachineTest.mm",
    ],
    deps = [
        ":KillingMachine",
        "//Source/common:CSOpsHelper",
        "//Source/common:CodeSigningIdentifierUtils",
        "//Source/common:SNTKillCommand",
        "//Source/common:SNTLogging",
        "//Source/common:SNTSystemInfo",
        "//Source/common:String",
        "//Source/common:SystemResources",
        "@abseil-cpp//absl/cleanup:cleanup",
    ],
)

objc_library(
    name = "SNTDaemonControlController",
    srcs = ["SNTDaemonControlController.mm"],
    hdrs = ["SNTDaemonControlController.h"],
    deps = [
        ":AuthResultCache",
        ":EndpointSecurityLogger",
        ":KillingMachine",
        ":SNTDatabaseController",
        ":SNTEventTable",
        ":SNTNetworkExtensionQueue",
        ":SNTNotificationQueue",
        ":SNTRuleTable",
        ":SNTSyncdQueue",
        ":TemporaryMonitorMode",
        "//Source/common:MOLCodesignChecker",
        "//Source/common:MOLXPCConnection",
        "//Source/common:Pinning",
        "//Source/common:SNTCELFallbackRule",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTError",
        "//Source/common:SNTFileAccessRule",
        "//Source/common:SNTLogging",
        "//Source/common:SNTMetricSet",
        "//Source/common:SNTModeTransition",
        "//Source/common:SNTRule",
        "//Source/common:SNTRuleIdentifiers",
        "//Source/common:SNTStoredExecutionEvent",
        "//Source/common:SNTStrengthify",
        "//Source/common:SNTTimer",
        "//Source/common:SNTXPCControlInterface",
        "//Source/common:SNTXPCNotifierInterface",
        "//Source/common:SNTXPCSyncServiceInterface",
        "//Source/common/faa:WatchItems",
        "@FMDB",
        "@santanetd//src/santanetd:SNDProcessFlows",
    ],
)

objc_library(
    name = "Metrics",
    srcs = ["Metrics.mm"],
    hdrs = ["Metrics.h"],
    deps = [
        ":SNTApplicationCoreMetrics",
        "//Source/common:MOLXPCConnection",
        "//Source/common:Platform",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTLogging",
        "//Source/common:SNTMetricSet",
        "//Source/common:SNTXPCMetricServiceInterface",
        "//Source/common/es:ESMetricsObserver",
        "@abseil-cpp//absl/container:flat_hash_map",
    ],
)

objc_library(
    name = "Santad",
    srcs = ["Santad.mm"],
    hdrs = ["Santad.h"],
    deps = [
        ":AuthResultCache",
        ":DaemonConfigBundle",
        ":EndpointSecurityLogger",
        ":FAAPolicyProcessor",
        ":Metrics",
        ":SNTCompilerController",
        ":SNTDaemonControlController",
        ":SNTDatabaseController",
        ":SNTDecisionCache",
        ":SNTEndpointSecurityAuthorizer",
        ":SNTEndpointSecurityDataFileAccessAuthorizer",
        ":SNTEndpointSecurityDeviceManager",
        ":SNTEndpointSecurityProcessFileAccessAuthorizer",
        ":SNTEndpointSecurityRecorder",
        ":SNTEndpointSecurityTamperResistance",
        ":SNTEventTable",
        ":SNTExecutionController",
        ":SNTNetworkExtensionQueue",
        ":SNTNotificationQueue",
        ":SNTRuleTable",
        ":SNTSyncdQueue",
        ":TTYWriter",
        "//Source/common:MOLXPCConnection",
        "//Source/common:PowerMonitor",
        "//Source/common:PrefixTree",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTKVOManager",
        "//Source/common:SNTLogging",
        "//Source/common:SNTStoredFileAccessEvent",
        "//Source/common:SNTStoredNetworkMountEvent",
        "//Source/common:SNTStoredUSBMountEvent",
        "//Source/common:SNTXPCNotifierInterface",
        "//Source/common:SNTXPCSyncServiceInterface",
        "//Source/common:TelemetryEventMap",
        "//Source/common:Unit",
        "//Source/common/es:EndpointSecurityAPI",
        "//Source/common/es:EndpointSecurityEnricher",
        "//Source/common/faa:WatchItemPolicy",
        "//Source/common/faa:WatchItems",
        "//Source/common/processtree:process_tree",
    ],
)

objc_library(
    name = "SantadDeps",
    srcs = ["SantadDeps.mm"],
    hdrs = ["SantadDeps.h"],
    deps = [
        ":AuthResultCache",
        ":EndpointSecurityLogger",
        ":EntitlementsFilter",
        ":Metrics",
        ":ProcessControl",
        ":SNTCompilerController",
        ":SNTDatabaseController",
        ":SNTDecisionCache",
        ":SNTEventTable",
        ":SNTExecutionController",
        ":SNTNetworkExtensionQueue",
        ":SNTNotificationQueue",
        ":SNTRuleTable",
        ":SNTSyncdQueue",
        ":SleighLauncher",
        ":TTYWriter",
        "//Source/common:MOLXPCConnection",
        "//Source/common:PrefixTree",
        "//Source/common:RingBuffer",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTExportConfiguration",
        "//Source/common:SNTLogging",
        "//Source/common:SNTMetricSet",
        "//Source/common:SNTStrengthify",
        "//Source/common:SNTXPCControlInterface",
        "//Source/common:SNTXPCUnprivilegedControlInterface",
        "//Source/common:TelemetryEventMap",
        "//Source/common:Unit",
        "//Source/common/es:EndpointSecurityAPI",
        "//Source/common/es:EndpointSecurityEnricher",
        "//Source/common/faa:WatchItems",
        "//Source/common/processtree:process_tree",
        "//Source/common/processtree/annotations:originator",
    ],
)

objc_library(
    name = "santad_main",
    srcs = ["main.mm"],
    sdk_dylibs = [
        "bsm",
        "EndpointSecurity",
    ],
    sdk_frameworks = [
        "DiskArbitration",
    ],
    deps = [
        ":SNTDaemonControlController",
        ":Santad",
        ":SantadDeps",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTLogging",
        "//Source/common:SNTMetricSet",
        "//Source/common:SNTSystemInfo",
        "//Source/common:SNTXPCControlInterface",
        "//Source/common:SystemResources",
        "//Source/santad:ProcessControl",
    ],
)

macos_bundle(
    name = "com.northpolesec.santa.daemon",
    bundle_extension = "systemextension",
    bundle_id = "com.northpolesec.santa.daemon",
    codesignopts = [
        "--timestamp=none",
        "--force",
        "--options library,kill,runtime",
    ],
    entitlements = select({
        "//:adhoc_build": "com.northpolesec.santa.daemon.systemextension-adhoc.entitlements",
        "//:debugger_build": "com.northpolesec.santa.daemon.systemextension-debugger.entitlements",
        # By default builds get their entitlements from the provisioning profile.
        "//conditions:default": None,
    }),
    infoplists = [
        "Info.plist",
        "//Source/common:CommitHash",
    ],
    linkopts = ["-execute"],
    minimum_os_version = SANTA_MINIMUM_OS_VERSION,
    provisioning_profile = select({
        "//:adhoc_build": None,
        "//conditions:default": "@profiles//:daemon_dev",
    }),
    resources = [
        "//:Conf/com.northpolesec.santa.bundleservice.plist",
        "//:Conf/com.northpolesec.santa.metricservice.plist",
        "//:Conf/com.northpolesec.santa.plist",
        "//:Conf/com.northpolesec.santa.syncservice.plist",
        "//:Conf/install_services.sh",
    ],
    version = "//:version",
    visibility = ["//:santa_package_group"],
    deps = [":santad_main"],
)

#
# Begin test targets
#

objc_library(
    name = "MockFAAPolicyProcessor",
    testonly = 1,
    hdrs = ["EventProviders/MockFAAPolicyProcessor.h"],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
    deps = [
        ":EndpointSecurityLogger",
        ":Metrics",
        ":SNTDecisionCache",
        ":TTYWriter",
        "//Source/common:SNTCachedDecision",
        "//Source/common/es:EndpointSecurityEnricher",
        "//Source/common/faa:WatchItemPolicy",
        "@googletest//:gtest",
    ],
)

objc_library(
    name = "MockLogger",
    testonly = 1,
    hdrs = ["Logs/EndpointSecurity/MockLogger.h"],
    deps = [
        ":EndpointSecurityLogger",
        "//Source/common:TelemetryEventMap",
        "//Source/common/es:EndpointSecurityEnrichedTypes",
        "//Source/common/es:EndpointSecurityMessage",
        "@googletest//:gtest",
    ],
)

santa_unit_test(
    name = "SNTEventTableTest",
    srcs = [
        "DataLayer/SNTDatabaseTable.h",
        "DataLayer/SNTDatabaseTable.mm",
        "DataLayer/SNTEventTable.h",
        "DataLayer/SNTEventTable.mm",
        "DataLayer/SNTEventTableTest.mm",
    ],
    structured_resources = [
        "//Source/santad/testdata:archive_testdata",
    ],
    deps = [
        "//Source/common:MOLCertificate",
        "//Source/common:MOLCodesignChecker",
        "//Source/common:SNTFileInfo",
        "//Source/common:SNTLogging",
        "//Source/common:SNTStoredExecutionEvent",
        "//Source/common:SNTStoredFileAccessEvent",
        "//Source/common:SNTStoredTemporaryMonitorModeAuditEvent",
        "//Source/common:SantaCache",
        "//Source/common:String",
        "//Source/common:TestUtils",
        "@FMDB",
        "@OCMock",
    ],
)

santa_unit_test(
    name = "SNTRuleTableTest",
    srcs = [
        "DataLayer/SNTRuleTableTest.mm",
    ],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
    deps = [
        ":SNTRuleTable",
        "//Source/common:CertificateHelpers",
        "//Source/common:MOLCertificate",
        "//Source/common:MOLCodesignChecker",
        "//Source/common:Platform",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTFileAccessRule",
        "//Source/common:SNTFileInfo",
        "//Source/common:SNTLogging",
        "//Source/common:SNTRule",
        "//Source/common:SNTRuleIdentifiers",
        "//Source/common:SigningIDHelpers",
        "//Source/common:String",
        "//Source/common:TestUtils",
        "//Source/common/cel:CEL",
        "@FMDB",
        "@OCMock",
    ],
)

santa_unit_test(
    name = "SantadTest",
    srcs = ["SantadTest.mm"],
    sdk_dylibs = [
        "bsm",
        "EndpointSecurity",
    ],
    structured_resources = [
        "//Source/santad/testdata:binaryrules_testdata",
    ],
    tags = ["exclusive"],
    deps = [
        ":Metrics",
        ":ProcessControl",
        ":SNTDatabaseController",
        ":SNTDecisionCache",
        ":SNTEndpointSecurityAuthorizer",
        ":SantadDeps",
        "//Source/common:MOLCertificate",
        "//Source/common:MOLCodesignChecker",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTConfigurator",
        "//Source/common:TestUtils",
        "//Source/common/es:EndpointSecurityMessage",
        "//Source/common/es:MockEndpointSecurityAPI",
        "//Source/common/es:SNTEndpointSecurityClient",
        "@OCMock",
        "@googletest//:gtest",
    ],
)

santa_unit_test(
    name = "SNTApplicationCoreMetricsTest",
    srcs = [
        "SNTApplicationCoreMetricsTest.mm",
    ],
    deps = [
        ":SNTApplicationCoreMetrics",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTMetricSet",
        "//Source/common:SNTSystemInfo",
        "//Source/santametricservice/Formats:SNTMetricFormatTestHelper",
        "@OCMock",
    ],
)

santa_unit_test(
    name = "EndpointSecuritySanitizableStringTest",
    srcs = ["Logs/EndpointSecurity/Serializers/SanitizableStringTest.mm"],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
    deps = [
        ":EndpointSecuritySanitizableString",
        "//Source/common:TestUtils",
        "@OCMock",
    ],
)

santa_unit_test(
    name = "EndpointSecuritySerializerUtilitiesTest",
    srcs = ["Logs/EndpointSecurity/Serializers/UtilitiesTest.mm"],
    deps = [
        ":EndpointSecuritySerializerUtilities",
        "//Source/common:TestUtils",
        "//Source/common/es:EndpointSecurityMessage",
        "//Source/common/es:MockEndpointSecurityAPI",
        "@OCMock",
        "@googletest//:gtest",
    ],
)

santa_unit_test(
    name = "EndpointSecuritySerializerBasicStringTest",
    srcs = ["Logs/EndpointSecurity/Serializers/BasicStringTest.mm"],
    sdk_dylibs = [
        "bsm",
        "EndpointSecurity",
    ],
    deps = [
        ":EndpointSecuritySerializer",
        ":EndpointSecuritySerializerBasicString",
        ":SNTDecisionCache",
        "//Source/common:Platform",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTStoredExecutionEvent",
        "//Source/common:TestUtils",
        "//Source/common/es:EndpointSecurityEnrichedTypes",
        "//Source/common/es:EndpointSecurityEnricher",
        "//Source/common/es:EndpointSecurityMessage",
        "//Source/common/es:MockEndpointSecurityAPI",
        "@OCMock",
        "@googletest//:gtest",
    ],
)

santa_unit_test(
    name = "EndpointSecuritySerializerProtobufTest",
    srcs = ["Logs/EndpointSecurity/Serializers/ProtobufTest.mm"],
    structured_resources = [
        "//Source/santad/testdata:protobuf_json_testdata",
    ],
    deps = [
        ":EndpointSecuritySerializer",
        ":EndpointSecuritySerializerProtobuf",
        ":SNTDecisionCache",
        "//Source/common:Platform",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTStoredExecutionEvent",
        "//Source/common:TestUtils",
        "//Source/common:santa_cc_proto",
        "//Source/common/es:EndpointSecurityEnrichedTypes",
        "//Source/common/es:EndpointSecurityEnricher",
        "//Source/common/es:EndpointSecurityMessage",
        "//Source/common/es:MockEndpointSecurityAPI",
        "@OCMock",
        "@abseil-cpp//absl/status",
        "@googletest//:gtest",
        "@protobuf//src/google/protobuf/json",
    ],
)

santa_unit_test(
    name = "AuthResultCacheTest",
    srcs = ["EventProviders/AuthResultCacheTest.mm"],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
    deps = [
        ":AuthResultCache",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SantaVnode",
        "//Source/common:TestUtils",
        "//Source/common/es:MockEndpointSecurityAPI",
        "//Source/common/es:SNTEndpointSecurityClientBase",
        "@OCMock",
        "@googletest//:gtest",
    ],
)

santa_unit_test(
    name = "RateLimiterTest",
    srcs = ["EventProviders/RateLimiterTest.mm"],
    deps = [
        ":Metrics",
        ":RateLimiter",
        "//Source/common:SystemResources",
    ],
)

santa_unit_test(
    name = "EndpointSecuritySerializerEmptyTest",
    srcs = ["Logs/EndpointSecurity/Serializers/EmptyTest.mm"],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
    deps = [
        ":EndpointSecuritySerializerEmpty",
        "//Source/common/es:EndpointSecurityEnrichedTypes",
        "@OCMock",
    ],
)

santa_unit_test(
    name = "EndpointSecurityWriterFileTest",
    srcs = ["Logs/EndpointSecurity/Writers/FileTest.mm"],
    deps = [
        ":EndpointSecurityWriterFile",
        "//Source/common:TestUtils",
        "@OCMock",
        "@googletest//:gtest",
    ],
)

santa_unit_test(
    name = "EndpointSecurityWriterSpoolTest",
    srcs = ["Logs/EndpointSecurity/Writers/SpoolTest.mm"],
    deps = [
        ":EndpointSecurityWriterSpool",
        "//Source/common:TestUtils",
        "//Source/santad/Logs/EndpointSecurity/Writers/FSSpool:SpoolBatchers",
        "//Source/santad/Logs/EndpointSecurity/Writers/FSSpool:fsspool",
    ],
)

santa_unit_test(
    name = "EndpointSecurityLoggerTest",
    srcs = ["Logs/EndpointSecurity/LoggerTest.mm"],
    sdk_dylibs = [
        "bsm",
        "EndpointSecurity",
    ],
    deps = [
        ":EndpointSecurityLogger",
        ":EndpointSecuritySerializer",
        ":EndpointSecuritySerializerBasicString",
        ":EndpointSecuritySerializerEmpty",
        ":EndpointSecuritySerializerProtobuf",
        ":EndpointSecurityWriter",
        ":EndpointSecurityWriterFile",
        ":EndpointSecurityWriterNull",
        ":EndpointSecurityWriterSpool",
        ":EndpointSecurityWriterSyslog",
        ":SleighLauncher",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTExportConfiguration",
        "//Source/common:TelemetryEventMap",
        "//Source/common:TestUtils",
        "//Source/common/es:EndpointSecurityMessage",
        "//Source/common/es:MockEndpointSecurityAPI",
        "//Source/santad/Logs/EndpointSecurity/Writers/FSSpool:SpoolBatchers",
        "@googletest//:gtest",
    ],
)

santa_unit_test(
    name = "MetricsTest",
    srcs = ["MetricsTest.mm"],
    deps = [
        ":Metrics",
        "//Source/common:Platform",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTMetricSet",
        "//Source/common:TestUtils",
        "@OCMock",
    ],
)

santa_unit_test(
    name = "SNTDecisionCacheTest",
    srcs = ["SNTDecisionCacheTest.mm"],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
    deps = [
        ":SNTDatabaseController",
        ":SNTDecisionCache",
        ":SNTRuleTable",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTRule",
        "//Source/common:SantaVnode",
        "//Source/common:TestUtils",
        "@OCMock",
    ],
)

santa_unit_test(
    name = "SNTExecutionControllerTest",
    srcs = ["SNTExecutionControllerTest.mm"],
    sdk_dylibs = [
        "EndpointSecurity",
        "bsm",
    ],
    deps = [
        ":EntitlementsFilter",
        ":ProcessControl",
        ":SNTDatabaseController",
        ":SNTDecisionCache",
        ":SNTEventTable",
        ":SNTExecutionController",
        ":SNTPolicyProcessor",
        ":SNTRuleTable",
        "//Source/common:MOLCertificate",
        "//Source/common:MOLCodesignChecker",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTFileInfo",
        "//Source/common:SNTMetricSet",
        "//Source/common:SNTRule",
        "//Source/common:SNTRuleIdentifiers",
        "//Source/common:TestUtils",
        "//Source/common/es:EndpointSecurityMessage",
        "//Source/common/es:MockEndpointSecurityAPI",
        "@OCMock",
    ],
)

santa_unit_test(
    name = "SNTEndpointSecurityAuthorizerTest",
    srcs = ["EventProviders/SNTEndpointSecurityAuthorizerTest.mm"],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
    deps = [
        ":AuthResultCache",
        ":Metrics",
        ":SNTCompilerController",
        ":SNTEndpointSecurityAuthorizer",
        ":SNTExecutionController",
        ":TTYWriter",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommonEnums",
        "//Source/common:TestUtils",
        "//Source/common/es:EndpointSecurityClient",
        "//Source/common/es:EndpointSecurityMessage",
        "//Source/common/es:MockEndpointSecurityAPI",
        "@OCMock",
        "@googletest//:gtest",
    ],
)

santa_unit_test(
    name = "SNTEndpointSecurityDataFileAccessAuthorizerTest",
    srcs = ["EventProviders/SNTEndpointSecurityDataFileAccessAuthorizerTest.mm"],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
    deps = [
        ":SNTEndpointSecurityDataFileAccessAuthorizer",
        "//Source/common:SNTConfigurator",
        "//Source/common:TestUtils",
        "//Source/common/es:MockEndpointSecurityAPI",
        "@OCMock",
        "@googletest//:gtest",
    ],
)

santa_unit_test(
    name = "SNTEndpointSecurityProcessFileAccessAuthorizerTest",
    srcs = ["EventProviders/SNTEndpointSecurityProcessFileAccessAuthorizerTest.mm"],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
    deps = [
        ":MockFAAPolicyProcessor",
        ":SNTEndpointSecurityProcessFileAccessAuthorizer",
        "//Source/common:TestUtils",
        "//Source/common/es:EndpointSecurityMessage",
        "//Source/common/es:MockEndpointSecurityAPI",
        "//Source/common/faa:WatchItemPolicy",
        "@OCMock",
    ],
)

santa_unit_test(
    name = "FAAPolicyProcessorTest",
    srcs = ["EventProviders/FAAPolicyProcessorTest.mm"],
    deps = [
        ":FAAPolicyProcessor",
        ":MockFAAPolicyProcessor",
        ":SNTDecisionCache",
        "//Source/common:MOLCertificate",
        "//Source/common:MOLCodesignChecker",
        "//Source/common:SNTCachedDecision",
        "//Source/common:TestUtils",
        "//Source/common/es:EndpointSecurityMessage",
        "//Source/common/es:MockEndpointSecurityAPI",
        "//Source/common/faa:WatchItemPolicy",
        "@OCMock",
        "@googletest//:gtest",
    ],
)

santa_unit_test(
    name = "SNTEndpointSecurityTamperResistanceTest",
    srcs = ["EventProviders/SNTEndpointSecurityTamperResistanceTest.mm"],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
    deps = [
        ":Metrics",
        ":SNTEndpointSecurityTamperResistance",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTLogging",
        "//Source/common:TestUtils",
        "//Source/common/es:EndpointSecurityClient",
        "//Source/common/es:EndpointSecurityMessage",
        "//Source/common/es:MockEndpointSecurityAPI",
        "//Source/common/faa:WatchItemPolicy",
        "@OCMock",
        "@googletest//:gtest",
    ],
)

santa_unit_test(
    name = "SNTEndpointSecurityRecorderTest",
    srcs = ["EventProviders/SNTEndpointSecurityRecorderTest.mm"],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
    deps = [
        ":AuthResultCache",
        ":EndpointSecurityLogger",
        ":Metrics",
        ":MockLogger",
        ":SNTCompilerController",
        ":SNTEndpointSecurityRecorder",
        "//Source/common:Platform",
        "//Source/common:PrefixTree",
        "//Source/common:SNTConfigurator",
        "//Source/common:TelemetryEventMap",
        "//Source/common:TestUtils",
        "//Source/common:Unit",
        "//Source/common/es:EndpointSecurityClient",
        "//Source/common/es:EndpointSecurityEnrichedTypes",
        "//Source/common/es:EndpointSecurityEnricher",
        "//Source/common/es:EndpointSecurityMessage",
        "//Source/common/es:MockEndpointSecurityAPI",
        "//Source/common/es:MockEnricher",
        "@OCMock",
        "@googletest//:gtest",
    ],
)

santa_unit_test(
    name = "SNTEndpointSecurityDeviceManagerTest",
    srcs = ["EventProviders/SNTEndpointSecurityDeviceManagerTest.mm"],
    sdk_dylibs = [
        "bsm",
        "EndpointSecurity",
    ],
    deps = [
        ":AuthResultCache",
        ":DiskArbitrationTestLib",
        ":Metrics",
        ":SNTEndpointSecurityDeviceManager",
        "//Source/common:Platform",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTDeviceEvent",
        "//Source/common:TestUtils",
        "//Source/common/es:EndpointSecurityClient",
        "//Source/common/es:EndpointSecurityMessage",
        "//Source/common/es:MockEndpointSecurityAPI",
        "//Source/common/es:MockEnricher",
        "//Source/common/es:SNTEndpointSecurityClient",
        "@OCMock",
        "@googletest//:gtest",
    ],
)

santa_unit_test(
    name = "SNTCompilerControllerTest",
    srcs = ["SNTCompilerControllerTest.mm"],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
    deps = [
        ":EndpointSecurityLogger",
        ":SNTCompilerController",
        ":SNTDecisionCache",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTFileInfo",
        "//Source/common:TestUtils",
        "//Source/common/es:EndpointSecurityMessage",
        "//Source/common/es:MockEndpointSecurityAPI",
        "@OCMock",
        "@googletest//:gtest",
    ],
)

test_suite(
    name = "unit_tests",
    tests = [
        ":AuthResultCacheTest",
        ":DaemonConfigBundleTest",
        ":EndpointSecurityLoggerTest",
        ":EndpointSecuritySanitizableStringTest",
        ":EndpointSecuritySerializerBasicStringTest",
        ":EndpointSecuritySerializerEmptyTest",
        ":EndpointSecuritySerializerProtobufTest",
        ":EndpointSecuritySerializerUtilitiesTest",
        ":EndpointSecurityWriterFileTest",
        ":EndpointSecurityWriterSpoolTest",
        ":EntitlementsFilterTest",
        ":FAAPolicyProcessorTest",
        ":KillingMachineTest",
        ":MetricsTest",
        ":RateLimiterTest",
        ":SNTApplicationCoreMetricsTest",
        ":SNTCompilerControllerTest",
        ":SNTDecisionCacheTest",
        ":SNTEndpointSecurityAuthorizerTest",
        ":SNTEndpointSecurityDataFileAccessAuthorizerTest",
        ":SNTEndpointSecurityDeviceManagerTest",
        ":SNTEndpointSecurityProcessFileAccessAuthorizerTest",
        ":SNTEndpointSecurityRecorderTest",
        ":SNTEndpointSecurityTamperResistanceTest",
        ":SNTEndpointSecurityTreeAwareClientTest",
        ":SNTEventTableTest",
        ":SNTExecutionControllerTest",
        ":SNTNotificationQueueTest",
        ":SNTPolicyProcessorTest",
        ":SNTRuleTableTest",
        ":SNTSyncdQueueTest",
        ":SantadTest",
        ":TemporaryMonitorModeTest",
        "//Source/common/es:EndpointSecurityClientTest",
        "//Source/common/es:EndpointSecurityEnricherTest",
        "//Source/common/es:EndpointSecurityMessageTest",
        "//Source/common/es:SNTEndpointSecurityClientTest",
        "//Source/common/processtree:process_tree_test",
        "//Source/common/processtree/annotations:originator_test",
        "//Source/santad/Logs/EndpointSecurity/Writers/FSSpool:StreamBatchersTest",
        "//Source/santad/Logs/EndpointSecurity/Writers/FSSpool:fsspool_test",
    ],
    visibility = ["//:santa_package_group"],
)
