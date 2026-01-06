load("@rules_apple//apple:macos.bzl", "macos_bundle")
load("@rules_cc//cc:defs.bzl", "objc_library")
load("//:helper.bzl", "SANTA_MINIMUM_OS_VERSION", "santa_unit_test")

package(
    default_visibility = [":__subpackages__"],
)

licenses(["notice"])

objc_library(
    name = "SNTDatabaseTable",
    srcs = ["data_layer/SNTDatabaseTable.mm"],
    hdrs = ["data_layer/SNTDatabaseTable.h"],
    deps = [
        "//src/common:SNTLogging",
        "@FMDB",
    ],
)

objc_library(
    name = "SNTRuleTable",
    srcs = ["data_layer/SNTRuleTable.mm"],
    hdrs = ["data_layer/SNTRuleTable.h"],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
    deps = [
        ":SNTDatabaseTable",
        "//src/common:CertificateHelpers",
        "//src/common:MOLCertificate",
        "//src/common:MOLCodesignChecker",
        "//src/common:Platform",
        "//src/common:SNTCachedDecision",
        "//src/common:SNTCommonEnums",
        "//src/common:SNTConfigurator",
        "//src/common:SNTError",
        "//src/common:SNTFileAccessRule",
        "//src/common:SNTFileInfo",
        "//src/common:SNTLogging",
        "//src/common:SNTRule",
        "//src/common:SNTRuleIdentifiers",
        "//src/common:SNTXxhash",
        "//src/common:SigningIDHelpers",
        "//src/common:String",
        "//src/common/cel:CEL",
    ],
)

objc_library(
    name = "SNTEventTable",
    srcs = ["data_layer/SNTEventTable.mm"],
    hdrs = ["data_layer/SNTEventTable.h"],
    deps = [
        ":SNTDatabaseTable",
        "//src/common:MOLCertificate",
        "//src/common:SNTLogging",
        "//src/common:SNTStoredExecutionEvent",
        "//src/common:SNTStoredFileAccessEvent",
        "//src/common:SNTStoredTemporaryMonitorModeAuditEvent",
        "//src/common:SantaCache",
        "//src/common:String",
    ],
)

objc_library(
    name = "SNTDatabaseController",
    srcs = ["SNTDatabaseController.mm"],
    hdrs = ["SNTDatabaseController.h"],
    deps = [
        ":SNTEventTable",
        ":SNTRuleTable",
        "//src/common:SNTLogging",
        "@FMDB",
    ],
)

objc_library(
    name = "SNTEndpointSecurityEventHandler",
    hdrs = ["event_providers/SNTEndpointSecurityEventHandler.h"],
    deps = [
        ":EndpointSecurityMessage",
        ":Metrics",
        "//src/common:SNTStoredFileAccessEvent",
        "//src/common/faa:WatchItemPolicy",
    ],
)

objc_library(
    name = "SNTApplicationCoreMetrics",
    srcs = ["SNTApplicationCoreMetrics.mm"],
    hdrs = ["SNTApplicationCoreMetrics.h"],
    deps = [
        "//src/common:SNTCommonEnums",
        "//src/common:SNTConfigurator",
        "//src/common:SNTMetricSet",
        "//src/common:SNTSystemInfo",
        "//src/common:SystemResources",
    ],
)

objc_library(
    name = "DiskArbitrationTestLib",
    testonly = 1,
    srcs = ["event_providers/DiskArbitrationTestUtil.mm"],
    hdrs = ["event_providers/DiskArbitrationTestUtil.h"],
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
        "//src/common:AuditUtilities",
        "//src/common:CodeSigningIdentifierUtils",
        "//src/common:MOLCertificate",
        "//src/common:MOLCodesignChecker",
        "//src/common:SNTCachedDecision",
        "//src/common:SNTCommonEnums",
        "//src/common:SNTLogging",
        "//src/common:SNTRule",
        "//src/common:SantaCache",
        "//src/common:SantaVnode",
        "//src/common:SystemResources",
    ],
)

objc_library(
    name = "SNTCompilerController",
    srcs = ["SNTCompilerController.mm"],
    hdrs = ["SNTCompilerController.h"],
    deps = [
        ":EndpointSecurityLogger",
        ":EndpointSecurityMessage",
        ":SNTDatabaseController",
        ":SNTDecisionCache",
        ":SNTRuleTable",
        "//src/common:SNTCachedDecision",
        "//src/common:SNTCommonEnums",
        "//src/common:SNTFileInfo",
        "//src/common:SNTLogging",
        "//src/common:SNTRule",
    ],
)

objc_library(
    name = "SNTNotificationQueue",
    srcs = ["SNTNotificationQueue.mm"],
    hdrs = ["SNTNotificationQueue.h"],
    deps = [
        "//src/common:MOLXPCConnection",
        "//src/common:RingBuffer",
        "//src/common:SNTConfigState",
        "//src/common:SNTLogging",
        "//src/common:SNTStoredExecutionEvent",
        "//src/common:SNTStrengthify",
        "//src/common:SNTXPCNotifierInterface",
    ],
)

santa_unit_test(
    name = "SNTNotificationQueueTest",
    srcs = ["SNTNotificationQueueTest.mm"],
    deps = [
        ":SNTNotificationQueue",
        "//src/common:MOLXPCConnection",
        "//src/common:SNTConfigState",
        "//src/common:SNTStoredExecutionEvent",
        "//src/common:SNTXPCNotifierInterface",
        "//src/common:TestUtils",
        "@OCMock",
    ],
)

objc_library(
    name = "SNTSyncdQueue",
    srcs = ["SNTSyncdQueue.mm"],
    hdrs = ["SNTSyncdQueue.h"],
    deps = [
        "//src/common:MOLXPCConnection",
        "//src/common:SNTCommonEnums",
        "//src/common:SNTConfigurator",
        "//src/common:SNTExportConfiguration",
        "//src/common:SNTLogging",
        "//src/common:SNTStoredExecutionEvent",
        "//src/common:SNTStoredFileAccessEvent",
        "//src/common:SNTXPCSyncServiceInterface",
        "//src/common:SantaCache",
        "//src/common:String",
    ],
)

santa_unit_test(
    name = "SNTSyncdQueueTest",
    srcs = ["SNTSyncdQueueTest.mm"],
    deps = [
        ":SNTSyncdQueue",
        "//src/common:SNTStoredExecutionEvent",
        "@OCMock",
    ],
)

objc_library(
    name = "SNTPolicyProcessor",
    srcs = ["SNTPolicyProcessor.mm"],
    hdrs = ["SNTPolicyProcessor.h"],
    deps = [
        ":EntitlementsFilter",
        ":SNTRuleTable",
        "//src/common:CertificateHelpers",
        "//src/common:MOLCertificate",
        "//src/common:MOLCodesignChecker",
        "//src/common:MOLXPCConnection",
        "//src/common:SNTCachedDecision",
        "//src/common:SNTCommonEnums",
        "//src/common:SNTConfigState",
        "//src/common:SNTConfigurator",
        "//src/common:SNTDeepCopy",
        "//src/common:SNTFileInfo",
        "//src/common:SNTLogging",
        "//src/common:SNTRule",
        "//src/common:SNTRuleIdentifiers",
        "//src/common:SigningIDHelpers",
        "//src/common:String",
        "//src/common/cel:CEL",
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
        "//src/common:SNTCachedDecision",
        "//src/common:SNTConfigurator",
        "//src/common:SNTRule",
        "//src/common:TestUtils",
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
        "//src/common:PassKey",
        "//src/common:Pinning",
        "//src/common:SNTConfigurator",
        "//src/common:SNTError",
        "//src/common:SNTKVOManager",
        "//src/common:SNTModeTransition",
        "//src/common:SNTStoredTemporaryMonitorModeAuditEvent",
        "//src/common:SNTSystemInfo",
        "//src/common:SystemResources",
        "//src/common:Timer",
        "@abseil-cpp//absl/synchronization",
    ],
)

santa_unit_test(
    name = "TemporaryMonitorModeTest",
    srcs = ["TemporaryMonitorModeTest.mm"],
    deps = [
        ":SNTNotificationQueue",
        ":TemporaryMonitorMode",
        "//src/common:SNTModeTransition",
        "//src/common:SystemResources",
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
        "//src/common:SNTLogging",
        "//src/common:String",
    ],
)

objc_library(
    name = "ProcessControl",
    srcs = ["ProcessControl.mm"],
    hdrs = ["ProcessControl.h"],
    deps = [
        "//src/common:SNTLogging",
    ],
)

objc_library(
    name = "DaemonConfigBundle",
    srcs = ["DaemonConfigBundle.mm"],
    hdrs = ["DaemonConfigBundle.h"],
    deps = [
        "//src/common:SNTConfigBundle",
        "//src/common:SNTConfigurator",
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
        "//src/common:PrefixTree",
        "//src/common:SNTDeepCopy",
        "//src/common:String",
        "//src/common:Unit",
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
    name = "SNTExecutionController",
    srcs = ["SNTExecutionController.mm"],
    hdrs = ["SNTExecutionController.h"],
    deps = [
        ":EndpointSecurityAPI",
        ":EndpointSecurityMessage",
        ":ProcessControl",
        ":SNTDecisionCache",
        ":SNTEventTable",
        ":SNTNotificationQueue",
        ":SNTPolicyProcessor",
        ":SNTRuleTable",
        ":SNTSyncdQueue",
        ":TTYWriter",
        "//src/common:BranchPrediction",
        "//src/common:MOLCodesignChecker",
        "//src/common:PrefixTree",
        "//src/common:SNTBlockMessage",
        "//src/common:SNTCachedDecision",
        "//src/common:SNTCommonEnums",
        "//src/common:SNTConfigState",
        "//src/common:SNTConfigurator",
        "//src/common:SNTFileInfo",
        "//src/common:SNTLogging",
        "//src/common:SNTMetricSet",
        "//src/common:SNTRule",
        "//src/common:SNTStoredExecutionEvent",
        "//src/common:SantaVnode",
        "//src/common:String",
        "//src/common:Unit",
        "@abseil-cpp//absl/synchronization",
    ],
)

objc_library(
    name = "SNTEndpointSecurityClientBase",
    hdrs = ["event_providers/SNTEndpointSecurityClientBase.h"],
    deps = [
        ":EndpointSecurityAPI",
        ":EndpointSecurityClient",
        ":EndpointSecurityEnrichedTypes",
        ":EndpointSecurityMessage",
        ":Metrics",
        "//src/common/faa:WatchItemPolicy",
    ],
)

objc_library(
    name = "SNTEndpointSecurityClient",
    srcs = ["event_providers/SNTEndpointSecurityClient.mm"],
    hdrs = ["event_providers/SNTEndpointSecurityClient.h"],
    deps = [
        ":EndpointSecurityAPI",
        ":EndpointSecurityClient",
        ":EndpointSecurityEnrichedTypes",
        ":EndpointSecurityMessage",
        ":Metrics",
        ":SNTEndpointSecurityClientBase",
        "//src/common:AuditUtilities",
        "//src/common:BranchPrediction",
        "//src/common:SNTCommonEnums",
        "//src/common:SNTConfigurator",
        "//src/common:SNTLogging",
        "//src/common:SystemResources",
        "//src/common/faa:WatchItemPolicy",
    ],
)

objc_library(
    name = "SNTEndpointSecurityTreeAwareClient",
    srcs = ["event_providers/SNTEndpointSecurityTreeAwareClient.mm"],
    hdrs = ["event_providers/SNTEndpointSecurityTreeAwareClient.h"],
    deps = [
        ":EndpointSecurityAPI",
        ":EndpointSecurityMessage",
        ":Metrics",
        ":SNTEndpointSecurityClient",
        "//src/santad/process_tree:SNTEndpointSecurityAdapter",
        "//src/santad/process_tree:process_tree",
    ],
)

santa_unit_test(
    name = "SNTEndpointSecurityTreeAwareClientTest",
    srcs = ["event_providers/SNTEndpointSecurityTreeAwareClientTest.mm"],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
    deps = [
        ":EndpointSecurityMessage",
        ":Metrics",
        ":MockEndpointSecurityAPI",
        ":SNTEndpointSecurityTreeAwareClient",
        "//src/common:TestUtils",
        "@OCMock",
        "@googletest//:gtest",
    ],
)

objc_library(
    name = "SNTEndpointSecurityRecorder",
    srcs = ["event_providers/SNTEndpointSecurityRecorder.mm"],
    hdrs = ["event_providers/SNTEndpointSecurityRecorder.h"],
    deps = [
        ":AuthResultCache",
        ":EndpointSecurityAPI",
        ":EndpointSecurityEnrichedTypes",
        ":EndpointSecurityEnricher",
        ":EndpointSecurityLogger",
        ":EndpointSecurityMessage",
        ":Metrics",
        ":SNTCompilerController",
        ":SNTEndpointSecurityEventHandler",
        ":SNTEndpointSecurityTreeAwareClient",
        "//src/common:Platform",
        "//src/common:PrefixTree",
        "//src/common:SNTConfigurator",
        "//src/common:SNTLogging",
        "//src/common:String",
        "//src/common:TelemetryEventMap",
        "//src/common:Unit",
        "//src/santad/process_tree:process_tree",
    ],
)

objc_library(
    name = "SNTEndpointSecurityTamperResistance",
    srcs = ["event_providers/SNTEndpointSecurityTamperResistance.mm"],
    hdrs = ["event_providers/SNTEndpointSecurityTamperResistance.h"],
    deps = [
        ":EndpointSecurityAPI",
        ":EndpointSecurityLogger",
        ":EndpointSecurityMessage",
        ":Metrics",
        ":SNTEndpointSecurityClient",
        ":SNTEndpointSecurityEventHandler",
        "//src/common:SNTLogging",
        "//src/common/faa:WatchItemPolicy",
    ],
)

objc_library(
    name = "SNTEndpointSecurityAuthorizer",
    srcs = ["event_providers/SNTEndpointSecurityAuthorizer.mm"],
    hdrs = ["event_providers/SNTEndpointSecurityAuthorizer.h"],
    deps = [
        ":AuthResultCache",
        ":EndpointSecurityAPI",
        ":EndpointSecurityEnrichedTypes",
        ":EndpointSecurityEnricher",
        ":EndpointSecurityMessage",
        ":Metrics",
        ":SNTCompilerController",
        ":SNTEndpointSecurityClient",
        ":SNTEndpointSecurityEventHandler",
        ":SNTExecutionController",
        ":TTYWriter",
        "//src/common:BranchPrediction",
        "//src/common:SNTCommonEnums",
        "//src/common:SNTLogging",
    ],
)

objc_library(
    name = "FAAPolicyProcessor",
    srcs = ["event_providers/FAAPolicyProcessor.mm"],
    hdrs = ["event_providers/FAAPolicyProcessor.h"],
    deps = [
        ":EndpointSecurityEnricher",
        ":EndpointSecurityLogger",
        ":EndpointSecurityMessage",
        ":EntitlementsFilter",
        ":Metrics",
        ":RateLimiter",
        ":SNTDecisionCache",
        ":SNTEndpointSecurityEventHandler",
        ":TTYWriter",
        "//src/common:AuditUtilities",
        "//src/common:MOLCertificate",
        "//src/common:MOLCodesignChecker",
        "//src/common:SNTBlockMessage",
        "//src/common:SNTCachedDecision",
        "//src/common:SNTCommonEnums",
        "//src/common:SNTConfigurator",
        "//src/common:SNTStoredFileAccessEvent",
        "//src/common:SantaCache",
        "//src/common:SantaSetCache",
        "//src/common:SantaVnode",
        "//src/common:String",
        "//src/common/faa:WatchItemPolicy",
    ],
)

objc_library(
    name = "SNTEndpointSecurityDataFileAccessAuthorizer",
    srcs = ["event_providers/SNTEndpointSecurityDataFileAccessAuthorizer.mm"],
    hdrs = ["event_providers/SNTEndpointSecurityDataFileAccessAuthorizer.h"],
    sdk_dylibs = [
        "bsm",
    ],
    deps = [
        ":EndpointSecurityAPI",
        ":EndpointSecurityLogger",
        ":EndpointSecurityMessage",
        ":FAAPolicyProcessor",
        ":Metrics",
        ":SNTEndpointSecurityClient",
        ":SNTEndpointSecurityEventHandler",
        "//src/common:AuditUtilities",
        "//src/common:SNTConfigurator",
        "//src/common:SNTMetricSet",
        "//src/common:SNTStrengthify",
        "//src/common/faa:WatchItemPolicy",
        "//src/common/faa:WatchItems",
    ],
)

objc_library(
    name = "SNTEndpointSecurityProcessFileAccessAuthorizer",
    srcs = ["event_providers/SNTEndpointSecurityProcessFileAccessAuthorizer.mm"],
    hdrs = ["event_providers/SNTEndpointSecurityProcessFileAccessAuthorizer.h"],
    deps = [
        ":EndpointSecurityAPI",
        ":EndpointSecurityMessage",
        ":FAAPolicyProcessor",
        ":Metrics",
        ":SNTEndpointSecurityClient",
        ":SNTEndpointSecurityEventHandler",
        "//src/common:AuditUtilities",
        "//src/common:SNTLogging",
        "//src/common:SantaCache",
        "//src/common:SantaSetCache",
        "//src/common/faa:WatchItemPolicy",
        "//src/common/faa:WatchItems",
    ],
)

objc_library(
    name = "SNTEndpointSecurityDeviceManager",
    srcs = ["event_providers/SNTEndpointSecurityDeviceManager.mm"],
    hdrs = ["event_providers/SNTEndpointSecurityDeviceManager.h"],
    deps = [
        ":AuthResultCache",
        ":EndpointSecurityAPI",
        ":EndpointSecurityEnricher",
        ":EndpointSecurityLogger",
        ":EndpointSecurityMessage",
        ":EndpointSecuritySerializerUtilities",
        ":Metrics",
        ":SNTEndpointSecurityClient",
        ":SNTEndpointSecurityEventHandler",
        "//src/common:AuditUtilities",
        "//src/common:SNTCommonEnums",
        "//src/common:SNTConfigurator",
        "//src/common:SNTDeviceEvent",
        "//src/common:SNTLogging",
        "//src/common:SNTMetricSet",
        "//src/common:SNTProcessChain",
        "//src/common:SNTStoredNetworkMountEvent",
        "//src/common:String",
    ],
)

objc_library(
    name = "AuthResultCache",
    srcs = ["event_providers/AuthResultCache.mm"],
    hdrs = ["event_providers/AuthResultCache.h"],
    deps = [
        ":EndpointSecurityAPI",
        ":EndpointSecurityClient",
        ":SNTEndpointSecurityClientBase",
        "//src/common:SNTCommonEnums",
        "//src/common:SNTLogging",
        "//src/common:SNTMetricSet",
        "//src/common:SantaCache",
        "//src/common:SantaVnode",
    ],
)

objc_library(
    name = "RateLimiter",
    srcs = ["event_providers/RateLimiter.mm"],
    hdrs = ["event_providers/RateLimiter.h"],
    deps = [
        ":Metrics",
        "//src/common:BranchPrediction",
        "//src/common:SNTLogging",
        "//src/common:SystemResources",
    ],
)

objc_library(
    name = "EndpointSecurityEnricher",
    srcs = ["event_providers/endpoint_security/Enricher.mm"],
    hdrs = ["event_providers/endpoint_security/Enricher.h"],
    deps = [
        ":EndpointSecurityEnrichedTypes",
        "//src/common:Platform",
        "//src/common:SNTLogging",
        "//src/common:SantaCache",
        "//src/common:String",
        "//src/santad/process_tree:SNTEndpointSecurityAdapter",
        "//src/santad/process_tree:process_tree",
    ],
)

objc_library(
    name = "EndpointSecurityEnrichedTypes",
    hdrs = ["event_providers/endpoint_security/EnrichedTypes.h"],
    deps = [
        ":EndpointSecurityMessage",
        "//src/common:Platform",
        "//src/common:TelemetryEventMap",
        "//src/santad/process_tree:process_tree_cc_proto",
    ],
)

objc_library(
    name = "EndpointSecuritySerializer",
    srcs = ["logs/endpoint_security/serializers/Serializer.mm"],
    hdrs = ["logs/endpoint_security/serializers/Serializer.h"],
    deps = [
        ":EndpointSecurityEnrichedTypes",
        ":EndpointSecurityMessage",
        ":SNTDecisionCache",
        "//src/common:AuditUtilities",
        "//src/common:Platform",
        "//src/common:SNTCachedDecision",
        "//src/common:SNTCommonEnums",
        "//src/common:SNTConfigurator",
        "//src/common:SNTSystemInfo",
        "//src/common:SNTXxhash",
        "//src/common:String",
    ],
)

objc_library(
    name = "EndpointSecuritySerializerUtilities",
    srcs = ["logs/endpoint_security/serializers/Utilities.mm"],
    hdrs = ["logs/endpoint_security/serializers/Utilities.h"],
    sdk_dylibs = [
        "bsm",
    ],
    deps = [
        ":EndpointSecurityMessage",
        ":SNTDecisionCache",
        "//src/common:SantaCache",
        "//src/common:SantaVnode",
        "//src/common:String",
    ],
)

objc_library(
    name = "EndpointSecuritySerializerEmpty",
    srcs = ["logs/endpoint_security/serializers/Empty.mm"],
    hdrs = ["logs/endpoint_security/serializers/Empty.h"],
    deps = [
        ":EndpointSecuritySerializer",
        "//src/common:Platform",
        "//src/common:SNTCachedDecision",
    ],
)

objc_library(
    name = "EndpointSecuritySanitizableString",
    srcs = ["logs/endpoint_security/serializers/SanitizableString.mm"],
    hdrs = ["logs/endpoint_security/serializers/SanitizableString.h"],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
    deps = [
        ":EndpointSecurityMessage",
        "//src/common:String",
    ],
)

objc_library(
    name = "EndpointSecuritySerializerBasicString",
    srcs = ["logs/endpoint_security/serializers/BasicString.mm"],
    hdrs = ["logs/endpoint_security/serializers/BasicString.h"],
    deps = [
        ":EndpointSecurityAPI",
        ":EndpointSecuritySanitizableString",
        ":EndpointSecuritySerializer",
        ":EndpointSecuritySerializerUtilities",
        ":SNTDecisionCache",
        "//src/common:AuditUtilities",
        "//src/common:Platform",
        "//src/common:SNTCachedDecision",
        "//src/common:SNTLogging",
        "//src/common:SNTStoredExecutionEvent",
        "//src/common:String",
    ],
)

objc_library(
    name = "EndpointSecuritySerializerProtobuf",
    srcs = ["logs/endpoint_security/serializers/Protobuf.mm"],
    hdrs = ["logs/endpoint_security/serializers/Protobuf.h"],
    deps = [
        ":EndpointSecurityAPI",
        ":EndpointSecuritySerializer",
        ":EndpointSecuritySerializerUtilities",
        ":SNTDecisionCache",
        "//src/common:AuditUtilities",
        "//src/common:EncodeEntitlements",
        "//src/common:Platform",
        "//src/common:SNTCachedDecision",
        "//src/common:SNTConfigurator",
        "//src/common:SNTLogging",
        "//src/common:SNTStoredExecutionEvent",
        "//src/common:SNTSystemInfo",
        "//src/common:String",
        "//src/common:santa_cc_proto_library_wrapper",
        "@abseil-cpp//absl/status",
        "@protobuf//src/google/protobuf/json",
    ],
)

objc_library(
    name = "EndpointSecurityWriter",
    hdrs = ["logs/endpoint_security/writers/Writer.h"],
    deps = [
        "@abseil-cpp//absl/container:flat_hash_map",
        "@abseil-cpp//absl/container:flat_hash_set",
    ],
)

objc_library(
    name = "EndpointSecurityWriterSyslog",
    srcs = ["logs/endpoint_security/writers/Syslog.mm"],
    hdrs = ["logs/endpoint_security/writers/Syslog.h"],
    deps = [
        ":EndpointSecurityWriter",
    ],
)

objc_library(
    name = "EndpointSecurityWriterFile",
    srcs = ["logs/endpoint_security/writers/File.mm"],
    hdrs = ["logs/endpoint_security/writers/File.h"],
    deps = [
        ":EndpointSecurityWriter",
        "//src/common:BranchPrediction",
    ],
)

objc_library(
    name = "EndpointSecurityWriterSpool",
    hdrs = ["logs/endpoint_security/writers/Spool.h"],
    deps = [
        ":EndpointSecurityWriter",
        "//src/common:SNTLogging",
        "//src/common:santa_cc_proto_library_wrapper",
        "//src/santad/logs/endpoint_security/writers/fsspool:fsspool",
        "@abseil-cpp//absl/container:flat_hash_map",
        "@abseil-cpp//absl/container:flat_hash_set",
        "@abseil-cpp//absl/strings",
    ],
)

objc_library(
    name = "EndpointSecurityWriterNull",
    srcs = ["logs/endpoint_security/writers/Null.mm"],
    hdrs = ["logs/endpoint_security/writers/Null.h"],
    deps = [
        ":EndpointSecurityWriter",
    ],
)

objc_library(
    name = "EndpointSecurityLogger",
    srcs = ["logs/endpoint_security/Logger.mm"],
    hdrs = ["logs/endpoint_security/Logger.h"],
    deps = [
        ":EndpointSecurityAPI",
        ":EndpointSecurityEnrichedTypes",
        ":EndpointSecurityMessage",
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
        ":SNTSyncdQueue",
        "//src/common:SNTCommonEnums",
        "//src/common:SNTExportConfiguration",
        "//src/common:SNTLogging",
        "//src/common:SNTStoredExecutionEvent",
        "//src/common:SNTSystemInfo",
        "//src/common:TelemetryEventMap",
        "//src/common:Timer",
        "//src/santad/logs/endpoint_security/writers/fsspool:SpoolBatchers",
        "@abseil-cpp//absl/container:flat_hash_map",
        "@abseil-cpp//absl/container:flat_hash_set",
    ],
)

objc_library(
    name = "EndpointSecurityMessage",
    srcs = [
        "event_providers/endpoint_security/EndpointSecurityAPI.h",
        "event_providers/endpoint_security/Message.mm",
    ],
    hdrs = ["event_providers/endpoint_security/Message.h"],
    deps = [
        ":EndpointSecurityClient",
        "//src/common:String",
        "//src/common/faa:WatchItemPolicy",
        "//src/santad/process_tree:process_tree",
    ],
)

objc_library(
    name = "EndpointSecurityClient",
    hdrs = ["event_providers/endpoint_security/Client.h"],
)

objc_library(
    name = "EndpointSecurityAPI",
    srcs = ["event_providers/endpoint_security/EndpointSecurityAPI.mm"],
    hdrs = ["event_providers/endpoint_security/EndpointSecurityAPI.h"],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
    deps = [
        ":EndpointSecurityClient",
        ":EndpointSecurityMessage",
        "//src/common:Platform",
        "//src/common/faa:WatchItemPolicy",
    ],
)

objc_library(
    name = "KillingMachine",
    srcs = ["KillingMachine.mm"],
    hdrs = ["KillingMachine.h"],
    sdk_dylibs = [
        "bsm",
    ],
    deps = [
        "//src/common:CodeSigningIdentifierUtils",
        "//src/common:SNTKillCommand",
        "//src/common:SNTLogging",
        "//src/common:SNTSystemInfo",
        "//src/common:String",
        "//src/common:SystemResources",
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
        "//src/common:CodeSigningIdentifierUtils",
        "//src/common:SNTKillCommand",
        "//src/common:SNTLogging",
        "//src/common:SNTSystemInfo",
        "//src/common:String",
        "//src/common:SystemResources",
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
        ":SNTNotificationQueue",
        ":SNTRuleTable",
        ":SNTSyncdQueue",
        ":TemporaryMonitorMode",
        "//src/common:MOLCodesignChecker",
        "//src/common:MOLXPCConnection",
        "//src/common:Pinning",
        "//src/common:SNTCachedDecision",
        "//src/common:SNTCommonEnums",
        "//src/common:SNTConfigurator",
        "//src/common:SNTError",
        "//src/common:SNTFileAccessRule",
        "//src/common:SNTLogging",
        "//src/common:SNTMetricSet",
        "//src/common:SNTModeTransition",
        "//src/common:SNTRule",
        "//src/common:SNTRuleIdentifiers",
        "//src/common:SNTStoredExecutionEvent",
        "//src/common:SNTStrengthify",
        "//src/common:SNTTimer",
        "//src/common:SNTXPCControlInterface",
        "//src/common:SNTXPCNotifierInterface",
        "//src/common:SNTXPCSyncServiceInterface",
        "//src/common/faa:WatchItems",
        "@FMDB",
    ],
)

objc_library(
    name = "Metrics",
    srcs = ["Metrics.mm"],
    hdrs = ["Metrics.h"],
    deps = [
        ":EndpointSecurityMessage",
        ":SNTApplicationCoreMetrics",
        "//src/common:MOLXPCConnection",
        "//src/common:Platform",
        "//src/common:SNTCommonEnums",
        "//src/common:SNTLogging",
        "//src/common:SNTMetricSet",
        "//src/common:SNTXPCMetricServiceInterface",
    ],
)

objc_library(
    name = "Santad",
    srcs = ["Santad.mm"],
    hdrs = ["Santad.h"],
    deps = [
        ":AuthResultCache",
        ":DaemonConfigBundle",
        ":EndpointSecurityAPI",
        ":EndpointSecurityEnricher",
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
        ":SNTNotificationQueue",
        ":SNTRuleTable",
        ":SNTSyncdQueue",
        ":TTYWriter",
        "//src/common:MOLXPCConnection",
        "//src/common:PrefixTree",
        "//src/common:SNTCommonEnums",
        "//src/common:SNTConfigurator",
        "//src/common:SNTKVOManager",
        "//src/common:SNTLogging",
        "//src/common:SNTStoredFileAccessEvent",
        "//src/common:SNTStoredNetworkMountEvent",
        "//src/common:SNTXPCNotifierInterface",
        "//src/common:SNTXPCSyncServiceInterface",
        "//src/common:TelemetryEventMap",
        "//src/common:Unit",
        "//src/common/faa:WatchItemPolicy",
        "//src/common/faa:WatchItems",
        "//src/santad/process_tree:process_tree",
    ],
)

objc_library(
    name = "SantadDeps",
    srcs = ["SantadDeps.mm"],
    hdrs = ["SantadDeps.h"],
    deps = [
        ":AuthResultCache",
        ":EndpointSecurityAPI",
        ":EndpointSecurityEnricher",
        ":EndpointSecurityLogger",
        ":EntitlementsFilter",
        ":Metrics",
        ":ProcessControl",
        ":SNTCompilerController",
        ":SNTDatabaseController",
        ":SNTDecisionCache",
        ":SNTEventTable",
        ":SNTExecutionController",
        ":SNTNotificationQueue",
        ":SNTRuleTable",
        ":SNTSyncdQueue",
        ":TTYWriter",
        "//src/common:MOLXPCConnection",
        "//src/common:PrefixTree",
        "//src/common:RingBuffer",
        "//src/common:SNTConfigurator",
        "//src/common:SNTExportConfiguration",
        "//src/common:SNTLogging",
        "//src/common:SNTMetricSet",
        "//src/common:SNTStrengthify",
        "//src/common:SNTXPCControlInterface",
        "//src/common:SNTXPCUnprivilegedControlInterface",
        "//src/common:TelemetryEventMap",
        "//src/common:Unit",
        "//src/common/faa:WatchItems",
        "//src/santad/process_tree:process_tree",
        "//src/santad/process_tree/annotations:originator",
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
        "//src/common:SNTConfigurator",
        "//src/common:SNTLogging",
        "//src/common:SNTMetricSet",
        "//src/common:SNTSystemInfo",
        "//src/common:SNTXPCControlInterface",
        "//src/common:SystemResources",
        "//src/santad:ProcessControl",
    ],
)

macos_bundle(
    name = "com.northpolesec.santa.daemon",
    bundle_extension = "systemextension",
    bundle_id = "com.northpolesec.santa.daemon",
    codesignopts = [
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
        "//src/common:CommitHash",
    ],
    linkopts = ["-execute"],
    minimum_os_version = SANTA_MINIMUM_OS_VERSION,
    provisioning_profile = select({
        "//:adhoc_build": None,
        "//conditions:default": "//profiles:daemon_dev",
    }),
    resources = [
        "//:conf/com.northpolesec.santa.bundleservice.plist",
        "//:conf/com.northpolesec.santa.metricservice.plist",
        "//:conf/com.northpolesec.santa.plist",
        "//:conf/com.northpolesec.santa.syncservice.plist",
        "//:conf/install_services.sh",
    ],
    version = "//:version",
    visibility = ["//:santa_package_group"],
    deps = [":santad_main"],
)

#
# Begin test targets
#

objc_library(
    name = "MockEndpointSecurityAPI",
    testonly = 1,
    hdrs = ["event_providers/endpoint_security/MockEndpointSecurityAPI.h"],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
    deps = [
        ":EndpointSecurityAPI",
        ":EndpointSecurityClient",
        ":EndpointSecurityMessage",
        "//src/common/faa:WatchItemPolicy",
        "@googletest//:gtest",
    ],
)

objc_library(
    name = "MockEnricher",
    testonly = 1,
    hdrs = ["event_providers/endpoint_security/MockEnricher.h"],
    deps = [
        ":EndpointSecurityEnrichedTypes",
        ":EndpointSecurityEnricher",
        "@googletest//:gtest",
    ],
)

objc_library(
    name = "MockFAAPolicyProcessor",
    testonly = 1,
    hdrs = ["event_providers/MockFAAPolicyProcessor.h"],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
    deps = [
        ":EndpointSecurityEnricher",
        ":EndpointSecurityLogger",
        ":Metrics",
        ":SNTDecisionCache",
        ":TTYWriter",
        "//src/common:SNTCachedDecision",
        "//src/common/faa:WatchItemPolicy",
        "@googletest//:gtest",
    ],
)

objc_library(
    name = "MockLogger",
    testonly = 1,
    hdrs = ["logs/endpoint_security/MockLogger.h"],
    deps = [
        ":EndpointSecurityEnrichedTypes",
        ":EndpointSecurityLogger",
        ":EndpointSecurityMessage",
        "//src/common:TelemetryEventMap",
        "@googletest//:gtest",
    ],
)

santa_unit_test(
    name = "SNTEventTableTest",
    srcs = [
        "data_layer/SNTDatabaseTable.h",
        "data_layer/SNTDatabaseTable.mm",
        "data_layer/SNTEventTable.h",
        "data_layer/SNTEventTable.mm",
        "data_layer/SNTEventTableTest.mm",
    ],
    structured_resources = [
        "//src/santad/testdata:archive_testdata",
    ],
    deps = [
        "//src/common:MOLCertificate",
        "//src/common:MOLCodesignChecker",
        "//src/common:SNTFileInfo",
        "//src/common:SNTLogging",
        "//src/common:SNTStoredExecutionEvent",
        "//src/common:SNTStoredFileAccessEvent",
        "//src/common:SNTStoredTemporaryMonitorModeAuditEvent",
        "//src/common:SantaCache",
        "//src/common:String",
        "//src/common:TestUtils",
        "@FMDB",
        "@OCMock",
    ],
)

santa_unit_test(
    name = "SNTRuleTableTest",
    srcs = [
        "data_layer/SNTRuleTableTest.mm",
    ],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
    deps = [
        ":SNTRuleTable",
        "//src/common:CertificateHelpers",
        "//src/common:MOLCertificate",
        "//src/common:MOLCodesignChecker",
        "//src/common:Platform",
        "//src/common:SNTCachedDecision",
        "//src/common:SNTCommonEnums",
        "//src/common:SNTConfigurator",
        "//src/common:SNTFileAccessRule",
        "//src/common:SNTFileInfo",
        "//src/common:SNTLogging",
        "//src/common:SNTRule",
        "//src/common:SNTRuleIdentifiers",
        "//src/common:SigningIDHelpers",
        "//src/common:String",
        "//src/common:TestUtils",
        "//src/common/cel:CEL",
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
    sdk_frameworks = [
        "DiskArbitration",
    ],
    structured_resources = [
        "//src/santad/testdata:binaryrules_testdata",
    ],
    tags = ["exclusive"],
    deps = [
        ":EndpointSecurityMessage",
        ":Metrics",
        ":MockEndpointSecurityAPI",
        ":ProcessControl",
        ":SNTDatabaseController",
        ":SNTDecisionCache",
        ":SNTEndpointSecurityAuthorizer",
        ":SNTEndpointSecurityClient",
        ":SantadDeps",
        "//src/common:MOLCertificate",
        "//src/common:MOLCodesignChecker",
        "//src/common:SNTCachedDecision",
        "//src/common:SNTConfigurator",
        "//src/common:TestUtils",
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
        "//src/common:SNTCommonEnums",
        "//src/common:SNTConfigurator",
        "//src/common:SNTMetricSet",
        "//src/common:SNTSystemInfo",
        "//src/santametricservice/formats:SNTMetricFormatTestHelper",
        "@OCMock",
    ],
)

santa_unit_test(
    name = "EndpointSecuritySanitizableStringTest",
    srcs = ["logs/endpoint_security/serializers/SanitizableStringTest.mm"],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
    deps = [
        ":EndpointSecuritySanitizableString",
        "//src/common:TestUtils",
        "@OCMock",
    ],
)

santa_unit_test(
    name = "EndpointSecuritySerializerUtilitiesTest",
    srcs = ["logs/endpoint_security/serializers/UtilitiesTest.mm"],
    deps = [
        ":EndpointSecurityMessage",
        ":EndpointSecuritySerializerUtilities",
        ":MockEndpointSecurityAPI",
        "//src/common:TestUtils",
        "@OCMock",
        "@googletest//:gtest",
    ],
)

santa_unit_test(
    name = "EndpointSecuritySerializerBasicStringTest",
    srcs = ["logs/endpoint_security/serializers/BasicStringTest.mm"],
    sdk_dylibs = [
        "bsm",
        "EndpointSecurity",
    ],
    deps = [
        ":EndpointSecurityEnrichedTypes",
        ":EndpointSecurityEnricher",
        ":EndpointSecurityMessage",
        ":EndpointSecuritySerializer",
        ":EndpointSecuritySerializerBasicString",
        ":MockEndpointSecurityAPI",
        ":SNTDecisionCache",
        "//src/common:Platform",
        "//src/common:SNTCachedDecision",
        "//src/common:SNTCommonEnums",
        "//src/common:SNTConfigurator",
        "//src/common:SNTStoredExecutionEvent",
        "//src/common:TestUtils",
        "@OCMock",
        "@googletest//:gtest",
    ],
)

santa_unit_test(
    name = "EndpointSecuritySerializerProtobufTest",
    srcs = ["logs/endpoint_security/serializers/ProtobufTest.mm"],
    structured_resources = [
        "//src/santad/testdata:protobuf_json_testdata",
    ],
    deps = [
        ":EndpointSecurityEnrichedTypes",
        ":EndpointSecurityEnricher",
        ":EndpointSecurityMessage",
        ":EndpointSecuritySerializer",
        ":EndpointSecuritySerializerProtobuf",
        ":MockEndpointSecurityAPI",
        ":SNTDecisionCache",
        "//src/common:Platform",
        "//src/common:SNTCachedDecision",
        "//src/common:SNTCommonEnums",
        "//src/common:SNTConfigurator",
        "//src/common:SNTStoredExecutionEvent",
        "//src/common:TestUtils",
        "//src/common:santa_cc_proto_library_wrapper",
        "@OCMock",
        "@abseil-cpp//absl/status",
        "@googletest//:gtest",
        "@protobuf//src/google/protobuf/json",
    ],
)

santa_unit_test(
    name = "AuthResultCacheTest",
    srcs = ["event_providers/AuthResultCacheTest.mm"],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
    deps = [
        ":AuthResultCache",
        ":MockEndpointSecurityAPI",
        ":SNTEndpointSecurityClientBase",
        "//src/common:SNTCommonEnums",
        "//src/common:SantaVnode",
        "//src/common:TestUtils",
        "@OCMock",
        "@googletest//:gtest",
    ],
)

santa_unit_test(
    name = "RateLimiterTest",
    srcs = ["event_providers/RateLimiterTest.mm"],
    deps = [
        ":Metrics",
        ":RateLimiter",
        "//src/common:SystemResources",
    ],
)

santa_unit_test(
    name = "EndpointSecuritySerializerEmptyTest",
    srcs = ["logs/endpoint_security/serializers/EmptyTest.mm"],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
    deps = [
        ":EndpointSecurityEnrichedTypes",
        ":EndpointSecuritySerializerEmpty",
        "@OCMock",
    ],
)

santa_unit_test(
    name = "EndpointSecurityWriterFileTest",
    srcs = ["logs/endpoint_security/writers/FileTest.mm"],
    deps = [
        ":EndpointSecurityWriterFile",
        "//src/common:TestUtils",
        "@OCMock",
        "@googletest//:gtest",
    ],
)

santa_unit_test(
    name = "EndpointSecurityWriterSpoolTest",
    srcs = ["logs/endpoint_security/writers/SpoolTest.mm"],
    deps = [
        ":EndpointSecurityWriterSpool",
        "//src/common:TestUtils",
        "//src/santad/logs/endpoint_security/writers/fsspool:SpoolBatchers",
        "//src/santad/logs/endpoint_security/writers/fsspool:fsspool",
    ],
)

santa_unit_test(
    name = "EndpointSecurityLoggerTest",
    srcs = ["logs/endpoint_security/LoggerTest.mm"],
    sdk_dylibs = [
        "bsm",
        "EndpointSecurity",
    ],
    deps = [
        ":EndpointSecurityLogger",
        ":EndpointSecurityMessage",
        ":EndpointSecuritySerializer",
        ":EndpointSecuritySerializerBasicString",
        ":EndpointSecuritySerializerEmpty",
        ":EndpointSecuritySerializerProtobuf",
        ":EndpointSecurityWriter",
        ":EndpointSecurityWriterFile",
        ":EndpointSecurityWriterNull",
        ":EndpointSecurityWriterSpool",
        ":EndpointSecurityWriterSyslog",
        ":MockEndpointSecurityAPI",
        ":SNTSyncdQueue",
        "//src/common:SNTCommonEnums",
        "//src/common:SNTExportConfiguration",
        "//src/common:TelemetryEventMap",
        "//src/common:TestUtils",
        "//src/santad/logs/endpoint_security/writers/fsspool:SpoolBatchers",
        "@OCMock",
        "@googletest//:gtest",
    ],
)

santa_unit_test(
    name = "EndpointSecurityClientTest",
    srcs = ["event_providers/endpoint_security/ClientTest.mm"],
    deps = [
        ":EndpointSecurityClient",
        "@OCMock",
    ],
)

santa_unit_test(
    name = "EndpointSecurityEnricherTest",
    srcs = ["event_providers/endpoint_security/EnricherTest.mm"],
    sdk_dylibs = [
        "bsm",
    ],
    deps = [
        ":EndpointSecurityEnricher",
        "//src/common:TestUtils",
        "@OCMock",
    ],
)

santa_unit_test(
    name = "EndpointSecurityMessageTest",
    srcs = ["event_providers/endpoint_security/MessageTest.mm"],
    sdk_dylibs = [
        "bsm",
        "EndpointSecurity",
    ],
    deps = [
        ":EndpointSecurityMessage",
        ":MockEndpointSecurityAPI",
        "//src/common:AuditUtilities",
        "//src/common:TestUtils",
        "@OCMock",
        "@googletest//:gtest",
    ],
)

santa_unit_test(
    name = "MetricsTest",
    srcs = ["MetricsTest.mm"],
    deps = [
        ":EndpointSecurityMessage",
        ":Metrics",
        ":MockEndpointSecurityAPI",
        "//src/common:Platform",
        "//src/common:SNTCommonEnums",
        "//src/common:SNTMetricSet",
        "//src/common:TestUtils",
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
        "//src/common:SNTCachedDecision",
        "//src/common:SNTCommonEnums",
        "//src/common:SNTRule",
        "//src/common:SantaVnode",
        "//src/common:TestUtils",
        "@OCMock",
    ],
)

santa_unit_test(
    name = "SNTEndpointSecurityClientTest",
    srcs = ["event_providers/SNTEndpointSecurityClientTest.mm"],
    sdk_dylibs = [
        "bsm",
        "EndpointSecurity",
    ],
    deps = [
        ":EndpointSecurityClient",
        ":EndpointSecurityEnrichedTypes",
        ":EndpointSecurityMessage",
        ":Metrics",
        ":MockEndpointSecurityAPI",
        ":SNTEndpointSecurityClient",
        "//src/common:AuditUtilities",
        "//src/common:SNTCommonEnums",
        "//src/common:SNTConfigurator",
        "//src/common:SystemResources",
        "//src/common:TestUtils",
        "//src/common/faa:WatchItemPolicy",
        "@OCMock",
        "@googletest//:gtest",
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
        ":EndpointSecurityMessage",
        ":EntitlementsFilter",
        ":MockEndpointSecurityAPI",
        ":ProcessControl",
        ":SNTDatabaseController",
        ":SNTDecisionCache",
        ":SNTEventTable",
        ":SNTExecutionController",
        ":SNTPolicyProcessor",
        ":SNTRuleTable",
        "//src/common:MOLCertificate",
        "//src/common:MOLCodesignChecker",
        "//src/common:SNTCachedDecision",
        "//src/common:SNTCommonEnums",
        "//src/common:SNTConfigurator",
        "//src/common:SNTFileInfo",
        "//src/common:SNTMetricSet",
        "//src/common:SNTRule",
        "//src/common:SNTRuleIdentifiers",
        "//src/common:TestUtils",
        "@OCMock",
    ],
)

santa_unit_test(
    name = "SNTEndpointSecurityAuthorizerTest",
    srcs = ["event_providers/SNTEndpointSecurityAuthorizerTest.mm"],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
    deps = [
        ":AuthResultCache",
        ":EndpointSecurityClient",
        ":EndpointSecurityMessage",
        ":Metrics",
        ":MockEndpointSecurityAPI",
        ":SNTCompilerController",
        ":SNTEndpointSecurityAuthorizer",
        ":SNTExecutionController",
        ":TTYWriter",
        "//src/common:SNTCommonEnums",
        "//src/common:TestUtils",
        "@OCMock",
        "@googletest//:gtest",
    ],
)

santa_unit_test(
    name = "SNTEndpointSecurityDataFileAccessAuthorizerTest",
    srcs = ["event_providers/SNTEndpointSecurityDataFileAccessAuthorizerTest.mm"],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
    deps = [
        ":MockEndpointSecurityAPI",
        ":SNTEndpointSecurityDataFileAccessAuthorizer",
        "//src/common:SNTConfigurator",
        "//src/common:TestUtils",
        "@OCMock",
        "@googletest//:gtest",
    ],
)

santa_unit_test(
    name = "SNTEndpointSecurityProcessFileAccessAuthorizerTest",
    srcs = ["event_providers/SNTEndpointSecurityProcessFileAccessAuthorizerTest.mm"],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
    deps = [
        ":EndpointSecurityMessage",
        ":MockEndpointSecurityAPI",
        ":MockFAAPolicyProcessor",
        ":SNTEndpointSecurityProcessFileAccessAuthorizer",
        "//src/common:TestUtils",
        "//src/common/faa:WatchItemPolicy",
        "@OCMock",
    ],
)

santa_unit_test(
    name = "FAAPolicyProcessorTest",
    srcs = ["event_providers/FAAPolicyProcessorTest.mm"],
    deps = [
        ":EndpointSecurityMessage",
        ":FAAPolicyProcessor",
        ":MockEndpointSecurityAPI",
        ":MockFAAPolicyProcessor",
        ":SNTDecisionCache",
        "//src/common:MOLCertificate",
        "//src/common:MOLCodesignChecker",
        "//src/common:SNTCachedDecision",
        "//src/common:TestUtils",
        "//src/common/faa:WatchItemPolicy",
        "@OCMock",
        "@googletest//:gtest",
    ],
)

santa_unit_test(
    name = "SNTEndpointSecurityTamperResistanceTest",
    srcs = ["event_providers/SNTEndpointSecurityTamperResistanceTest.mm"],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
    deps = [
        ":EndpointSecurityClient",
        ":EndpointSecurityMessage",
        ":Metrics",
        ":MockEndpointSecurityAPI",
        ":SNTEndpointSecurityTamperResistance",
        "//src/common:SNTConfigurator",
        "//src/common:SNTLogging",
        "//src/common:TestUtils",
        "//src/common/faa:WatchItemPolicy",
        "@OCMock",
        "@googletest//:gtest",
    ],
)

santa_unit_test(
    name = "SNTEndpointSecurityRecorderTest",
    srcs = ["event_providers/SNTEndpointSecurityRecorderTest.mm"],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
    deps = [
        ":AuthResultCache",
        ":EndpointSecurityClient",
        ":EndpointSecurityEnrichedTypes",
        ":EndpointSecurityEnricher",
        ":EndpointSecurityLogger",
        ":EndpointSecurityMessage",
        ":Metrics",
        ":MockEndpointSecurityAPI",
        ":MockEnricher",
        ":MockLogger",
        ":SNTCompilerController",
        ":SNTEndpointSecurityRecorder",
        "//src/common:Platform",
        "//src/common:PrefixTree",
        "//src/common:SNTConfigurator",
        "//src/common:TelemetryEventMap",
        "//src/common:TestUtils",
        "//src/common:Unit",
        "@OCMock",
        "@googletest//:gtest",
    ],
)

santa_unit_test(
    name = "SNTEndpointSecurityDeviceManagerTest",
    srcs = ["event_providers/SNTEndpointSecurityDeviceManagerTest.mm"],
    sdk_dylibs = [
        "bsm",
        "EndpointSecurity",
    ],
    deps = [
        ":AuthResultCache",
        ":DiskArbitrationTestLib",
        ":EndpointSecurityClient",
        ":EndpointSecurityMessage",
        ":Metrics",
        ":MockEndpointSecurityAPI",
        ":MockEnricher",
        ":SNTEndpointSecurityClient",
        ":SNTEndpointSecurityDeviceManager",
        "//src/common:SNTCommonEnums",
        "//src/common:SNTConfigurator",
        "//src/common:SNTDeviceEvent",
        "//src/common:TestUtils",
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
        ":EndpointSecurityMessage",
        ":MockEndpointSecurityAPI",
        ":SNTCompilerController",
        ":SNTDecisionCache",
        "//src/common:SNTCachedDecision",
        "//src/common:SNTFileInfo",
        "//src/common:TestUtils",
        "@OCMock",
        "@googletest//:gtest",
    ],
)

test_suite(
    name = "unit_tests",
    tests = [
        ":AuthResultCacheTest",
        ":DaemonConfigBundleTest",
        ":EndpointSecurityClientTest",
        ":EndpointSecurityEnricherTest",
        ":EndpointSecurityLoggerTest",
        ":EndpointSecurityMessageTest",
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
        ":SNTEndpointSecurityClientTest",
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
        "//src/santad/logs/endpoint_security/writers/fsspool:fsspool_test",
        "//src/santad/process_tree:process_tree_test",
        "//src/santad/process_tree/annotations:originator_test",
    ],
    visibility = ["//:santa_package_group"],
)
