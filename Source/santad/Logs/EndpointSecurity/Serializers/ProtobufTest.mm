/// Copyright 2022 Google LLC
/// Copyright 2024 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     https://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#include <EndpointSecurity/EndpointSecurity.h>
#import <Foundation/Foundation.h>
#include <Kernel/kern/cs_blobs.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#include <gmock/gmock.h>
#include <google/protobuf/json/json.h>
#include <gtest/gtest.h>
#include <sys/proc_info.h>
#include <sys/signal.h>
#include <sys/wait.h>
#include <time.h>
#include <uuid/uuid.h>
#include <cstddef>
#include <cstring>

#include "Source/common/Platform.h"
#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTStoredExecutionEvent.h"
#include "Source/common/TestUtils.h"
#include "Source/common/santa_proto_include_wrapper.h"
#include "Source/santad/EventProviders/EndpointSecurity/EnrichedTypes.h"
#include "Source/santad/EventProviders/EndpointSecurity/Enricher.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/EventProviders/EndpointSecurity/MockEndpointSecurityAPI.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/Protobuf.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/Serializer.h"
#import "Source/santad/SNTDecisionCache.h"
#include "absl/status/status.h"
#include "google/protobuf/any.pb.h"
#include "google/protobuf/timestamp.pb.h"

using google::protobuf::Timestamp;
using JsonPrintOptions = google::protobuf::json::PrintOptions;
using JsonParseOptions = ::google::protobuf::json::ParseOptions;
using google::protobuf::json::JsonStringToMessage;
using google::protobuf::json::MessageToJsonString;
using santa::EnrichedEventType;
using santa::EnrichedMessage;
using santa::Enricher;
using santa::Message;
using santa::Protobuf;
using santa::Serializer;

namespace pbv1 = ::santa::pb::v1;

namespace santa {
extern void EncodeExitStatus(::pbv1::Exit *pbExit, int exitStatus);
extern void EncodeEntitlements(::pbv1::Execution *pb_exec, SNTCachedDecision *cd);
extern ::pbv1::Execution::Decision GetDecisionEnum(SNTEventState event_state);
extern ::pbv1::Execution::Reason GetReasonEnum(SNTEventState event_state);
extern ::pbv1::Execution::Mode GetModeEnum(SNTClientMode mode);
extern ::pbv1::FileDescriptor::FDType GetFileDescriptorType(uint32_t fdtype);
extern ::pbv1::FileAccess::AccessType GetAccessType(es_event_type_t event_type);
extern ::pbv1::FileAccess::PolicyDecision GetPolicyDecision(FileAccessPolicyDecision decision);
extern ::pbv1::SocketAddress::Type GetSocketAddressType(es_address_type_t type);
extern ::pbv1::OpenSSHLogin::Result GetOpenSSHLoginResultType(es_openssh_login_result_type_t type);
extern ::pbv1::AuthenticationTouchID::Mode GetAuthenticationTouchIDMode(es_touchid_mode_t mode);
extern ::pbv1::AuthenticationAutoUnlock::Type GetAuthenticationAutoUnlockType(
    es_auto_unlock_type_t type);
extern ::pbv1::LaunchItem::ItemType GetBTMLaunchItemType(es_btm_item_type_t item_type);
#if HAVE_MACOS_15_4
extern ::pbv1::TCCModification::IdentityType GetTCCIdentityType(es_tcc_identity_type_t id_type);
extern ::pbv1::TCCModification::EventType GetTCCEventType(es_tcc_event_type_t event_type);
extern ::pbv1::TCCModification::AuthorizationRight GetTCCAuthorizationRight(
    es_tcc_authorization_right_t auth_right);
extern ::pbv1::TCCModification::AuthorizationReason GetTCCAuthorizationReason(
    es_tcc_authorization_reason_t auth_reason);
#endif  // HAVE_MACOS_15_4
}  // namespace santa

using santa::EncodeEntitlements;
using santa::EncodeExitStatus;

@interface ProtobufTest : XCTestCase
@property id mockConfigurator;
@property id mockDecisionCache;
@property SNTCachedDecision *testCachedDecision;
@end

JsonPrintOptions DefaultJsonPrintOptions() {
  JsonPrintOptions options;
  options.always_print_enums_as_ints = false;
  options.always_print_fields_with_no_presence = false;
  options.preserve_proto_field_names = true;
  options.add_whitespace = true;
  return options;
}

NSString *ConstructFilename(es_event_type_t eventType, NSString *variant = nil) {
  NSString *name;
  switch (eventType) {
    case ES_EVENT_TYPE_NOTIFY_CLOSE: name = @"close"; break;
    case ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA: name = @"exchangedata"; break;
    case ES_EVENT_TYPE_NOTIFY_EXEC: name = @"exec"; break;
    case ES_EVENT_TYPE_NOTIFY_EXIT: name = @"exit"; break;
    case ES_EVENT_TYPE_NOTIFY_FORK: name = @"fork"; break;
    case ES_EVENT_TYPE_NOTIFY_LINK: name = @"link"; break;
    case ES_EVENT_TYPE_NOTIFY_RENAME: name = @"rename"; break;
    case ES_EVENT_TYPE_NOTIFY_UNLINK: name = @"unlink"; break;
    case ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED: name = @"cs_invalidated"; break;
    case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN: name = @"lw_session_login"; break;
    case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT: name = @"lw_session_logout"; break;
    case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK: name = @"lw_session_lock"; break;
    case ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK: name = @"lw_session_unlock"; break;
    case ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH: name = @"screensharing_attach"; break;
    case ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH: name = @"screensharing_detach"; break;
    case ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN: name = @"openssh_login"; break;
    case ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT: name = @"openssh_logout"; break;
    case ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN: name = @"login_login"; break;
    case ES_EVENT_TYPE_NOTIFY_AUTHENTICATION: name = @"authentication"; break;
    case ES_EVENT_TYPE_NOTIFY_CLONE: name = @"clone"; break;
    case ES_EVENT_TYPE_NOTIFY_COPYFILE: name = @"copyfile"; break;
    case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD: name = @"launch_item_add"; break;
    case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE: name = @"launch_item_remove"; break;
    case ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED: name = @"xp_detected"; break;
    case ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED: name = @"xp_remediated"; break;
#if HAVE_MACOS_15
    case ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE: name = @"gatekeeper"; break;
#endif  // HAVE_MACOS_15
#if HAVE_MACOS_15_4
    case ES_EVENT_TYPE_NOTIFY_TCC_MODIFY: name = @"tcc_modify"; break;
#endif  // HAVE_MACOS_15_4
    default:
      XCTFail(@"Failed to construct filename: Unhandled event type: %d", eventType);
      return nil;
  }

  if (variant) {
    return [NSString stringWithFormat:@"%@_%@.json", name, variant];
  } else {
    return [NSString stringWithFormat:@"%@.json", name];
  }
}

NSString *LoadTestJson(NSString *jsonFileName, uint32_t version) {
  if (!jsonFileName) {
    return nil;
  }

  NSString *path = [NSString pathWithComponents:@[
    [[NSBundle bundleForClass:[ProtobufTest class]] resourcePath],
    @"protobuf",
    [NSString stringWithFormat:@"v%u", version],
    jsonFileName,
  ]];

  NSError *err = nil;
  NSString *jsonData = [NSString stringWithContentsOfFile:path
                                                 encoding:NSUTF8StringEncoding
                                                    error:&err];

  if (err) {
    XCTFail(@"Failed to load test data \"%@\": %@", jsonFileName, err);
  }

  return jsonData;
}

bool CompareTime(const Timestamp &timestamp, struct timespec ts) {
  return timestamp.seconds() == ts.tv_sec && timestamp.nanos() == ts.tv_nsec;
}

const google::protobuf::Message &SantaMessageEvent(const ::pbv1::SantaMessage &santaMsg) {
  switch (santaMsg.event_case()) {
    case ::pbv1::SantaMessage::kExecution: return santaMsg.execution();
    case ::pbv1::SantaMessage::kFork: return santaMsg.fork();
    case ::pbv1::SantaMessage::kExit: return santaMsg.exit();
    case ::pbv1::SantaMessage::kClose: return santaMsg.close();
    case ::pbv1::SantaMessage::kRename: return santaMsg.rename();
    case ::pbv1::SantaMessage::kUnlink: return santaMsg.unlink();
    case ::pbv1::SantaMessage::kLink: return santaMsg.link();
    case ::pbv1::SantaMessage::kExchangedata: return santaMsg.exchangedata();
    case ::pbv1::SantaMessage::kDisk: return santaMsg.disk();
    case ::pbv1::SantaMessage::kBundle: return santaMsg.bundle();
    case ::pbv1::SantaMessage::kAllowlist: return santaMsg.allowlist();
    case ::pbv1::SantaMessage::kFileAccess: return santaMsg.file_access();
    case ::pbv1::SantaMessage::kCodesigningInvalidated: return santaMsg.codesigning_invalidated();
    case ::pbv1::SantaMessage::kLoginWindowSession: return santaMsg.login_window_session();
    case ::pbv1::SantaMessage::kScreenSharing: return santaMsg.screen_sharing();
    case ::pbv1::SantaMessage::kOpenSsh: return santaMsg.open_ssh();
    case ::pbv1::SantaMessage::kLoginLogout: return santaMsg.login_logout();
    case ::pbv1::SantaMessage::kAuthentication: return santaMsg.authentication();
    case ::pbv1::SantaMessage::kClone: return santaMsg.clone();
    case ::pbv1::SantaMessage::kCopyfile: return santaMsg.copyfile();
    case ::pbv1::SantaMessage::kGatekeeperOverride: return santaMsg.gatekeeper_override();
    case ::pbv1::SantaMessage::kLaunchItem: return santaMsg.launch_item();
    case ::pbv1::SantaMessage::kTccModification: return santaMsg.tcc_modification();
    case ::pbv1::SantaMessage::kXprotect: return santaMsg.xprotect();
    case ::pbv1::SantaMessage::EVENT_NOT_SET:
      XCTFail(@"Protobuf message SantaMessage did not set an 'event' field");
      OS_FALLTHROUGH;
    default:
      [NSException raise:@"Required protobuf field not set"
                  format:@"SantaMessage missing required field 'event'"];
      abort();
  }
}

std::string ConvertMessageToJsonString(const ::pbv1::SantaMessage &santaMsg) {
  JsonPrintOptions options = DefaultJsonPrintOptions();
  const google::protobuf::Message &message = SantaMessageEvent(santaMsg);

  std::string json;
  XCTAssertTrue(MessageToJsonString(message, &json, options).ok());
  return json;
}

NSDictionary *FindDelta(NSDictionary *want, NSDictionary *got) {
  NSMutableDictionary *delta = [NSMutableDictionary dictionary];
  delta[@"want"] = [NSMutableDictionary dictionary];
  delta[@"got"] = [NSMutableDictionary dictionary];

  // Find objects in `want` that don't exist or are different in `got`.
  [want enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
    id otherObj = got[key];

    if (!otherObj) {
      delta[@"want"][key] = obj;
      delta[@"got"][key] = @"Key missing";
    } else if (![obj isEqual:otherObj]) {
      delta[@"want"][key] = obj;
      delta[@"got"][key] = otherObj;
    }
  }];

  // Find objects in `got` that don't exist in `want`
  [got enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
    id aObj = want[key];

    if (!aObj) {
      delta[@"want"][key] = @"Key missing";
      delta[@"got"][key] = obj;
    }
  }];

  return [delta[@"want"] count] > 0 ? delta : nil;
}

void SerializeAndCheck(es_event_type_t eventType,
                       bool (^shouldHandleMessageSetup)(std::shared_ptr<MockEndpointSecurityAPI>,
                                                        es_message_t *),
                       SNTDecisionCache *decisionCache, bool json, NSString *variant) {
  std::shared_ptr<MockEndpointSecurityAPI> mockESApi = std::make_shared<MockEndpointSecurityAPI>();

  for (uint32_t cur_version = MinSupportedESMessageVersion(eventType);
       cur_version <= MaxSupportedESMessageVersionForCurrentOS(); cur_version++) {
    if (cur_version == 3) {
      // Note: Version 3 was only in a macOS beta.
      continue;
    }

    es_file_t procFile = MakeESFile("foo", MakeStat(100));
    es_file_t ttyFile = MakeESFile("footty", MakeStat(200));
    es_process_t proc = MakeESProcess(&procFile, MakeAuditToken(12, 34), MakeAuditToken(56, 78));
    es_message_t esMsg = MakeESMessage(eventType, &proc);
    esMsg.process->tty = &ttyFile;
    esMsg.version = cur_version;

    if (!shouldHandleMessageSetup(mockESApi, &esMsg)) {
      continue;
    }

    mockESApi->SetExpectationsRetainReleaseMessage();

    std::shared_ptr<Serializer> bs = Protobuf::Create(mockESApi, decisionCache, json);
    std::unique_ptr<EnrichedMessage> enrichedMsg = Enricher().Enrich(Message(mockESApi, &esMsg));

    // Copy some values we need to check later before the object is moved out of this funciton
    struct timespec enrichmentTime;
    struct timespec msgTime;
    NSString *wantData = std::visit(
        [&msgTime, &enrichmentTime, variant](const EnrichedEventType &enrichedEvent) {
          msgTime = enrichedEvent->time;
          enrichmentTime = enrichedEvent.enrichment_time();

          return LoadTestJson(ConstructFilename(enrichedEvent->event_type, variant),
                              enrichedEvent->version);
        },
        enrichedMsg->GetEnrichedMessage());

    std::vector<uint8_t> vec = bs->SerializeMessage(std::move(enrichedMsg));
    std::string protoStr(vec.begin(), vec.end());

    ::pbv1::SantaMessage santaMsg;
    std::string gotData;

    if (json) {
      // Parse the jsonified string into the protobuf
      JsonParseOptions options;
      options.ignore_unknown_fields = true;
      absl::Status status = JsonStringToMessage(protoStr, &santaMsg, options);
      XCTAssertTrue(status.ok());
      gotData = ConvertMessageToJsonString(santaMsg);
    } else {
      XCTAssertTrue(santaMsg.ParseFromString(protoStr));
      gotData = ConvertMessageToJsonString(santaMsg);
    }

    XCTAssertTrue(CompareTime(santaMsg.processed_time(), enrichmentTime));
    XCTAssertTrue(CompareTime(santaMsg.event_time(), msgTime));

    // Convert JSON strings to objects and compare each key-value set.
    NSError *jsonError;
    NSData *objectData = [wantData dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *wantJSONDict =
        [NSJSONSerialization JSONObjectWithData:objectData
                                        options:NSJSONReadingMutableContainers
                                          error:&jsonError];
    XCTAssertNil(jsonError, @"failed to parse want data as JSON");
    NSDictionary *gotJSONDict = [NSJSONSerialization
        JSONObjectWithData:[NSData dataWithBytes:gotData.data() length:gotData.length()]
                   options:NSJSONReadingMutableContainers
                     error:&jsonError];
    XCTAssertNil(jsonError, @"failed to parse got data as JSON");

    XCTAssertNil(FindDelta(wantJSONDict, gotJSONDict));
    // Note: Uncomment this line to help create testfile JSON when the assert above fails
    // XCTAssertEqualObjects([NSString stringWithUTF8String:gotData.c_str()], wantData,
    //                       @"Result does not match expectations. Version: %d, Filename: %@",
    //                       cur_version, ConstructFilename(esMsg.event_type, variant));
  }

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

// Legacy variant. Now wraps `messageSetup` in a small block to always return `true`
void SerializeAndCheck(es_event_type_t eventType,
                       void (^messageSetup)(std::shared_ptr<MockEndpointSecurityAPI>,
                                            es_message_t *),
                       SNTDecisionCache *decisionCache, bool json, NSString *variant) {
  return SerializeAndCheck(
      eventType,
      ^bool(std::shared_ptr<MockEndpointSecurityAPI> esapi, es_message_t *msg) {
        messageSetup(esapi, msg);
        return true;
      },
      decisionCache, json, variant);
}

void SerializeAndCheckNonESEvents(
    uint32_t minAssociatedESVersion, es_event_type_t eventType, NSString *filename,
    void (^messageSetup)(std::shared_ptr<MockEndpointSecurityAPI>, es_message_t *),
    std::vector<uint8_t> (^RunSerializer)(std::shared_ptr<Serializer> serializer,
                                          const Message &msg)) {
  std::shared_ptr<MockEndpointSecurityAPI> mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsRetainReleaseMessage();
  std::shared_ptr<Serializer> bs = Protobuf::Create(mockESApi, nil);

  for (uint32_t cur_version = minAssociatedESVersion;
       cur_version <= MaxSupportedESMessageVersionForCurrentOS(); cur_version++) {
    if (cur_version == 3) {
      // Note: Version 3 was only in a macOS beta.
      continue;
    }

    es_file_t procFile = MakeESFile("foo", MakeStat(100));
    es_file_t ttyFile = MakeESFile("footty", MakeStat(200));
    es_process_t proc = MakeESProcess(&procFile, MakeAuditToken(12, 34), MakeAuditToken(56, 78));
    es_message_t esMsg = MakeESMessage(eventType, &proc);
    esMsg.process->tty = &ttyFile;
    esMsg.version = cur_version;

    messageSetup(mockESApi, &esMsg);

    std::vector<uint8_t> vec = RunSerializer(bs, Message(mockESApi, &esMsg));

    std::string protoStr(vec.begin(), vec.end());

    ::pbv1::SantaMessage santaMsg;
    XCTAssertTrue(santaMsg.ParseFromString(protoStr));
    std::string got = ConvertMessageToJsonString(santaMsg);
    NSString *wantData = LoadTestJson(filename, esMsg.version);

    XCTAssertEqualObjects([NSString stringWithUTF8String:got.c_str()], wantData);
  }

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

@implementation ProtobufTest

- (void)setUp {
  self.mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([self.mockConfigurator configurator]).andReturn(self.mockConfigurator);
  OCMStub([self.mockConfigurator clientMode]).andReturn(SNTClientModeLockdown);
  OCMStub([self.mockConfigurator enableMachineIDDecoration]).andReturn(YES);
  OCMStub([self.mockConfigurator machineID]).andReturn(@"my_machine_id");

  self.testCachedDecision = [[SNTCachedDecision alloc] init];
  self.testCachedDecision.decision = SNTEventStateAllowBinary;
  self.testCachedDecision.decisionExtra = @"extra!";
  self.testCachedDecision.sha256 = @"1234_file_hash";
  self.testCachedDecision.quarantineURL = @"google.com";
  self.testCachedDecision.certSHA256 = @"5678_cert_hash";
  self.testCachedDecision.decisionClientMode = SNTClientModeLockdown;
  self.testCachedDecision.entitlements = @{
    @"key_with_str_val" : @"bar",
    @"key_with_num_val" : @(1234),
    @"key_with_date_val" : [NSDate dateWithTimeIntervalSince1970:1699376402],
    @"key_with_data_val" : [@"Hello World" dataUsingEncoding:NSUTF8StringEncoding],
    @"key_with_arr_val" : @[ @"v1", @"v2", @"v3" ],
    @"key_with_arr_val_nested" : @[ @"v1", @"v2", @"v3", @[ @"nv1", @"nv2" ] ],
    @"key_with_arr_val_multitype" :
        @[ @"v1", @"v2", @"v3", @(123), [NSDate dateWithTimeIntervalSince1970:1699376402] ],
    @"key_with_dict_val" : @{@"k1" : @"v1", @"k2" : @"v2"},
    @"key_with_dict_val_nested" : @{
      @"k1" : @"v1",
      @"k2" : @"v2",
      @"k3" : @{@"nk1" : @"nv1", @"nk2" : [NSDate dateWithTimeIntervalSince1970:1699376402]}
    },
  };

  self.mockDecisionCache = OCMClassMock([SNTDecisionCache class]);
  OCMStub([self.mockDecisionCache sharedCache]).andReturn(self.mockDecisionCache);
  OCMStub([self.mockDecisionCache resetTimestampForCachedDecision:{}])
      .ignoringNonObjectArgs()
      .andReturn(self.testCachedDecision);
}

- (void)tearDown {
  [self.mockConfigurator stopMocking];
  [self.mockDecisionCache stopMocking];
}

- (void)serializeAndCheckEvent:(es_event_type_t)eventType
                       variant:(NSString *)variant
      shouldHandleMessageSetup:(bool (^)(std::shared_ptr<MockEndpointSecurityAPI>,
                                         es_message_t *))shouldHandleMessageSetup {
  SerializeAndCheck(eventType, shouldHandleMessageSetup, self.mockDecisionCache, false, variant);
}

- (void)serializeAndCheckEvent:(es_event_type_t)eventType
                  messageSetup:(void (^)(std::shared_ptr<MockEndpointSecurityAPI>,
                                         es_message_t *))messageSetup
                          json:(BOOL)json {
  SerializeAndCheck(eventType, messageSetup, self.mockDecisionCache, (bool)json, nil);
}

- (void)serializeAndCheckEvent:(es_event_type_t)eventType
                  messageSetup:(void (^)(std::shared_ptr<MockEndpointSecurityAPI>,
                                         es_message_t *))messageSetup {
  SerializeAndCheck(eventType, messageSetup, self.mockDecisionCache, false, nil);
}

- (void)serializeAndCheckEvent:(es_event_type_t)eventType
                  messageSetup:(void (^)(std::shared_ptr<MockEndpointSecurityAPI>,
                                         es_message_t *))messageSetup
                       variant:(NSString *)variant {
  SerializeAndCheck(eventType, messageSetup, self.mockDecisionCache, false, variant);
}

- (void)testSerializeMessageClose {
  __block es_file_t file = MakeESFile("close_file", MakeStat(300));

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_CLOSE
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.close.modified = true;
                    esMsg->event.close.target = &file;
                  }];
}

- (void)testSerializeMessageExchange {
  __block es_file_t file1 = MakeESFile("exchange_file_1", MakeStat(300));
  __block es_file_t file2 = MakeESFile("exchange_file_1", MakeStat(400));

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.exchangedata.file1 = &file1;
                    esMsg->event.exchangedata.file2 = &file2;
                  }];
}

- (void)testGetDecisionEnum {
  std::map<SNTEventState, ::pbv1::Execution::Decision> stateToDecision = {
      {SNTEventStateUnknown, ::pbv1::Execution::DECISION_UNKNOWN},
      {SNTEventStateBundleBinary, ::pbv1::Execution::DECISION_UNKNOWN},
      {SNTEventStateBlockUnknown, ::pbv1::Execution::DECISION_DENY},
      {SNTEventStateBlockBinary, ::pbv1::Execution::DECISION_DENY},
      {SNTEventStateBlockCertificate, ::pbv1::Execution::DECISION_DENY},
      {SNTEventStateBlockScope, ::pbv1::Execution::DECISION_DENY},
      {SNTEventStateBlockTeamID, ::pbv1::Execution::DECISION_DENY},
      {SNTEventStateBlockLongPath, ::pbv1::Execution::DECISION_DENY},
      {SNTEventStateAllowUnknown, ::pbv1::Execution::DECISION_ALLOW},
      {SNTEventStateAllowBinary, ::pbv1::Execution::DECISION_ALLOW},
      {SNTEventStateAllowCertificate, ::pbv1::Execution::DECISION_ALLOW},
      {SNTEventStateAllowScope, ::pbv1::Execution::DECISION_ALLOW},
      {SNTEventStateAllowCompilerBinary, ::pbv1::Execution::DECISION_ALLOW_COMPILER},
      {SNTEventStateAllowCompilerCDHash, ::pbv1::Execution::DECISION_ALLOW_COMPILER},
      {SNTEventStateAllowCompilerSigningID, ::pbv1::Execution::DECISION_ALLOW_COMPILER},
      {SNTEventStateAllowTransitive, ::pbv1::Execution::DECISION_ALLOW},
      {SNTEventStateAllowPendingTransitive, ::pbv1::Execution::DECISION_ALLOW},
      {SNTEventStateAllowTeamID, ::pbv1::Execution::DECISION_ALLOW},
  };

  for (const auto &kv : stateToDecision) {
    XCTAssertEqual(santa::GetDecisionEnum(kv.first), kv.second, @"Bad decision for state: %llu",
                   kv.first);
  }
}

- (void)testGetReasonEnum {
  for (uint64_t i = 0; i <= 64; i++) {
    SNTEventState state = static_cast<SNTEventState>(i == 0 ? 0 : 1 << (i - 1));
    ::pbv1::Execution::Reason want = ::pbv1::Execution::REASON_UNKNOWN;
    switch (state) {
      case SNTEventStateUnknown: want = ::pbv1::Execution::REASON_UNKNOWN; break;
      case SNTEventStateBundleBinary: want = ::pbv1::Execution::REASON_UNKNOWN; break;
      case SNTEventStateBlockUnknown: want = ::pbv1::Execution::REASON_UNKNOWN; break;
      case SNTEventStateBlockBinary: want = ::pbv1::Execution::REASON_BINARY; break;
      case SNTEventStateBlockCertificate: want = ::pbv1::Execution::REASON_CERT; break;
      case SNTEventStateBlockScope: want = ::pbv1::Execution::REASON_SCOPE; break;
      case SNTEventStateBlockTeamID: want = ::pbv1::Execution::REASON_TEAM_ID; break;
      case SNTEventStateBlockLongPath: want = ::pbv1::Execution::REASON_LONG_PATH; break;
      case SNTEventStateBlockSigningID: want = ::pbv1::Execution::REASON_SIGNING_ID; break;
      case SNTEventStateBlockCDHash: want = ::pbv1::Execution::REASON_CDHASH; break;
      case SNTEventStateAllowUnknown: want = ::pbv1::Execution::REASON_UNKNOWN; break;
      case SNTEventStateAllowBinary: want = ::pbv1::Execution::REASON_BINARY; break;
      case SNTEventStateAllowCertificate: want = ::pbv1::Execution::REASON_CERT; break;
      case SNTEventStateAllowScope: want = ::pbv1::Execution::REASON_SCOPE; break;
      case SNTEventStateAllowCompilerBinary: want = ::pbv1::Execution::REASON_BINARY; break;
      case SNTEventStateAllowTransitive: want = ::pbv1::Execution::REASON_TRANSITIVE; break;
      case SNTEventStateAllowPendingTransitive:
        want = ::pbv1::Execution::REASON_PENDING_TRANSITIVE;
        break;
      case SNTEventStateAllowTeamID: want = ::pbv1::Execution::REASON_TEAM_ID; break;
      case SNTEventStateAllowSigningID: want = ::pbv1::Execution::REASON_SIGNING_ID; break;
      case SNTEventStateAllowCDHash: want = ::pbv1::Execution::REASON_CDHASH; break;
      case SNTEventStateAllowLocalBinary: want = ::pbv1::Execution::REASON_BINARY; break;
      case SNTEventStateAllowLocalSigningID: want = ::pbv1::Execution::REASON_SIGNING_ID; break;
      case SNTEventStateAllowCompilerSigningID: want = ::pbv1::Execution::REASON_SIGNING_ID; break;
      case SNTEventStateAllowCompilerCDHash: want = ::pbv1::Execution::REASON_CDHASH; break;
      case SNTEventStateBlock: want = ::pbv1::Execution::REASON_UNKNOWN; break;
      case SNTEventStateAllow: want = ::pbv1::Execution::REASON_UNKNOWN; break;
    }

    XCTAssertEqual(santa::GetReasonEnum(state), want, @"Bad reason for state: %llu (1 << %llu)",
                   state, i == 0 ? 0 : (i - 1));
  }
}

- (void)testGetModeEnum {
  std::map<SNTClientMode, ::pbv1::Execution::Mode> clientModeToExecMode = {
      {SNTClientModeUnknown, ::pbv1::Execution::MODE_UNKNOWN},
      {SNTClientModeMonitor, ::pbv1::Execution::MODE_MONITOR},
      {SNTClientModeLockdown, ::pbv1::Execution::MODE_LOCKDOWN},
      {SNTClientModeStandalone, ::pbv1::Execution::MODE_STANDALONE},
      {(SNTClientMode)123, ::pbv1::Execution::MODE_UNKNOWN},
  };

  for (const auto &kv : clientModeToExecMode) {
    XCTAssertEqual(santa::GetModeEnum(kv.first), kv.second, @"Bad mode for client mode: %ld",
                   kv.first);
  }
}

- (void)testGetFileDescriptorType {
  std::map<uint32_t, ::pbv1::FileDescriptor::FDType> fdtypeToEnumType = {
      {PROX_FDTYPE_ATALK, ::pbv1::FileDescriptor::FD_TYPE_ATALK},
      {PROX_FDTYPE_VNODE, ::pbv1::FileDescriptor::FD_TYPE_VNODE},
      {PROX_FDTYPE_SOCKET, ::pbv1::FileDescriptor::FD_TYPE_SOCKET},
      {PROX_FDTYPE_PSHM, ::pbv1::FileDescriptor::FD_TYPE_PSHM},
      {PROX_FDTYPE_PSEM, ::pbv1::FileDescriptor::FD_TYPE_PSEM},
      {PROX_FDTYPE_KQUEUE, ::pbv1::FileDescriptor::FD_TYPE_KQUEUE},
      {PROX_FDTYPE_PIPE, ::pbv1::FileDescriptor::FD_TYPE_PIPE},
      {PROX_FDTYPE_FSEVENTS, ::pbv1::FileDescriptor::FD_TYPE_FSEVENTS},
      {PROX_FDTYPE_NETPOLICY, ::pbv1::FileDescriptor::FD_TYPE_NETPOLICY},
      {10 /* PROX_FDTYPE_CHANNEL */, ::pbv1::FileDescriptor::FD_TYPE_CHANNEL},
      {11 /* PROX_FDTYPE_NEXUS */, ::pbv1::FileDescriptor::FD_TYPE_NEXUS},
  };

  for (const auto &kv : fdtypeToEnumType) {
    XCTAssertEqual(santa::GetFileDescriptorType(kv.first), kv.second,
                   @"Bad fd type name for fdtype: %u", kv.first);
  }
}

- (void)testSerializeMessageExec {
  es_file_t procFileTarget = MakeESFile("fooexec", MakeStat(300));
  __block es_process_t procTarget =
      MakeESProcess(&procFileTarget, MakeAuditToken(23, 45), MakeAuditToken(67, 89));
  __block es_file_t fileCwd = MakeESFile("cwd", MakeStat(400));
  __block es_file_t fileScript = MakeESFile("script.sh", MakeStat(500));
  __block es_fd_t fd1 = {.fd = 1, .fdtype = PROX_FDTYPE_VNODE};
  __block es_fd_t fd2 = {.fd = 2, .fdtype = PROX_FDTYPE_SOCKET};
  __block es_fd_t fd3 = {.fd = 3, .fdtype = PROX_FDTYPE_PIPE, .pipe = {.pipe_id = 123}};

  procTarget.codesigning_flags = CS_SIGNED | CS_HARD | CS_KILL;
  memset(procTarget.cdhash, 'A', sizeof(procTarget.cdhash));
  procTarget.signing_id = MakeESStringToken("my_signing_id");
  procTarget.team_id = MakeESStringToken("my_team_id");

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_EXEC
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.exec.target = &procTarget;
                    esMsg->event.exec.cwd = &fileCwd;
                    esMsg->event.exec.script = &fileScript;

                    // For version 5, simulate a "truncated" set of FDs
                    if (esMsg->version == 5) {
                      esMsg->event.exec.last_fd = 123;
                    } else {
                      esMsg->event.exec.last_fd = 3;
                    }

                    EXPECT_CALL(*mockESApi, ExecArgCount).WillOnce(testing::Return(3));
                    EXPECT_CALL(*mockESApi, ExecArg)
                        .WillOnce(testing::Return(MakeESStringToken("exec_path")))
                        .WillOnce(testing::Return(MakeESStringToken("-l")))
                        .WillOnce(testing::Return(MakeESStringToken("--foo")));

                    EXPECT_CALL(*mockESApi, ExecEnvCount).WillOnce(testing::Return(2));
                    EXPECT_CALL(*mockESApi, ExecEnv)
                        .WillOnce(testing::Return(
                            MakeESStringToken("ENV_PATH=/path/to/bin:/and/another")))
                        .WillOnce(testing::Return(MakeESStringToken("DEBUG=1")));

                    if (esMsg->version >= 4) {
                      EXPECT_CALL(*mockESApi, ExecFDCount).WillOnce(testing::Return(3));
                      EXPECT_CALL(*mockESApi, ExecFD)
                          .WillOnce(testing::Return(&fd1))
                          .WillOnce(testing::Return(&fd2))
                          .WillOnce(testing::Return(&fd3));
                    }
                  }];
}

- (void)testSerializeMessageExecJSON {
  es_file_t procFileTarget = MakeESFile("fooexec", MakeStat(300));
  __block es_process_t procTarget =
      MakeESProcess(&procFileTarget, MakeAuditToken(23, 45), MakeAuditToken(67, 89));
  __block es_file_t fileCwd = MakeESFile("cwd", MakeStat(400));
  __block es_file_t fileScript = MakeESFile("script.sh", MakeStat(500));
  __block es_fd_t fd1 = {.fd = 1, .fdtype = PROX_FDTYPE_VNODE};
  __block es_fd_t fd2 = {.fd = 2, .fdtype = PROX_FDTYPE_SOCKET};
  __block es_fd_t fd3 = {.fd = 3, .fdtype = PROX_FDTYPE_PIPE, .pipe = {.pipe_id = 123}};

  procTarget.codesigning_flags = CS_SIGNED | CS_HARD | CS_KILL;
  memset(procTarget.cdhash, 'A', sizeof(procTarget.cdhash));
  procTarget.signing_id = MakeESStringToken("my_signing_id");
  procTarget.team_id = MakeESStringToken("my_team_id");

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_EXEC
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.exec.target = &procTarget;
                    esMsg->event.exec.cwd = &fileCwd;
                    esMsg->event.exec.script = &fileScript;

                    // For version 5, simulate a "truncated" set of FDs
                    if (esMsg->version == 5) {
                      esMsg->event.exec.last_fd = 123;
                    } else {
                      esMsg->event.exec.last_fd = 3;
                    }

                    EXPECT_CALL(*mockESApi, ExecArgCount).WillOnce(testing::Return(3));
                    EXPECT_CALL(*mockESApi, ExecArg)
                        .WillOnce(testing::Return(MakeESStringToken("exec_path")))
                        .WillOnce(testing::Return(MakeESStringToken("-l")))
                        .WillOnce(testing::Return(MakeESStringToken("--foo")));

                    EXPECT_CALL(*mockESApi, ExecEnvCount).WillOnce(testing::Return(2));
                    EXPECT_CALL(*mockESApi, ExecEnv)
                        .WillOnce(testing::Return(
                            MakeESStringToken("ENV_PATH=/path/to/bin:/and/another")))
                        .WillOnce(testing::Return(MakeESStringToken("DEBUG=1")));

                    if (esMsg->version >= 4) {
                      EXPECT_CALL(*mockESApi, ExecFDCount).WillOnce(testing::Return(3));
                      EXPECT_CALL(*mockESApi, ExecFD)
                          .WillOnce(testing::Return(&fd1))
                          .WillOnce(testing::Return(&fd2))
                          .WillOnce(testing::Return(&fd3));
                    }
                  }
                          json:YES];
}

- (void)testEncodeEntitlements {
  int kMaxEncodeObjectEntries = 64;  // From Protobuf.mm
  // Test basic encoding without filtered entitlements
  {
    ::pbv1::Execution pbExec;

    SNTCachedDecision *cd = [[SNTCachedDecision alloc] init];
    cd.entitlements = @{@"com.northpolesec.test" : @(YES)};

    XCTAssertEqual(0, pbExec.entitlement_info().entitlements_size());
    XCTAssertFalse(cd.entitlementsFiltered);
    XCTAssertEqual(1, cd.entitlements.count);

    EncodeEntitlements(&pbExec, cd);

    XCTAssertEqual(1, pbExec.entitlement_info().entitlements_size());
    XCTAssertTrue(pbExec.entitlement_info().has_entitlements_filtered());
    XCTAssertFalse(pbExec.entitlement_info().entitlements_filtered());
  }

  // Test basic encoding with filtered entitlements
  {
    ::pbv1::Execution pbExec;

    SNTCachedDecision *cd = [[SNTCachedDecision alloc] init];
    cd.entitlements = @{@"com.northpolesec.test" : @(YES), @"com.northpolesec.test2" : @(NO)};
    cd.entitlementsFiltered = YES;

    XCTAssertEqual(0, pbExec.entitlement_info().entitlements_size());
    XCTAssertTrue(cd.entitlementsFiltered);
    XCTAssertEqual(2, cd.entitlements.count);

    EncodeEntitlements(&pbExec, cd);

    XCTAssertEqual(2, pbExec.entitlement_info().entitlements_size());
    XCTAssertTrue(pbExec.entitlement_info().has_entitlements_filtered());
    XCTAssertTrue(pbExec.entitlement_info().entitlements_filtered());
  }

  // Test max number of entitlements logged
  // When entitlements are clipped, `entitlements_filtered` is set to true
  {
    ::pbv1::Execution pbExec;
    NSMutableDictionary *ents = [NSMutableDictionary dictionary];

    for (int i = 0; i < 100; i++) {
      ents[[NSString stringWithFormat:@"k%d", i]] = @(i);
    }

    SNTCachedDecision *cd = [[SNTCachedDecision alloc] init];
    cd.entitlements = ents;

    XCTAssertEqual(0, pbExec.entitlement_info().entitlements_size());
    XCTAssertFalse(cd.entitlementsFiltered);
    XCTAssertGreaterThan(cd.entitlements.count, kMaxEncodeObjectEntries);

    EncodeEntitlements(&pbExec, cd);

    XCTAssertEqual(kMaxEncodeObjectEntries, pbExec.entitlement_info().entitlements_size());
    XCTAssertTrue(pbExec.entitlement_info().has_entitlements_filtered());
    XCTAssertTrue(pbExec.entitlement_info().entitlements_filtered());
  }
}

- (void)testSerializeMessageExit {
  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_EXIT
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.exit.stat = W_EXITCODE(1, 0);
                  }];
}

- (void)testEncodeExitStatus {
  {
    ::pbv1::Exit pbExit;
    EncodeExitStatus(&pbExit, W_EXITCODE(1, 0));
    XCTAssertTrue(pbExit.has_exited());
    XCTAssertEqual(1, pbExit.exited().exit_status());
  }

  {
    ::pbv1::Exit pbExit;
    EncodeExitStatus(&pbExit, W_EXITCODE(2, SIGUSR1));
    XCTAssertTrue(pbExit.has_signaled());
    XCTAssertEqual(SIGUSR1, pbExit.signaled().signal());
  }

  {
    ::pbv1::Exit pbExit;
    EncodeExitStatus(&pbExit, W_STOPCODE(SIGSTOP));
    XCTAssertTrue(pbExit.has_stopped());
    XCTAssertEqual(SIGSTOP, pbExit.stopped().signal());
  }
}

- (void)testSerializeMessageFork {
  __block es_file_t procFileChild = MakeESFile("foo_child", MakeStat(300));
  __block es_file_t ttyFileChild = MakeESFile("footty", MakeStat(400));
  __block es_process_t procChild =
      MakeESProcess(&procFileChild, MakeAuditToken(12, 34), MakeAuditToken(56, 78));
  procChild.tty = &ttyFileChild;

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_FORK
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.fork.child = &procChild;
                  }];
}

- (void)testSerializeMessageLink {
  __block es_file_t fileSource = MakeESFile("source", MakeStat(300));
  __block es_file_t fileTargetDir = MakeESFile("target_dir");
  es_string_token_t targetTok = MakeESStringToken("target_file");

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_LINK
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.link.source = &fileSource;
                    esMsg->event.link.target_dir = &fileTargetDir;
                    esMsg->event.link.target_filename = targetTok;
                  }];
}

- (void)testSerializeMessageRename {
  __block es_file_t fileSource = MakeESFile("source", MakeStat(300));
  __block es_file_t fileTargetDir = MakeESFile("target_dir");
  es_string_token_t targetTok = MakeESStringToken("target_file");

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_RENAME
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.rename.source = &fileSource;
                    // Test new and existing destination types
                    if (esMsg->version == 4) {
                      esMsg->event.rename.destination.existing_file = &fileTargetDir;
                      esMsg->event.rename.destination_type = ES_DESTINATION_TYPE_EXISTING_FILE;
                    } else {
                      esMsg->event.rename.destination.new_path.dir = &fileTargetDir;
                      esMsg->event.rename.destination.new_path.filename = targetTok;
                      esMsg->event.rename.destination_type = ES_DESTINATION_TYPE_NEW_PATH;
                    }
                  }];
}

- (void)testSerializeMessageUnlink {
  __block es_file_t fileTarget = MakeESFile("unlink_file", MakeStat(300));
  __block es_file_t fileTargetParent = MakeESFile("unlink_file_parent", MakeStat(400));

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_UNLINK
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.unlink.target = &fileTarget;
                    esMsg->event.unlink.parent_dir = &fileTargetParent;
                  }];
}

- (void)testSerializeMessageCodesigningInvalidated {
  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                  }
                          json:NO];
}

- (void)testSerializeMessageClone {
  __block es_file_t fileSource = MakeESFile("source", MakeStat(300));
  __block es_file_t fileTargetDir = MakeESFile("target_dir");
  es_string_token_t targetTok = MakeESStringToken("target_file");

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_CLONE
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.clone.source = &fileSource;
                    esMsg->event.clone.target_dir = &fileTargetDir;
                    esMsg->event.clone.target_name = targetTok;
                  }];
}

- (void)testSerializeMessageCopyfile {
  __block es_file_t fileSource = MakeESFile("source", MakeStat(300));
  __block es_file_t fileTargetDir = MakeESFile("target_dir");
  es_string_token_t targetTok = MakeESStringToken("target_file");

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_COPYFILE
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.copyfile.source = &fileSource;
                    esMsg->event.copyfile.target_dir = &fileTargetDir;
                    esMsg->event.copyfile.target_name = targetTok;
                    esMsg->event.copyfile.mode = 0x123;
                    esMsg->event.copyfile.flags = 0x456;

                    // For one of the versions don't set the target file to
                    // simulate output when a target doesn't already exist
                    if (esMsg->version == 7) {
                      esMsg->event.copyfile.target_file = NULL;
                    } else {
                      esMsg->event.copyfile.target_file = &fileTargetDir;
                    }
                  }];
}

- (void)testSerializeMessageLoginWindowSessionLogin {
  __block es_event_lw_session_login_t lwLogin = {
      .username = MakeESStringToken("daemon"),
      .graphical_session_id = 123,
  };

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.lw_session_login = &lwLogin;
                  }];
}

- (void)testSerializeMessageLoginWindowSessionLogout {
  __block es_event_lw_session_logout_t lwLogout = {
      .username = MakeESStringToken("daemon"),
      .graphical_session_id = 123,
  };

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.lw_session_logout = &lwLogout;
                  }];
}

- (void)testSerializeMessageLoginWindowSessionLock {
  __block es_event_lw_session_lock_t lwLock = {
      .username = MakeESStringToken("daemon"),
      .graphical_session_id = 123,
  };

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.lw_session_lock = &lwLock;
                  }];
}

- (void)testSerializeMessageLoginWindowSessionUnlock {
  __block es_event_lw_session_unlock_t lwUnlock = {
      .username = MakeESStringToken("daemon"),
      .graphical_session_id = 123,
  };

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.lw_session_unlock = &lwUnlock;
                  }];
}

- (void)testSerializeMessageScreensharingAttach {
  __block es_event_screensharing_attach_t attach = {
      .success = true,
      .source_address_type = ES_ADDRESS_TYPE_IPV6,
      .source_address = MakeESStringToken("::1"),
      .viewer_appleid = MakeESStringToken("foo@example.com"),
      .authentication_type = MakeESStringToken("idk"),
      .authentication_username = MakeESStringToken("my_auth_user"),
      .session_username = MakeESStringToken("my_session_user"),
      .existing_session = true,
      .graphical_session_id = 123,
  };

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.screensharing_attach = &attach;
                  }];

  attach.source_address_type = (es_address_type_t)1234;
  attach.source_address = MakeESStringToken(NULL);
  attach.viewer_appleid = MakeESStringToken(NULL);
  attach.authentication_type = MakeESStringToken(NULL);
  attach.authentication_username = MakeESStringToken(NULL);
  attach.session_username = MakeESStringToken(NULL);

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.screensharing_attach = &attach;
                  }
                       variant:@"unset_fields"];
}

- (void)testSerializeMessageScreensharingDetach {
  __block es_event_screensharing_detach_t detach = {
      .source_address_type = ES_ADDRESS_TYPE_IPV4,
      .source_address = MakeESStringToken("1.2.3.4"),
      .viewer_appleid = MakeESStringToken("foo@example.com"),
      .graphical_session_id = 123,
  };

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.screensharing_detach = &detach;
                  }];
}

- (void)testSerializeMessageOpenSSHLogin {
  __block es_event_openssh_login_t sshLogin = {.success = true,
                                               .result_type = ES_OPENSSH_AUTH_SUCCESS,
                                               .source_address_type = ES_ADDRESS_TYPE_IPV4,
                                               .source_address = MakeESStringToken("1.2.3.4"),
                                               .username = MakeESStringToken("foo_user"),
                                               .has_uid = true,
                                               .uid = {
                                                   .uid = 12345,
                                               }};

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.openssh_login = &sshLogin;
                  }];

  sshLogin.success = false;
  sshLogin.result_type = ES_OPENSSH_AUTH_FAIL_HOSTBASED;
  sshLogin.source_address_type = ES_ADDRESS_TYPE_IPV6;
  sshLogin.source_address = MakeESStringToken("::1");
  sshLogin.has_uid = false;
  sshLogin.username = MakeESStringToken(NULL);

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.openssh_login = &sshLogin;
                  }
                       variant:@"failed_attempt"];
}

- (void)testSerializeMessageOpenSSHLogout {
  __block es_event_openssh_logout_t sshLogout = {
      .source_address_type = ES_ADDRESS_TYPE_IPV4,
      .source_address = MakeESStringToken("1.2.3.4"),
      .username = MakeESStringToken("foo_user"),
      .uid = 12345,
  };

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.openssh_logout = &sshLogout;
                  }];
}

- (void)testSerializeMessageLoginLogin {
  __block es_event_login_login_t login = {.success = true,
                                          .failure_message = MakeESStringToken(NULL),
                                          .username = MakeESStringToken("asdf"),
                                          .has_uid = true,
                                          .uid = {
                                              .uid = 321,
                                          }};

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.login_login = &login;
                  }];

  login.success = false;
  login.failure_message = MakeESStringToken("my|failure");
  login.has_uid = false;

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.login_login = &login;
                  }
                       variant:@"failed_attempt"];
}

- (void)testGetSocketAddressType {
  std::map<es_address_type_t, ::pbv1::SocketAddress::Type> esToSantaAddrType = {
      {ES_ADDRESS_TYPE_NONE, ::pbv1::SocketAddress::TYPE_NONE},
      {ES_ADDRESS_TYPE_IPV4, ::pbv1::SocketAddress::TYPE_IPV4},
      {ES_ADDRESS_TYPE_IPV6, ::pbv1::SocketAddress::TYPE_IPV6},
      {ES_ADDRESS_TYPE_NAMED_SOCKET, ::pbv1::SocketAddress::TYPE_NAMED_SOCKET},
      {(es_address_type_t)1234, ::pbv1::SocketAddress::TYPE_UNKNOWN},
  };

  for (const auto &kv : esToSantaAddrType) {
    XCTAssertEqual(santa::GetSocketAddressType(kv.first), kv.second);
  }
}

- (void)testGetOpenSSHLoginResultType {
  std::map<es_openssh_login_result_type_t, ::pbv1::OpenSSHLogin::Result> esToSantaOpenSSHResultType{
      {ES_OPENSSH_LOGIN_EXCEED_MAXTRIES, ::pbv1::OpenSSHLogin::RESULT_LOGIN_EXCEED_MAXTRIES},
      {ES_OPENSSH_LOGIN_ROOT_DENIED, ::pbv1::OpenSSHLogin::RESULT_LOGIN_ROOT_DENIED},
      {ES_OPENSSH_AUTH_SUCCESS, ::pbv1::OpenSSHLogin::RESULT_AUTH_SUCCESS},
      {ES_OPENSSH_AUTH_FAIL_NONE, ::pbv1::OpenSSHLogin::RESULT_AUTH_FAIL_NONE},
      {ES_OPENSSH_AUTH_FAIL_PASSWD, ::pbv1::OpenSSHLogin::RESULT_AUTH_FAIL_PASSWD},
      {ES_OPENSSH_AUTH_FAIL_KBDINT, ::pbv1::OpenSSHLogin::RESULT_AUTH_FAIL_KBDINT},
      {ES_OPENSSH_AUTH_FAIL_PUBKEY, ::pbv1::OpenSSHLogin::RESULT_AUTH_FAIL_PUBKEY},
      {ES_OPENSSH_AUTH_FAIL_HOSTBASED, ::pbv1::OpenSSHLogin::RESULT_AUTH_FAIL_HOSTBASED},
      {ES_OPENSSH_AUTH_FAIL_GSSAPI, ::pbv1::OpenSSHLogin::RESULT_AUTH_FAIL_GSSAPI},
      {ES_OPENSSH_INVALID_USER, ::pbv1::OpenSSHLogin::RESULT_INVALID_USER},
      {(es_openssh_login_result_type_t)1234, ::pbv1::OpenSSHLogin::RESULT_UNKNOWN},
  };

  for (const auto &kv : esToSantaOpenSSHResultType) {
    XCTAssertEqual(santa::GetOpenSSHLoginResultType(kv.first), kv.second);
  }
}

- (void)testSerializeMessageAuthenticationOD {
  es_file_t instigatorProcTarget = MakeESFile("foo", MakeStat(300));
  __block es_process_t instigatorProc =
      MakeESProcess(&instigatorProcTarget, MakeAuditToken(23, 45), MakeAuditToken(67, 89));
  __block es_event_authentication_od_t authenticationOD = {
      .instigator = &instigatorProc,
      .record_type = MakeESStringToken("my_rec_type"),
      .record_name = MakeESStringToken("my_rec_name"),
      .node_name = MakeESStringToken("my_node_name"),
      .db_path = MakeESStringToken("my_db_path"),
#if HAVE_MACOS_15
      .instigator_token = MakeAuditToken(98, 76),
#endif
  };

  __block es_event_authentication_t authenticationEvent = {
      .success = true,
      .type = ES_AUTHENTICATION_TYPE_OD,
      .data = {.od = &authenticationOD},
  };

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_AUTHENTICATION
                       variant:@"od"
      shouldHandleMessageSetup:^bool(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                     es_message_t *esMsg) {
        esMsg->event.authentication = &authenticationEvent;
        return true;
      }];

  if (@available(macOS 15.0, *)) {
    authenticationOD.instigator = nullptr;
    [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_AUTHENTICATION
                         variant:@"od_missing_auth_instigator"
        shouldHandleMessageSetup:^bool(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                       es_message_t *esMsg) {
          if (esMsg->version < 8) {
            return false;
          }

          esMsg->event.authentication = &authenticationEvent;

          return true;
        }];
  }
}

- (void)testGetAuthenticationTouchIDMode {
  std::map<es_touchid_mode_t, ::pbv1::AuthenticationTouchID::Mode> esToSantaTouchIDMode{
      {ES_TOUCHID_MODE_VERIFICATION, ::pbv1::AuthenticationTouchID::MODE_VERIFICATION},
      {ES_TOUCHID_MODE_IDENTIFICATION, ::pbv1::AuthenticationTouchID::MODE_IDENTIFICATION},
      {(es_touchid_mode_t)1234, ::pbv1::AuthenticationTouchID::MODE_UNKNOWN},
  };

  for (const auto &kv : esToSantaTouchIDMode) {
    XCTAssertEqual(santa::GetAuthenticationTouchIDMode(kv.first), kv.second);
  }
}

- (void)testSerializeMessageAuthenticationTouchID {
  es_file_t instigatorProcTarget = MakeESFile("foo", MakeStat(300));
  __block es_process_t instigatorProc =
      MakeESProcess(&instigatorProcTarget, MakeAuditToken(23, 45), MakeAuditToken(67, 89));
  __block es_event_authentication_touchid_t authenticationTouchID = {
      .instigator = &instigatorProc,
      .touchid_mode = ES_TOUCHID_MODE_VERIFICATION,
      .has_uid = true,
      .uid =
          {
              .uid = NOBODY_UID,
          },
#if HAVE_MACOS_15
      .instigator_token = MakeAuditToken(98, 76),
#endif
  };

  __block es_event_authentication_t authenticationEvent = {
      .success = true,
      .type = ES_AUTHENTICATION_TYPE_TOUCHID,
      .data = {.touchid = &authenticationTouchID},
  };

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_AUTHENTICATION
                       variant:@"touchid"
      shouldHandleMessageSetup:^bool(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                     es_message_t *esMsg) {
        esMsg->event.authentication = &authenticationEvent;
        return true;
      }];

  authenticationTouchID.touchid_mode = ES_TOUCHID_MODE_IDENTIFICATION;
  authenticationTouchID.has_uid = false;
  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_AUTHENTICATION
                       variant:@"touchid_no_uid"
      shouldHandleMessageSetup:^bool(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                     es_message_t *esMsg) {
        esMsg->event.authentication = &authenticationEvent;
        return true;
      }];

  if (@available(macOS 15.0, *)) {
    authenticationTouchID.instigator = nullptr;
    [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_AUTHENTICATION
                         variant:@"touchid_missing_auth_instigator"
        shouldHandleMessageSetup:^bool(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                       es_message_t *esMsg) {
          if (esMsg->version < 8) {
            return false;
          }

          esMsg->event.authentication = &authenticationEvent;

          return true;
        }];
  }
}

- (void)testSerializeMessageAuthenticationToken {
  es_file_t instigatorProcTarget = MakeESFile("foo", MakeStat(300));
  __block es_process_t instigatorProc =
      MakeESProcess(&instigatorProcTarget, MakeAuditToken(23, 45), MakeAuditToken(67, 89));
  __block es_event_authentication_token_t authenticationToken = {
      .instigator = &instigatorProc,
      .pubkey_hash = MakeESStringToken("my_pubkey_hash"),
      .token_id = MakeESStringToken("my_token_id"),
      .kerberos_principal = MakeESStringToken("my_kerberos_principal"),
#if HAVE_MACOS_15
      .instigator_token = MakeAuditToken(98, 76),
#endif
  };

  __block es_event_authentication_t authenticationEvent = {
      .success = true,
      .type = ES_AUTHENTICATION_TYPE_TOKEN,
      .data = {.token = &authenticationToken},
  };

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_AUTHENTICATION
                       variant:@"token"
      shouldHandleMessageSetup:^bool(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                     es_message_t *esMsg) {
        esMsg->event.authentication = &authenticationEvent;
        return true;
      }];

  if (@available(macOS 15.0, *)) {
    authenticationToken.instigator = nullptr;
    [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_AUTHENTICATION
                         variant:@"token_missing_auth_instigator"
        shouldHandleMessageSetup:^bool(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                       es_message_t *esMsg) {
          if (esMsg->version < 8) {
            return false;
          }

          esMsg->event.authentication = &authenticationEvent;

          return true;
        }];
  }
}

- (void)testGetAuthenticationAutoUnlockType {
  std::map<es_auto_unlock_type_t, ::pbv1::AuthenticationAutoUnlock::Type> esToSantaAutoUnlockType{
      {ES_AUTO_UNLOCK_MACHINE_UNLOCK, ::pbv1::AuthenticationAutoUnlock::TYPE_MACHINE_UNLOCK},
      {ES_AUTO_UNLOCK_AUTH_PROMPT, ::pbv1::AuthenticationAutoUnlock::TYPE_AUTH_PROMPT},
      {(es_auto_unlock_type_t)1234, ::pbv1::AuthenticationAutoUnlock::TYPE_UNKNOWN},
  };

  for (const auto &kv : esToSantaAutoUnlockType) {
    XCTAssertEqual(santa::GetAuthenticationAutoUnlockType(kv.first), kv.second);
  }
}

- (void)testSerializeMessageAuthenticationAutoUnlock {
  __block es_event_authentication_auto_unlock_t authenticationAutoUnlock = {
      .username = MakeESStringToken("nobody"),
      .type = ES_AUTO_UNLOCK_MACHINE_UNLOCK,
  };

  __block es_event_authentication_t authenticationEvent = {
      .success = true,
      .type = ES_AUTHENTICATION_TYPE_AUTO_UNLOCK,
      .data = {.auto_unlock = &authenticationAutoUnlock},
  };

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_AUTHENTICATION
                       variant:@"auto_unlock"
      shouldHandleMessageSetup:^bool(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                     es_message_t *esMsg) {
        esMsg->event.authentication = &authenticationEvent;
        return true;
      }];

  authenticationAutoUnlock.username = MakeESStringToken("ThisUserShouldNotEverExistForTests");
  authenticationAutoUnlock.type = ES_AUTO_UNLOCK_AUTH_PROMPT;
  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_AUTHENTICATION
                       variant:@"auto_unlock_missing_uid"
      shouldHandleMessageSetup:^bool(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                     es_message_t *esMsg) {
        esMsg->event.authentication = &authenticationEvent;
        return true;
      }];
}

- (void)testGetBTMLaunchItemType {
  std::map<es_btm_item_type_t, ::pbv1::LaunchItem::ItemType> launchItemTypeToEnum{
      {ES_BTM_ITEM_TYPE_USER_ITEM, ::pbv1::LaunchItem::ITEM_TYPE_USER_ITEM},
      {ES_BTM_ITEM_TYPE_APP, ::pbv1::LaunchItem::ITEM_TYPE_APP},
      {ES_BTM_ITEM_TYPE_LOGIN_ITEM, ::pbv1::LaunchItem::ITEM_TYPE_LOGIN_ITEM},
      {ES_BTM_ITEM_TYPE_AGENT, ::pbv1::LaunchItem::ITEM_TYPE_AGENT},
      {ES_BTM_ITEM_TYPE_DAEMON, ::pbv1::LaunchItem::ITEM_TYPE_DAEMON},
      {(es_btm_item_type_t)1234, ::pbv1::LaunchItem::ITEM_TYPE_UNKNOWN},
  };

  for (const auto &kv : launchItemTypeToEnum) {
    XCTAssertEqual(santa::GetBTMLaunchItemType(kv.first), kv.second);
  }
}

- (void)testSerializeMessageLaunchItemAdd {
  es_file_t instigatorProcFile = MakeESFile("fooInst");
  es_process_t instigatorProc =
      MakeESProcess(&instigatorProcFile, MakeAuditToken(21, 43), MakeAuditToken(65, 87));

  es_file_t instigatorAppFile = MakeESFile("fooApp");
  es_process_t instigatorApp =
      MakeESProcess(&instigatorAppFile, MakeAuditToken(22, 33), MakeAuditToken(44, 55));
#if HAVE_MACOS_15
  audit_token_t tokInst = MakeAuditToken(654, 321);
  audit_token_t tokApp = MakeAuditToken(111, 222);
#endif

  es_btm_launch_item_t item = {
      .item_type = ES_BTM_ITEM_TYPE_USER_ITEM,
      .legacy = true,
      .managed = false,
      .uid = (uid_t)-2,
      .item_url = MakeESStringToken("/absolute/path/item"),
      .app_url = MakeESStringToken("/absolute/path/app"),
  };

  __block es_event_btm_launch_item_add_t launchItem = {
      .instigator = &instigatorProc,
      .app = &instigatorApp,
      .item = &item,
      .executable_path = MakeESStringToken("exec_path"),
#if HAVE_MACOS_15
      .instigator_token = &tokInst,
      .app_token = &tokApp,
#endif
  };

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.btm_launch_item_add = &launchItem;
                  }];

  launchItem.instigator = NULL;
  item.item_url = MakeESStringToken("relative/path");
  item.app_url = MakeESStringToken("file:///path/url");
  item.item_type = ES_BTM_ITEM_TYPE_DAEMON;

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.btm_launch_item_add = &launchItem;
                  }
                       variant:@"relative"];

  item.app_url = MakeESStringToken(NULL);
  item.item_type = ES_BTM_ITEM_TYPE_AGENT;
  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.btm_launch_item_add = &launchItem;
                  }
                       variant:@"relative_null_app"];

  launchItem.app = NULL;
  launchItem.instigator = &instigatorProc;
  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.btm_launch_item_add = &launchItem;
                  }
                       variant:@"null_app"];
}

- (void)testSerializeMessageLaunchItemRemove {
  es_file_t instigatorProcFile = MakeESFile("fooInst");
  es_process_t instigatorProc =
      MakeESProcess(&instigatorProcFile, MakeAuditToken(21, 43), MakeAuditToken(65, 87));

  es_file_t instigatorAppFile = MakeESFile("fooApp");
  es_process_t instigatorApp =
      MakeESProcess(&instigatorAppFile, MakeAuditToken(22, 33), MakeAuditToken(66, 77));
#if HAVE_MACOS_15
  audit_token_t tokInst = MakeAuditToken(654, 321);
  audit_token_t tokApp = MakeAuditToken(111, 222);
#endif

  es_btm_launch_item_t item = {
      .item_type = ES_BTM_ITEM_TYPE_USER_ITEM,
      .legacy = true,
      .managed = false,
      .uid = (uid_t)-2,
      .item_url = MakeESStringToken("/absolute/path/item"),
      .app_url = MakeESStringToken("/absolute/path/app"),
  };

  __block es_event_btm_launch_item_remove_t launchItem = {
      .instigator = &instigatorProc,
      .app = &instigatorApp,
      .item = &item,
#if HAVE_MACOS_15
      .instigator_token = &tokInst,
      .app_token = &tokApp,
#endif
  };

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.btm_launch_item_remove = &launchItem;
                  }];

  launchItem.instigator = NULL;
  item.item_url = MakeESStringToken("relative/path");
  item.app_url = MakeESStringToken("file:///path/url");
  item.item_type = ES_BTM_ITEM_TYPE_DAEMON;

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.btm_launch_item_remove = &launchItem;
                  }
                       variant:@"relative"];

  launchItem.app = NULL;
  item.app_url = MakeESStringToken(NULL);
  item.item_type = ES_BTM_ITEM_TYPE_AGENT;
  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.btm_launch_item_remove = &launchItem;
                  }
                       variant:@"relative_null_app"];
}

- (void)testSerializeMessageXProtectDetected {
  __block es_event_xp_malware_detected_t xp = {
      .signature_version = MakeESStringToken("sig_ver"),
      .malware_identifier = MakeESStringToken("mal_id"),
      .incident_identifier = MakeESStringToken("inc_id"),
      .detected_path = MakeESStringToken("/detected/path"),
  };

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.xp_malware_detected = &xp;
                  }];
}

- (void)testSerializeMessageXProtectRemediated {
  audit_token_t tok = MakeAuditToken(99, 88);
  __block es_event_xp_malware_remediated_t xp = {
      .signature_version = MakeESStringToken("sig_ver"),
      .malware_identifier = MakeESStringToken("mal_id"),
      .incident_identifier = MakeESStringToken("inc_id"),
      .action_type = MakeESStringToken("act_type"),
      .success = true,
      .result_description = MakeESStringToken("res_desc"),
      .remediated_path = MakeESStringToken("/rem/path"),
      .remediated_process_audit_token = &tok,
  };

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.xp_malware_remediated = &xp;
                  }];

  xp.remediated_process_audit_token = NULL;
  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.xp_malware_remediated = &xp;
                  }
                       variant:@"null_token"];
}

#if HAVE_MACOS_15

- (void)testSerializeMessageGatekeeperOverride {
  es_file_t targetFile = MakeESFile("foo");
  es_sha256_t fileHash;
  std::fill(std::begin(fileHash), std::end(fileHash), 'A');

  es_signed_file_info_t signingInfo = {
      .signing_id = MakeESStringToken("com.my.sid"),
      .team_id = MakeESStringToken("mytid"),
  };
  std::fill(std::begin(signingInfo.cdhash), std::end(signingInfo.cdhash), 'B');

  __block es_event_gatekeeper_user_override_t gatekeeper = {
      .file_type = ES_GATEKEEPER_USER_OVERRIDE_FILE_TYPE_FILE,
      .file = {.file = &targetFile},
      .sha256 = &fileHash,
      .signing_info = &signingInfo,
  };

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.gatekeeper_user_override = &gatekeeper;
                  }];

  gatekeeper.file_type = ES_GATEKEEPER_USER_OVERRIDE_FILE_TYPE_PATH;
  gatekeeper.file.file_path = MakeESStringToken("foo_path");
  gatekeeper.signing_info = NULL;
  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.gatekeeper_user_override = &gatekeeper;
                  }
                       variant:@"path_only"];
}

#endif  // HAVE_MACOS_15

#if HAVE_MACOS_15_4

- (void)testGetTCCIdentityType {
  std::map<es_tcc_identity_type_t, ::pbv1::TCCModification::IdentityType> identityTypeToString{
      {ES_TCC_IDENTITY_TYPE_BUNDLE_ID, ::pbv1::TCCModification::IDENTITY_TYPE_BUNDLE_ID},
      {ES_TCC_IDENTITY_TYPE_EXECUTABLE_PATH,
       ::pbv1::TCCModification::IDENTITY_TYPE_EXECUTABLE_PATH},
      {ES_TCC_IDENTITY_TYPE_POLICY_ID, ::pbv1::TCCModification::IDENTITY_TYPE_POLICY_ID},
      {ES_TCC_IDENTITY_TYPE_FILE_PROVIDER_DOMAIN_ID,
       ::pbv1::TCCModification::IDENTITY_TYPE_FILE_PROVIDER_DOMAIN_ID},
      {(es_tcc_identity_type_t)1234, ::pbv1::TCCModification::IDENTITY_TYPE_UNKNOWN},
  };

  for (const auto &kv : identityTypeToString) {
    XCTAssertEqual(santa::GetTCCIdentityType(kv.first), kv.second);
  }
}
- (void)testGetTCCEventType {
  std::map<es_tcc_event_type_t, ::pbv1::TCCModification::EventType> eventTypeToString{
      {ES_TCC_EVENT_TYPE_CREATE, ::pbv1::TCCModification::EVENT_TYPE_CREATE},
      {ES_TCC_EVENT_TYPE_MODIFY, ::pbv1::TCCModification::EVENT_TYPE_MODIFY},
      {ES_TCC_EVENT_TYPE_DELETE, ::pbv1::TCCModification::EVENT_TYPE_DELETE},
      {(es_tcc_event_type_t)1234, ::pbv1::TCCModification::EVENT_TYPE_UNKNOWN},
  };

  for (const auto &kv : eventTypeToString) {
    XCTAssertEqual(santa::GetTCCEventType(kv.first), kv.second);
  }
}
- (void)testGetTCCAuthorizationRight {
  std::map<es_tcc_authorization_right_t, ::pbv1::TCCModification::AuthorizationRight>
      authRightToString{
          {ES_TCC_AUTHORIZATION_RIGHT_DENIED, ::pbv1::TCCModification::AUTHORIZATION_RIGHT_DENIED},
          {ES_TCC_AUTHORIZATION_RIGHT_UNKNOWN,
           ::pbv1::TCCModification::AUTHORIZATION_RIGHT_UNKNOWN},
          {ES_TCC_AUTHORIZATION_RIGHT_ALLOWED,
           ::pbv1::TCCModification::AUTHORIZATION_RIGHT_ALLOWED},
          {ES_TCC_AUTHORIZATION_RIGHT_LIMITED,
           ::pbv1::TCCModification::AUTHORIZATION_RIGHT_LIMITED},
          {ES_TCC_AUTHORIZATION_RIGHT_ADD_MODIFY_ADDED,
           ::pbv1::TCCModification::AUTHORIZATION_RIGHT_ADD_MODIFY_ADDED},
          {ES_TCC_AUTHORIZATION_RIGHT_SESSION_PID,
           ::pbv1::TCCModification::AUTHORIZATION_RIGHT_SESSION_PID},
          {ES_TCC_AUTHORIZATION_RIGHT_LEARN_MORE,
           ::pbv1::TCCModification::AUTHORIZATION_RIGHT_LEARN_MORE},
          {(es_tcc_authorization_right_t)1234,
           ::pbv1::TCCModification::AUTHORIZATION_RIGHT_UNKNOWN},
      };

  for (const auto &kv : authRightToString) {
    XCTAssertEqual(santa::GetTCCAuthorizationRight(kv.first), kv.second);
  }
}
- (void)testGetTCCAuthorizationReason {
  std::map<es_tcc_authorization_reason_t, ::pbv1::TCCModification::AuthorizationReason>
      authReasonToString{
          {ES_TCC_AUTHORIZATION_REASON_NONE, ::pbv1::TCCModification::AUTHORIZATION_REASON_NONE},
          {ES_TCC_AUTHORIZATION_REASON_ERROR, ::pbv1::TCCModification::AUTHORIZATION_REASON_ERROR},
          {ES_TCC_AUTHORIZATION_REASON_USER_CONSENT,
           ::pbv1::TCCModification::AUTHORIZATION_REASON_USER_CONSENT},
          {ES_TCC_AUTHORIZATION_REASON_USER_SET,
           ::pbv1::TCCModification::AUTHORIZATION_REASON_USER_SET},
          {ES_TCC_AUTHORIZATION_REASON_SYSTEM_SET,
           ::pbv1::TCCModification::AUTHORIZATION_REASON_SYSTEM_SET},
          {ES_TCC_AUTHORIZATION_REASON_SERVICE_POLICY,
           ::pbv1::TCCModification::AUTHORIZATION_REASON_SERVICE_POLICY},
          {ES_TCC_AUTHORIZATION_REASON_MDM_POLICY,
           ::pbv1::TCCModification::AUTHORIZATION_REASON_MDM_POLICY},
          {ES_TCC_AUTHORIZATION_REASON_SERVICE_OVERRIDE_POLICY,
           ::pbv1::TCCModification::AUTHORIZATION_REASON_SERVICE_OVERRIDE_POLICY},
          {ES_TCC_AUTHORIZATION_REASON_MISSING_USAGE_STRING,
           ::pbv1::TCCModification::AUTHORIZATION_REASON_MISSING_USAGE_STRING},
          {ES_TCC_AUTHORIZATION_REASON_PROMPT_TIMEOUT,
           ::pbv1::TCCModification::AUTHORIZATION_REASON_PROMPT_TIMEOUT},
          {ES_TCC_AUTHORIZATION_REASON_PREFLIGHT_UNKNOWN,
           ::pbv1::TCCModification::AUTHORIZATION_REASON_PREFLIGHT_UNKNOWN},
          {ES_TCC_AUTHORIZATION_REASON_ENTITLED,
           ::pbv1::TCCModification::AUTHORIZATION_REASON_ENTITLED},
          {ES_TCC_AUTHORIZATION_REASON_APP_TYPE_POLICY,
           ::pbv1::TCCModification::AUTHORIZATION_REASON_APP_TYPE_POLICY},
          {ES_TCC_AUTHORIZATION_REASON_PROMPT_CANCEL,
           ::pbv1::TCCModification::AUTHORIZATION_REASON_PROMPT_CANCEL},
          {(es_tcc_authorization_reason_t)1234,
           ::pbv1::TCCModification::AUTHORIZATION_REASON_UNKNOWN},
      };

  for (const auto &kv : authReasonToString) {
    XCTAssertEqual(santa::GetTCCAuthorizationReason(kv.first), kv.second);
  }
}

- (void)testSerializeMessageTCCModification {
  es_file_t instigatorProcFile = MakeESFile("fooInst");
  es_process_t instigatorProc =
      MakeESProcess(&instigatorProcFile, MakeAuditToken(21, 43), MakeAuditToken(65, 87));

  es_file_t responsibleFile = MakeESFile("fooApp");
  es_process_t responsibleProc =
      MakeESProcess(&responsibleFile, MakeAuditToken(55, 66), MakeAuditToken(77, 88));

  audit_token_t tokInstigator = MakeAuditToken(6666, 7777);
  audit_token_t tokResponsible = MakeAuditToken(8888, 9999);

  __block es_event_tcc_modify_t tcc = {
      .service = MakeESStringToken("SystemPolicyDocumentsFolder"),
      .identity = MakeESStringToken("security.northpole.santa"),
      .identity_type = ES_TCC_IDENTITY_TYPE_BUNDLE_ID,
      .update_type = ES_TCC_EVENT_TYPE_MODIFY,
      .instigator_token = tokInstigator,
      .instigator = &instigatorProc,
      .responsible_token = &tokResponsible,
      .responsible = &responsibleProc,
      .right = ES_TCC_AUTHORIZATION_RIGHT_SESSION_PID,
      .reason = ES_TCC_AUTHORIZATION_REASON_SERVICE_POLICY,
  };

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_TCC_MODIFY
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.tcc_modify = &tcc;
                  }];

  tcc.instigator = NULL;
  tcc.right = ES_TCC_AUTHORIZATION_RIGHT_ALLOWED;
  tcc.reason = ES_TCC_AUTHORIZATION_REASON_MDM_POLICY;

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_TCC_MODIFY
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.tcc_modify = &tcc;
                  }
                       variant:@"null_trigger"];

  tcc.responsible = NULL;

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_TCC_MODIFY
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.tcc_modify = &tcc;
                  }
                       variant:@"null_trigger_responsible"];

  tcc.responsible_token = NULL;

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_TCC_MODIFY
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.tcc_modify = &tcc;
                  }
                       variant:@"null_everything"];
}

#endif  // HAVE_MACOS_15_4

- (void)testGetAccessType {
  std::map<es_event_type_t, ::pbv1::FileAccess::AccessType> eventTypeToAccessType = {
      {ES_EVENT_TYPE_AUTH_CLONE, ::pbv1::FileAccess::ACCESS_TYPE_CLONE},
      {ES_EVENT_TYPE_AUTH_COPYFILE, ::pbv1::FileAccess::ACCESS_TYPE_COPYFILE},
      {ES_EVENT_TYPE_AUTH_CREATE, ::pbv1::FileAccess::ACCESS_TYPE_CREATE},
      {ES_EVENT_TYPE_AUTH_EXCHANGEDATA, ::pbv1::FileAccess::ACCESS_TYPE_EXCHANGEDATA},
      {ES_EVENT_TYPE_AUTH_LINK, ::pbv1::FileAccess::ACCESS_TYPE_LINK},
      {ES_EVENT_TYPE_AUTH_OPEN, ::pbv1::FileAccess::ACCESS_TYPE_OPEN},
      {ES_EVENT_TYPE_AUTH_RENAME, ::pbv1::FileAccess::ACCESS_TYPE_RENAME},
      {ES_EVENT_TYPE_AUTH_TRUNCATE, ::pbv1::FileAccess::ACCESS_TYPE_TRUNCATE},
      {ES_EVENT_TYPE_AUTH_UNLINK, ::pbv1::FileAccess::ACCESS_TYPE_UNLINK},
      {(es_event_type_t)1234, ::pbv1::FileAccess::ACCESS_TYPE_UNKNOWN},
  };

  for (const auto &kv : eventTypeToAccessType) {
    XCTAssertEqual(santa::GetAccessType(kv.first), kv.second);
  }
}

- (void)testGetPolicyDecision {
  std::map<FileAccessPolicyDecision, ::pbv1::FileAccess::PolicyDecision> policyDecisionEnumToProto =
      {
          {FileAccessPolicyDecision::kNoPolicy, ::pbv1::FileAccess::POLICY_DECISION_UNKNOWN},
          {FileAccessPolicyDecision::kDenied, ::pbv1::FileAccess::POLICY_DECISION_DENIED},
          {FileAccessPolicyDecision::kDeniedInvalidSignature,
           ::pbv1::FileAccess::POLICY_DECISION_DENIED_INVALID_SIGNATURE},
          {FileAccessPolicyDecision::kAllowed, ::pbv1::FileAccess::POLICY_DECISION_UNKNOWN},
          {FileAccessPolicyDecision::kAllowedReadAccess,
           ::pbv1::FileAccess::POLICY_DECISION_UNKNOWN},
          {FileAccessPolicyDecision::kAllowedAuditOnly,
           ::pbv1::FileAccess::POLICY_DECISION_ALLOWED_AUDIT_ONLY},
          {(FileAccessPolicyDecision)1234, ::pbv1::FileAccess::POLICY_DECISION_UNKNOWN},
  };

  for (const auto &kv : policyDecisionEnumToProto) {
    XCTAssertEqual(santa::GetPolicyDecision(kv.first), kv.second);
  }
}

- (void)testSerializeFileAccess {
  __block es_file_t openFile = MakeESFile("open_file", MakeStat(300));
  SerializeAndCheckNonESEvents(
      6, ES_EVENT_TYPE_AUTH_OPEN, @"file_access.json",
      ^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi, es_message_t *esMsg) {
        esMsg->event.open.file = &openFile;
      },
      ^std::vector<uint8_t>(std::shared_ptr<Serializer> serializer, const Message &msg) {
        return serializer->SerializeFileAccess("policy_version", "policy_name", msg,
                                               Enricher().Enrich(*msg->process), "target",
                                               FileAccessPolicyDecision::kDenied, "abc123");
      });
}

- (void)testSerializeAllowlist {
  __block es_file_t closeFile = MakeESFile("close_file", MakeStat(300));
  SerializeAndCheckNonESEvents(
      1, ES_EVENT_TYPE_NOTIFY_CLOSE, @"allowlist.json",
      ^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi, es_message_t *esMsg) {
        esMsg->event.close.target = &closeFile;
      },
      ^std::vector<uint8_t>(std::shared_ptr<Serializer> serializer, const Message &msg) {
        return serializer->SerializeAllowlist(msg, "hash_value");
      });
}

- (void)testSerializeBundleHashingEvent {
  SNTStoredExecutionEvent *se = [[SNTStoredExecutionEvent alloc] init];

  se.fileSHA256 = @"file_hash";
  se.fileBundleHash = @"file_bundle_hash";
  se.fileBundleName = @"file_bundle_name";
  se.fileBundleID = nil;
  se.fileBundlePath = @"file_bundle_path";
  se.filePath = @"file_path";

  std::vector<uint8_t> vec = Protobuf::Create(nullptr, nil)->SerializeBundleHashingEvent(se);
  std::string protoStr(vec.begin(), vec.end());

  ::pbv1::SantaMessage santaMsg;
  XCTAssertTrue(santaMsg.ParseFromString(protoStr));
  XCTAssertTrue(santaMsg.has_bundle());

  const ::pbv1::Bundle &pbBundle = santaMsg.bundle();

  ::pbv1::Hash pbHash = pbBundle.file_hash();
  XCTAssertEqualObjects(@(pbHash.hash().c_str()), se.fileSHA256);
  XCTAssertEqual(pbHash.type(), ::pbv1::Hash::HASH_ALGO_SHA256);

  pbHash = pbBundle.bundle_hash();
  XCTAssertEqualObjects(@(pbHash.hash().c_str()), se.fileBundleHash);
  XCTAssertEqual(pbHash.type(), ::pbv1::Hash::HASH_ALGO_SHA256);

  XCTAssertEqualObjects(@(pbBundle.bundle_name().c_str()), se.fileBundleName);
  XCTAssertEqualObjects(@(pbBundle.bundle_id().c_str()), @"");
  XCTAssertEqualObjects(@(pbBundle.bundle_path().c_str()), se.fileBundlePath);
  XCTAssertEqualObjects(@(pbBundle.path().c_str()), se.filePath);
}

- (void)testSerializeDiskAppeared {
  NSDictionary *props = @{
    @"DADevicePath" : @"",
    @"DADeviceVendor" : @"vendor",
    @"DADeviceModel" : @"model",
    @"DAAppearanceTime" : @(123456789),
    @"DAVolumePath" : [NSURL URLWithString:@"/"],
    @"DAMediaBSDName" : @"bsd",
    @"DAVolumeKind" : @"apfs",
    @"DADeviceProtocol" : @"usb",
  };

  std::vector<uint8_t> vec = Protobuf::Create(nullptr, nil)->SerializeDiskAppeared(props);
  std::string protoStr(vec.begin(), vec.end());

  ::pbv1::SantaMessage santaMsg;
  XCTAssertTrue(santaMsg.ParseFromString(protoStr));
  XCTAssertTrue(santaMsg.has_disk());

  const ::pbv1::Disk &pbDisk = santaMsg.disk();

  XCTAssertEqual(pbDisk.action(), ::pbv1::Disk::ACTION_APPEARED);

  XCTAssertEqualObjects(@(pbDisk.mount().c_str()), [props[@"DAVolumePath"] path]);
  XCTAssertEqualObjects(@(pbDisk.volume().c_str()), @"");
  XCTAssertEqualObjects(@(pbDisk.bsd_name().c_str()), props[@"DAMediaBSDName"]);
  XCTAssertEqualObjects(@(pbDisk.fs().c_str()), props[@"DAVolumeKind"]);
  XCTAssertEqualObjects(@(pbDisk.model().c_str()), @"vendor model");
  XCTAssertEqualObjects(@(pbDisk.serial().c_str()), @"");
  XCTAssertEqualObjects(@(pbDisk.bus().c_str()), props[@"DADeviceProtocol"]);
  XCTAssertEqualObjects(@(pbDisk.dmg_path().c_str()), @"");
  XCTAssertCppStringBeginsWith(pbDisk.mount_from(), std::string("/"));

  // Note: `DAAppearanceTime` is treated as a reference time since 2001 and is converted to a
  // reference time of 1970. Skip the calculation in the test here, just ensure the value is set.
  XCTAssertGreaterThan(pbDisk.appearance().seconds(), 1);
}

- (void)testSerializeDiskDisppeared {
  NSDictionary *props = @{
    @"DADevicePath" : @"",
    @"DADeviceVendor" : @"vendor",
    @"DADeviceModel" : @"model",
    @"DAAppearanceTime" : @(123456789),
    @"DAVolumePath" : [NSURL URLWithString:@"path"],
    @"DAMediaBSDName" : @"bsd",
    @"DAVolumeKind" : @"apfs",
    @"DADeviceProtocol" : @"usb",
  };

  std::vector<uint8_t> vec = Protobuf::Create(nullptr, nil)->SerializeDiskDisappeared(props);
  std::string protoStr(vec.begin(), vec.end());

  ::pbv1::SantaMessage santaMsg;
  XCTAssertTrue(santaMsg.ParseFromString(protoStr));
  XCTAssertTrue(santaMsg.has_disk());

  const ::pbv1::Disk &pbDisk = santaMsg.disk();

  XCTAssertEqual(pbDisk.action(), ::pbv1::Disk::ACTION_DISAPPEARED);

  XCTAssertEqualObjects(@(pbDisk.mount().c_str()), [props[@"DAVolumePath"] path]);
  XCTAssertEqualObjects(@(pbDisk.volume().c_str()), @"");
  XCTAssertEqualObjects(@(pbDisk.bsd_name().c_str()), props[@"DAMediaBSDName"]);
  XCTAssertEqualObjects(@(pbDisk.fs().c_str()), props[@"DAVolumeKind"]);
  XCTAssertEqualObjects(@(pbDisk.model().c_str()), @"vendor model");
  XCTAssertEqualObjects(@(pbDisk.serial().c_str()), @"");
  XCTAssertEqualObjects(@(pbDisk.bus().c_str()), props[@"DADeviceProtocol"]);
  XCTAssertEqualObjects(@(pbDisk.dmg_path().c_str()), @"");

  // Note: `DAAppearanceTime` is treated as a reference time since 2001 and is converted to a
  // reference time of 1970. Skip the calculation in the test here, just ensure the value is set.
  XCTAssertGreaterThan(pbDisk.appearance().seconds(), 1);
}

@end
