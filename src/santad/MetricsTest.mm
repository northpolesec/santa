/// Copyright 2022 Google Inc. All rights reserved.
/// Copyright 2024 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     http://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#include "src/santad/Metrics.h"

#include <EndpointSecurity/ESTypes.h>
#include <EndpointSecurity/EndpointSecurity.h>
#import <Foundation/Foundation.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#include <dispatch/dispatch.h>

#include <map>
#include <memory>

#include "src/common/Platform.h"
#import "src/common/SNTCommonEnums.h"
#include "src/common/SNTMetricSet.h"
#include "src/common/TestUtils.h"
#include "src/santad/event_providers/endpoint_security/Message.h"
#include "src/santad/event_providers/endpoint_security/MockEndpointSecurityAPI.h"

using santa::EventCountTuple;
using santa::EventDisposition;
using santa::EventStatsTuple;
using santa::EventTimesTuple;
using santa::FileAccessEventCountTuple;
using santa::Processor;

namespace santa {

extern NSString *const ProcessorToString(Processor processor);
extern NSString *const EventTypeToString(es_event_type_t eventType);
extern NSString *const EventDispositionToString(EventDisposition d);
extern NSString *const FileAccessMetricStatusToString(FileAccessMetricStatus status);
extern NSString *const FileAccessPolicyDecisionToString(FileAccessPolicyDecision decision);

class MetricsPeer : public Metrics {
 public:
  // Make base class constructors visible
  using Metrics::Metrics;

  // Private methods
  using Metrics::FlushMetrics;

  // Private member variables
  using Metrics::drop_cache_;
  using Metrics::event_counts_cache_;
  using Metrics::event_times_cache_;
  using Metrics::faa_event_counts_cache_;
  using Metrics::interval_;
  using Metrics::rate_limit_counts_cache_;
  using Metrics::running_;

  using Metrics::SequenceStats;
};

}  // namespace santa

using santa::EventDispositionToString;
using santa::EventTypeToString;
using santa::FileAccessMetricStatus;
using santa::FileAccessMetricStatusToString;
using santa::FileAccessPolicyDecisionToString;
using santa::Message;
using santa::Metrics;
using santa::MetricsPeer;
using santa::ProcessorToString;

std::shared_ptr<MetricsPeer> CreateBasicMetricsPeer(dispatch_queue_t q, void (^block)(Metrics *)) {
  dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, q);
  return std::make_shared<MetricsPeer>(q, timer, 100, nil, nil, nil, nil, nil, nil, block);
}

@interface MetricsTest : XCTestCase
@property dispatch_queue_t q;
@property dispatch_semaphore_t sema;
@end

@implementation MetricsTest

- (void)setUp {
  self.q = dispatch_queue_create(NULL, DISPATCH_QUEUE_SERIAL);
  XCTAssertNotNil(self.q);
  self.sema = dispatch_semaphore_create(0);
}

- (void)testStartStop {
  std::shared_ptr<MetricsPeer> metrics = CreateBasicMetricsPeer(self.q, ^(Metrics *) {
    dispatch_semaphore_signal(self.sema);
  });

  XCTAssertFalse(metrics->running_);

  metrics->StartPoll();
  XCTAssertEqual(0, dispatch_semaphore_wait(self.sema, DISPATCH_TIME_NOW),
                 "Initialization block never called");

  // Should be marked running after starting
  XCTAssertTrue(metrics->running_);

  metrics->StartPoll();

  // Ensure the initialization block isn't called a second time
  XCTAssertNotEqual(0, dispatch_semaphore_wait(self.sema, DISPATCH_TIME_NOW),
                    "Initialization block called second time unexpectedly");

  // Double-start doesn't change the running state
  XCTAssertTrue(metrics->running_);

  metrics->StopPoll();

  // After stopping, the internal state is no longer marked running
  XCTAssertFalse(metrics->running_);

  metrics->StopPoll();

  // Double-stop doesn't change the running state
  XCTAssertFalse(metrics->running_);
}

- (void)testSetInterval {
  std::shared_ptr<MetricsPeer> metrics = CreateBasicMetricsPeer(self.q, ^(Metrics *){
                                                                });

  XCTAssertEqual(100, metrics->interval_);

  metrics->SetInterval(200);
  XCTAssertEqual(200, metrics->interval_);
}

- (void)testProcessorToString {
  std::map<Processor, NSString *> processorToString = {
      {Processor::kAuthorizer, @"Authorizer"},
      {Processor::kDeviceManager, @"DeviceManager"},
      {Processor::kRecorder, @"Recorder"},
      {Processor::kTamperResistance, @"TamperResistance"},
      {Processor::kDataFileAccessAuthorizer, @"DataFileAccessAuthorizer"},
      {Processor::kProcessFileAccessAuthorizer, @"ProcessFileAccessAuthorizer"},
  };

  for (const auto &kv : processorToString) {
    XCTAssertEqualObjects(ProcessorToString(kv.first), kv.second);
  }

  XCTAssertThrows(ProcessorToString((Processor)12345));
}

- (void)testEventTypeToString {
  std::map<es_event_type_t, NSString *> eventTypeToString = {
      {ES_EVENT_TYPE_AUTH_CLONE, @"AuthClone"},
      {ES_EVENT_TYPE_AUTH_COPYFILE, @"AuthCopyfile"},
      {ES_EVENT_TYPE_AUTH_CREATE, @"AuthCreate"},
      {ES_EVENT_TYPE_AUTH_EXCHANGEDATA, @"AuthExchangedata"},
      {ES_EVENT_TYPE_AUTH_EXEC, @"AuthExec"},
      {ES_EVENT_TYPE_AUTH_KEXTLOAD, @"AuthKextload"},
      {ES_EVENT_TYPE_AUTH_LINK, @"AuthLink"},
      {ES_EVENT_TYPE_AUTH_MOUNT, @"AuthMount"},
      {ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME, @"AuthProcSuspendResume"},
      {ES_EVENT_TYPE_AUTH_REMOUNT, @"AuthRemount"},
      {ES_EVENT_TYPE_AUTH_RENAME, @"AuthRename"},
      {ES_EVENT_TYPE_AUTH_SIGNAL, @"AuthSignal"},
      {ES_EVENT_TYPE_AUTH_TRUNCATE, @"AuthTruncate"},
      {ES_EVENT_TYPE_AUTH_UNLINK, @"AuthUnlink"},
      {ES_EVENT_TYPE_NOTIFY_CLONE, @"NotifyClone"},
      {ES_EVENT_TYPE_NOTIFY_CLOSE, @"NotifyClose"},
      {ES_EVENT_TYPE_NOTIFY_COPYFILE, @"NotifyCopyfile"},
      {ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED, @"NotifyCodesigningInvalidated"},
      {ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA, @"NotifyExchangedata"},
      {ES_EVENT_TYPE_NOTIFY_EXEC, @"NotifyExec"},
      {ES_EVENT_TYPE_NOTIFY_EXIT, @"NotifyExit"},
      {ES_EVENT_TYPE_NOTIFY_FORK, @"NotifyFork"},
      {ES_EVENT_TYPE_NOTIFY_LINK, @"NotifyLink"},
      {ES_EVENT_TYPE_NOTIFY_RENAME, @"NotifyRename"},
      {ES_EVENT_TYPE_NOTIFY_UNLINK, @"NotifyUnlink"},
      {ES_EVENT_TYPE_NOTIFY_UNMOUNT, @"NotifyUnmount"},
      {ES_EVENT_TYPE_NOTIFY_AUTHENTICATION, @"NotifyAuthentication"},
      {ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN, @"NotifyLoginLogin"},
      {ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT, @"NotifyLoginLogout"},
      {ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN, @"NotifyLWSessionLogin"},
      {ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT, @"NotifyLWSessionLogout"},
      {ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK, @"NotifyLWSessionLock"},
      {ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK, @"NotifyLWSessionUnlock"},
      {ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH, @"NotifyScreensharingAttach"},
      {ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH, @"NotifyScreensharingDetach"},
      {ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN, @"NotifyOpenSSHLogin"},
      {ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT, @"NotifyOpenSSHLogout"},
      {ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD, @"NotifyLaunchItemAdd"},
      {ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE, @"NotifyLaunchItemRemove"},
      {ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED, @"NotifyXProtectDetected"},
      {ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED, @"NotifyXProtectRemediated"},
#if HAVE_MACOS_15
      {ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE, @"NotifyGatekeeperOverride"},
#endif  // HAVE_MACOS_15
#if HAVE_MACOS_15_4
      {ES_EVENT_TYPE_NOTIFY_TCC_MODIFY, @"NotifyTCCModification"},
#endif  // HAVE_MACOS_15_4
      {ES_EVENT_TYPE_LAST, @"Global"},
  };

  for (const auto &kv : eventTypeToString) {
    XCTAssertEqualObjects(EventTypeToString(kv.first), kv.second);
  }

  XCTAssertThrows(EventTypeToString((es_event_type_t)12345));
}

- (void)testEventDispositionToString {
  std::map<EventDisposition, NSString *> dispositionToString = {
      {EventDisposition::kDropped, @"Dropped"},
      {EventDisposition::kProcessed, @"Processed"},
  };

  for (const auto &kv : dispositionToString) {
    XCTAssertEqualObjects(EventDispositionToString(kv.first), kv.second);
  }

  XCTAssertThrows(EventDispositionToString((EventDisposition)12345));
}

- (void)testFileAccessMetricStatusToString {
  std::map<FileAccessMetricStatus, NSString *> statusToString = {
      {FileAccessMetricStatus::kOK, @"OK"},
      {FileAccessMetricStatus::kBlockedUser, @"BLOCKED_USER"},
  };

  for (const auto &kv : statusToString) {
    XCTAssertEqualObjects(FileAccessMetricStatusToString(kv.first), kv.second);
  }

  XCTAssertThrows(FileAccessMetricStatusToString((FileAccessMetricStatus)12345));
}

- (void)testFileAccessPolicyDecisionToString {
  std::map<FileAccessPolicyDecision, NSString *> decisionToString = {
      {FileAccessPolicyDecision::kDenied, @"Denied"},
      {FileAccessPolicyDecision::kDeniedInvalidSignature, @"Denied"},
      {FileAccessPolicyDecision::kDeniedInvalidSignature, @"Denied"},
  };

  for (const auto &kv : decisionToString) {
    XCTAssertEqualObjects(FileAccessPolicyDecisionToString(kv.first), kv.second);
  }

  std::set<FileAccessPolicyDecision> decisionToStringThrows = {
      FileAccessPolicyDecision::kNoPolicy,
      FileAccessPolicyDecision::kAllowed,
      FileAccessPolicyDecision::kAllowedReadAccess,
      (FileAccessPolicyDecision)12345,
  };
  for (const auto &v : decisionToStringThrows) {
    XCTAssertThrows(FileAccessPolicyDecisionToString(v));
  }
}

- (void)testSetEventMetrics {
  int64_t nanos = 1234;
  es_message_t esExecMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_EXEC, NULL);
  es_message_t esOpenMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_OPEN, NULL);

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsRetainReleaseMessage();

  std::shared_ptr<MetricsPeer> metrics = CreateBasicMetricsPeer(self.q, ^(Metrics *){
                                                                });

  // Initial maps are empty
  XCTAssertEqual(metrics->event_counts_cache_.size(), 0);
  XCTAssertEqual(metrics->event_times_cache_.size(), 0);

  {
    Message execMsg(mockESApi, &esExecMsg);
    Message openMsg(mockESApi, &esOpenMsg);
    metrics->SetEventMetrics(Processor::kAuthorizer, EventDisposition::kProcessed, nanos, execMsg);

    // Check sizes after setting metrics once
    XCTAssertEqual(metrics->event_counts_cache_.size(), 1);
    XCTAssertEqual(metrics->event_times_cache_.size(), 1);

    metrics->SetEventMetrics(Processor::kAuthorizer, EventDisposition::kProcessed, nanos, execMsg);

    metrics->SetEventMetrics(Processor::kAuthorizer, EventDisposition::kProcessed, nanos * 2,
                             openMsg);
  }

  // Re-check expected counts. One was an update, so should only be 2 items
  XCTAssertEqual(metrics->event_counts_cache_.size(), 2);
  XCTAssertEqual(metrics->event_times_cache_.size(), 2);

  // Check map values
  EventCountTuple ecExec{Processor::kAuthorizer, ES_EVENT_TYPE_AUTH_EXEC,
                         EventDisposition::kProcessed};
  EventCountTuple ecOpen{Processor::kAuthorizer, ES_EVENT_TYPE_AUTH_OPEN,
                         EventDisposition::kProcessed};
  EventTimesTuple etExec{Processor::kAuthorizer, ES_EVENT_TYPE_AUTH_EXEC};
  EventTimesTuple etOpen{Processor::kAuthorizer, ES_EVENT_TYPE_AUTH_OPEN};

  XCTAssertEqual(metrics->event_counts_cache_[ecExec], 2);
  XCTAssertEqual(metrics->event_counts_cache_[ecOpen], 1);
  XCTAssertEqual(metrics->event_times_cache_[etExec], nanos);
  XCTAssertEqual(metrics->event_times_cache_[etOpen], nanos * 2);
}

- (void)testAddRateLimitingMetrics {
  std::shared_ptr<MetricsPeer> metrics = CreateBasicMetricsPeer(self.q, ^(Metrics *){
                                                                });

  // Initial count is zero
  XCTAssertEqual(metrics->rate_limit_counts_cache_.load(), 0);

  // Check counts after setting metrics once
  metrics->AddRateLimitingMetrics(123);
  XCTAssertEqual(metrics->rate_limit_counts_cache_.load(), 123);

  // Re-check expected counts. One was an update, so should only be 2 items
  metrics->AddRateLimitingMetrics(100);
  metrics->AddRateLimitingMetrics(200);

  // Check final value
  XCTAssertEqual(metrics->rate_limit_counts_cache_.load(), 423);
}

- (void)testSetFileAccessEventMetrics {
  std::shared_ptr<MetricsPeer> metrics = CreateBasicMetricsPeer(self.q, ^(Metrics *){
                                                                });

  // Initial map is empty
  XCTAssertEqual(metrics->faa_event_counts_cache_.size(), 0);

  metrics->SetFileAccessEventMetrics("v1.0", "rule_abc", FileAccessMetricStatus::kOK,
                                     ES_EVENT_TYPE_AUTH_OPEN, FileAccessPolicyDecision::kDenied);

  // Check sizes after setting metrics once
  XCTAssertEqual(metrics->faa_event_counts_cache_.size(), 1);

  // Update the previous metric
  metrics->SetFileAccessEventMetrics("v1.0", "rule_abc", FileAccessMetricStatus::kOK,
                                     ES_EVENT_TYPE_AUTH_OPEN, FileAccessPolicyDecision::kDenied);

  // Add a second metric
  metrics->SetFileAccessEventMetrics("v1.0", "rule_xyz", FileAccessMetricStatus::kOK,
                                     ES_EVENT_TYPE_AUTH_OPEN, FileAccessPolicyDecision::kDenied);

  // Re-check expected counts. One was an update, so should only be 2 items
  XCTAssertEqual(metrics->faa_event_counts_cache_.size(), 2);

  FileAccessEventCountTuple ruleAbc{"v1.0", "rule_abc", FileAccessMetricStatus::kOK,
                                    ES_EVENT_TYPE_AUTH_OPEN, FileAccessPolicyDecision::kDenied};
  FileAccessEventCountTuple ruleXyz{"v1.0", "rule_xyz", FileAccessMetricStatus::kOK,
                                    ES_EVENT_TYPE_AUTH_OPEN, FileAccessPolicyDecision::kDenied};

  XCTAssertEqual(metrics->faa_event_counts_cache_[ruleAbc], 2);
  XCTAssertEqual(metrics->faa_event_counts_cache_[ruleXyz], 1);
}

- (void)testUpdateEventStats {
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_EXEC, NULL);
  esMsg.seq_num = 0;
  esMsg.global_seq_num = 0;

  std::shared_ptr<MetricsPeer> metrics = CreateBasicMetricsPeer(self.q, ^(Metrics *){
                                                                });

  EventStatsTuple eventStats{Processor::kRecorder, ES_EVENT_TYPE_NOTIFY_EXEC};
  EventStatsTuple globalStats{Processor::kRecorder, ES_EVENT_TYPE_LAST};

  // Map does not initially contain entries
  XCTAssertEqual(0, metrics->drop_cache_.size());

  metrics->UpdateEventStats(Processor::kRecorder, &esMsg);

  // After the first update, 2 entries exist, one for the event, and one for global
  XCTAssertEqual(2, metrics->drop_cache_.size());
  XCTAssertEqual(1, metrics->drop_cache_[eventStats].next_seq_num);
  XCTAssertEqual(0, metrics->drop_cache_[eventStats].drops);
  XCTAssertEqual(1, metrics->drop_cache_[globalStats].next_seq_num);
  XCTAssertEqual(0, metrics->drop_cache_[globalStats].drops);

  // Increment sequence numbers by 1 and check that no drop was detected
  esMsg.seq_num++;
  esMsg.global_seq_num++;

  metrics->UpdateEventStats(Processor::kRecorder, &esMsg);

  XCTAssertEqual(2, metrics->drop_cache_.size());
  XCTAssertEqual(2, metrics->drop_cache_[eventStats].next_seq_num);
  XCTAssertEqual(0, metrics->drop_cache_[eventStats].drops);
  XCTAssertEqual(2, metrics->drop_cache_[globalStats].next_seq_num);
  XCTAssertEqual(0, metrics->drop_cache_[globalStats].drops);

  // Now incremenet sequence numbers by a large amount to trigger drop detection
  esMsg.seq_num += 10;
  esMsg.global_seq_num += 10;

  metrics->UpdateEventStats(Processor::kRecorder, &esMsg);

  XCTAssertEqual(2, metrics->drop_cache_.size());
  XCTAssertEqual(12, metrics->drop_cache_[eventStats].next_seq_num);
  XCTAssertEqual(9, metrics->drop_cache_[eventStats].drops);
  XCTAssertEqual(12, metrics->drop_cache_[globalStats].next_seq_num);
  XCTAssertEqual(9, metrics->drop_cache_[globalStats].drops);
}

- (void)testFlushMetrics {
  id mockEventProcessingTimes = OCMClassMock([SNTMetricInt64Gauge class]);
  id mockEventCounts = OCMClassMock([SNTMetricCounter class]);
  int64_t nanos = 1234;
  es_message_t esExecMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_EXEC, NULL);
  es_message_t esOpenMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_OPEN, NULL);

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsRetainReleaseMessage();

  // Initial update will have non-zero sequence numbers, triggering drop detection
  es_message_t esMsgWithDrops = MakeESMessage(ES_EVENT_TYPE_NOTIFY_EXEC, NULL);
  esMsgWithDrops.seq_num = 123;
  esMsgWithDrops.global_seq_num = 123;

  OCMStub([mockEventCounts incrementBy:0 forFieldValues:[OCMArg any]])
      .ignoringNonObjectArgs()
      .andDo(^(NSInvocation *inv) {
        dispatch_semaphore_signal(self.sema);
      });

  OCMStub([(SNTMetricInt64Gauge *)mockEventProcessingTimes set:nanos forFieldValues:[OCMArg any]])
      .ignoringNonObjectArgs()
      .andDo(^(NSInvocation *inv) {
        dispatch_semaphore_signal(self.sema);
      });

  dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, self.q);
  auto metrics =
      std::make_shared<MetricsPeer>(self.q, timer, 100, mockEventProcessingTimes, mockEventCounts,
                                    mockEventCounts, mockEventCounts, mockEventCounts, nil,
                                    ^(santa::Metrics *m){
                                        // This block intentionally left blank
                                    });

  {
    Message execMsg(mockESApi, &esExecMsg);
    Message openMsg(mockESApi, &esOpenMsg);
    metrics->SetEventMetrics(Processor::kAuthorizer, EventDisposition::kProcessed, nanos, execMsg);
    metrics->SetEventMetrics(Processor::kAuthorizer, EventDisposition::kProcessed, nanos * 2,
                             openMsg);
  }
  metrics->UpdateEventStats(Processor::kRecorder, &esMsgWithDrops);
  metrics->AddRateLimitingMetrics(123);
  metrics->SetFileAccessEventMetrics("v1.0", "rule_abc", FileAccessMetricStatus::kOK,
                                     ES_EVENT_TYPE_AUTH_OPEN, FileAccessPolicyDecision::kDenied);

  // First ensure we have the expected map sizes
  XCTAssertEqual(metrics->event_counts_cache_.size(), 2);
  XCTAssertEqual(metrics->event_times_cache_.size(), 2);
  XCTAssertEqual(metrics->rate_limit_counts_cache_.load(), 123);
  XCTAssertEqual(metrics->faa_event_counts_cache_.size(), 1);
  XCTAssertEqual(metrics->drop_cache_.size(), 2);

  EventStatsTuple eventStats{Processor::kRecorder, esMsgWithDrops.event_type};
  EventStatsTuple globalStats{Processor::kRecorder, ES_EVENT_TYPE_LAST};
  XCTAssertEqual(metrics->drop_cache_[eventStats].next_seq_num, 124);
  XCTAssertEqual(metrics->drop_cache_[eventStats].drops, 123);
  XCTAssertEqual(metrics->drop_cache_[globalStats].next_seq_num, 124);
  XCTAssertEqual(metrics->drop_cache_[globalStats].drops, 123);

  metrics->FlushMetrics();

  // Expected call count is 8:
  // 2: event counts
  // 2: event times
  // 1: rate limit
  // 1: FAA
  // 2: drops (1 event, 1 global)
  int expectedCalls = 8;
  for (int i = 0; i < expectedCalls; i++) {
    XCTAssertSemaTrue(self.sema, 5, "Failed waiting for metrics to flush");
  }

  // After a flush, map sizes should be reset to 0
  XCTAssertEqual(metrics->event_counts_cache_.size(), 0);
  XCTAssertEqual(metrics->event_times_cache_.size(), 0);
  XCTAssertEqual(metrics->rate_limit_counts_cache_.load(), 0);
  XCTAssertEqual(metrics->faa_event_counts_cache_.size(), 0);
  // Note: The drop_cache_ should not be reset back to size 0. Instead, each
  // entry has the sequence number left intact, but drop counts reset to 0.
  XCTAssertEqual(metrics->drop_cache_.size(), 2);
  XCTAssertEqual(metrics->drop_cache_[eventStats].next_seq_num, 124);
  XCTAssertEqual(metrics->drop_cache_[eventStats].drops, 0);
  XCTAssertEqual(metrics->drop_cache_[globalStats].next_seq_num, 124);
  XCTAssertEqual(metrics->drop_cache_[globalStats].drops, 0);
}

@end
