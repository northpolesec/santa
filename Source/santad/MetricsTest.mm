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

#include "Source/santad/Metrics.h"

#include <EndpointSecurity/ESTypes.h>
#include <EndpointSecurity/EndpointSecurity.h>
#import <Foundation/Foundation.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#include <dispatch/dispatch.h>

#include <array>
#include <map>
#include <memory>

#include "Source/common/Platform.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTMetricSet.h"
#include "Source/common/TestUtils.h"

using santa::EventDisposition;
using santa::FileAccessEventCountTuple;
using santa::Processor;

namespace santa {

extern NSString* const ProcessorToString(Processor processor);
extern NSString* const EventTypeToString(es_event_type_t eventType);
extern NSString* const EventDispositionToString(EventDisposition d);
extern NSString* const FileAccessMetricStatusToString(FileAccessMetricStatus status);
extern NSString* const FileAccessPolicyDecisionToString(FileAccessPolicyDecision decision);

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
  using Metrics::events_q_;
  using Metrics::faa_event_counts_cache_;
  using Metrics::interval_;
  using Metrics::kNoEventTime;
  using Metrics::rate_limit_counts_cache_;
  using Metrics::running_;

  // Drain the events queue to ensure all async blocks have completed
  void DrainEventQueue() {
    dispatch_sync(events_q_, ^{
                  });
  }
};

}  // namespace santa

using santa::EventDispositionToString;
using santa::EventTypeToString;
using santa::FileAccessMetricStatus;
using santa::FileAccessMetricStatusToString;
using santa::FileAccessPolicyDecisionToString;
using santa::Metrics;
using santa::MetricsPeer;
using santa::ProcessorToString;

std::shared_ptr<MetricsPeer> CreateBasicMetricsPeer(dispatch_queue_t q, void (^block)(Metrics*)) {
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
  std::shared_ptr<MetricsPeer> metrics = CreateBasicMetricsPeer(self.q, ^(Metrics*) {
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
  std::shared_ptr<MetricsPeer> metrics = CreateBasicMetricsPeer(self.q, ^(Metrics*){
                                                                });

  XCTAssertEqual(100, metrics->interval_);

  metrics->SetInterval(200);
  XCTAssertEqual(200, metrics->interval_);
}

- (void)testProcessorToString {
  std::map<Processor, NSString*> processorToString = {
      {Processor::kAuthorizer, @"Authorizer"},
      {Processor::kDeviceManager, @"DeviceManager"},
      {Processor::kRecorder, @"Recorder"},
      {Processor::kTamperResistance, @"TamperResistance"},
      {Processor::kDataFileAccessAuthorizer, @"DataFileAccessAuthorizer"},
      {Processor::kProcessFileAccessAuthorizer, @"ProcessFileAccessAuthorizer"},
  };

  for (const auto& kv : processorToString) {
    XCTAssertEqualObjects(ProcessorToString(kv.first), kv.second);
  }

  XCTAssertThrows(ProcessorToString((Processor)12345));
}

- (void)testEventTypeToString {
  std::map<es_event_type_t, NSString*> eventTypeToString = {
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

  for (const auto& kv : eventTypeToString) {
    XCTAssertEqualObjects(EventTypeToString(kv.first), kv.second);
  }

  XCTAssertThrows(EventTypeToString((es_event_type_t)12345));
}

- (void)testEventDispositionToString {
  std::map<EventDisposition, NSString*> dispositionToString = {
      {EventDisposition::kDropped, @"Dropped"},
      {EventDisposition::kProcessed, @"Processed"},
  };

  for (const auto& kv : dispositionToString) {
    XCTAssertEqualObjects(EventDispositionToString(kv.first), kv.second);
  }

  XCTAssertThrows(EventDispositionToString((EventDisposition)12345));
}

- (void)testFileAccessMetricStatusToString {
  std::map<FileAccessMetricStatus, NSString*> statusToString = {
      {FileAccessMetricStatus::kOK, @"OK"},
      {FileAccessMetricStatus::kBlockedUser, @"BLOCKED_USER"},
  };

  for (const auto& kv : statusToString) {
    XCTAssertEqualObjects(FileAccessMetricStatusToString(kv.first), kv.second);
  }

  XCTAssertThrows(FileAccessMetricStatusToString((FileAccessMetricStatus)12345));
}

- (void)testFileAccessPolicyDecisionToString {
  std::map<FileAccessPolicyDecision, NSString*> decisionToString = {
      {FileAccessPolicyDecision::kDenied, @"Denied"},
      {FileAccessPolicyDecision::kDeniedInvalidSignature, @"Denied"},
      {FileAccessPolicyDecision::kDeniedInvalidSignature, @"Denied"},
  };

  for (const auto& kv : decisionToString) {
    XCTAssertEqualObjects(FileAccessPolicyDecisionToString(kv.first), kv.second);
  }

  std::set<FileAccessPolicyDecision> decisionToStringThrows = {
      FileAccessPolicyDecision::kNoPolicy,
      FileAccessPolicyDecision::kAllowed,
      FileAccessPolicyDecision::kAllowedReadAccess,
      (FileAccessPolicyDecision)12345,
  };
  for (const auto& v : decisionToStringThrows) {
    XCTAssertThrows(FileAccessPolicyDecisionToString(v));
  }
}

- (void)testSetEventMetrics {
  int64_t nanos = 1234;

  std::shared_ptr<MetricsPeer> metrics = CreateBasicMetricsPeer(self.q, ^(Metrics*){
                                                                });

  auto& counts = metrics->event_counts_cache_[static_cast<size_t>(Processor::kAuthorizer)];
  auto& times = metrics->event_times_cache_[static_cast<size_t>(Processor::kAuthorizer)];
  size_t processed = static_cast<size_t>(EventDisposition::kProcessed);

  // Cells are initially empty
  XCTAssertEqual(counts[ES_EVENT_TYPE_AUTH_EXEC][processed].load(), 0);
  XCTAssertEqual(times[ES_EVENT_TYPE_AUTH_EXEC].load(), MetricsPeer::kNoEventTime);

  metrics->SetEventMetrics(Processor::kAuthorizer, EventDisposition::kProcessed, nanos,
                           ES_EVENT_TYPE_AUTH_EXEC);

  // Check cells after setting metrics once
  XCTAssertEqual(counts[ES_EVENT_TYPE_AUTH_EXEC][processed].load(), 1);
  XCTAssertEqual(times[ES_EVENT_TYPE_AUTH_EXEC].load(), nanos);

  // A later time replaces the earlier one
  metrics->SetEventMetrics(Processor::kAuthorizer, EventDisposition::kProcessed, nanos * 3,
                           ES_EVENT_TYPE_AUTH_EXEC);

  metrics->SetEventMetrics(Processor::kAuthorizer, EventDisposition::kProcessed, nanos * 2,
                           ES_EVENT_TYPE_AUTH_OPEN);

  XCTAssertEqual(counts[ES_EVENT_TYPE_AUTH_EXEC][processed].load(), 2);
  XCTAssertEqual(times[ES_EVENT_TYPE_AUTH_EXEC].load(), nanos * 3);
  XCTAssertEqual(counts[ES_EVENT_TYPE_AUTH_OPEN][processed].load(), 1);
  XCTAssertEqual(times[ES_EVENT_TYPE_AUTH_OPEN].load(), nanos * 2);

  // Untouched cells are still empty
  XCTAssertEqual(
      counts[ES_EVENT_TYPE_AUTH_EXEC][static_cast<size_t>(EventDisposition::kDropped)].load(), 0);
  XCTAssertEqual(counts[ES_EVENT_TYPE_AUTH_UNLINK][processed].load(), 0);
  XCTAssertEqual(times[ES_EVENT_TYPE_AUTH_UNLINK].load(), MetricsPeer::kNoEventTime);
}

- (void)testAddRateLimitingMetrics {
  std::shared_ptr<MetricsPeer> metrics = CreateBasicMetricsPeer(self.q, ^(Metrics*){
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
  std::shared_ptr<MetricsPeer> metrics = CreateBasicMetricsPeer(self.q, ^(Metrics*){
                                                                });

  // Initial map is empty
  XCTAssertEqual(metrics->faa_event_counts_cache_.size(), 0);

  metrics->SetFileAccessEventMetrics("v1.0", "rule_abc", FileAccessMetricStatus::kOK,
                                     ES_EVENT_TYPE_AUTH_OPEN, FileAccessPolicyDecision::kDenied);
  metrics->DrainEventQueue();

  // Check sizes after setting metrics once
  XCTAssertEqual(metrics->faa_event_counts_cache_.size(), 1);

  // Update the previous metric
  metrics->SetFileAccessEventMetrics("v1.0", "rule_abc", FileAccessMetricStatus::kOK,
                                     ES_EVENT_TYPE_AUTH_OPEN, FileAccessPolicyDecision::kDenied);

  // Add a second metric
  metrics->SetFileAccessEventMetrics("v1.0", "rule_xyz", FileAccessMetricStatus::kOK,
                                     ES_EVENT_TYPE_AUTH_OPEN, FileAccessPolicyDecision::kDenied);
  metrics->DrainEventQueue();

  // Re-check expected counts. One was an update, so should only be 2 items
  XCTAssertEqual(metrics->faa_event_counts_cache_.size(), 2);

  FileAccessEventCountTuple ruleAbc{"v1.0", "rule_abc", FileAccessMetricStatus::kOK,
                                    ES_EVENT_TYPE_AUTH_OPEN, FileAccessPolicyDecision::kDenied};
  FileAccessEventCountTuple ruleXyz{"v1.0", "rule_xyz", FileAccessMetricStatus::kOK,
                                    ES_EVENT_TYPE_AUTH_OPEN, FileAccessPolicyDecision::kDenied};

  XCTAssertEqual(metrics->faa_event_counts_cache_[ruleAbc], 2);
  XCTAssertEqual(metrics->faa_event_counts_cache_[ruleXyz], 1);
}

- (void)testRecordDrops {
  std::shared_ptr<MetricsPeer> metrics = CreateBasicMetricsPeer(self.q, ^(Metrics*){
                                                                });

  auto& row = metrics->drop_cache_[static_cast<size_t>(Processor::kRecorder)];

  // Cells initially hold no drops
  XCTAssertEqual(0, row[ES_EVENT_TYPE_NOTIFY_EXEC].load());
  XCTAssertEqual(0, row[ES_EVENT_TYPE_LAST].load());

  // Both the event and the global cell record their drops
  metrics->RecordDrops(Processor::kRecorder, ES_EVENT_TYPE_NOTIFY_EXEC, 9, 9);
  XCTAssertEqual(9, row[ES_EVENT_TYPE_NOTIFY_EXEC].load());
  XCTAssertEqual(9, row[ES_EVENT_TYPE_LAST].load());

  // Only global drops leave the event cell unchanged
  metrics->RecordDrops(Processor::kRecorder, ES_EVENT_TYPE_NOTIFY_EXEC, 0, 4);
  XCTAssertEqual(9, row[ES_EVENT_TYPE_NOTIFY_EXEC].load());
  XCTAssertEqual(13, row[ES_EVENT_TYPE_LAST].load());
}

- (void)testFlushMetrics {
  id mockEventProcessingTimes = OCMStrictClassMock([SNTMetricInt64Gauge class]);
  id mockEventCounts = OCMStrictClassMock([SNTMetricCounter class]);
  id mockRateLimitCounts = OCMStrictClassMock([SNTMetricCounter class]);
  id mockFAAEventCounts = OCMStrictClassMock([SNTMetricCounter class]);
  id mockDropCounts = OCMStrictClassMock([SNTMetricCounter class]);
  int64_t nanos = 1234;

  dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, self.q);
  auto metrics =
      std::make_shared<MetricsPeer>(self.q, timer, 100, mockEventProcessingTimes, mockEventCounts,
                                    mockRateLimitCounts, mockFAAEventCounts, mockDropCounts, nil,
                                    ^(santa::Metrics* m){
                                        // This block intentionally left blank
                                    });

  metrics->SetEventMetrics(Processor::kAuthorizer, EventDisposition::kProcessed, nanos,
                           ES_EVENT_TYPE_AUTH_EXEC);
  metrics->SetEventMetrics(Processor::kAuthorizer, EventDisposition::kProcessed, nanos * 2,
                           ES_EVENT_TYPE_AUTH_OPEN);
  metrics->RecordDrops(Processor::kRecorder, ES_EVENT_TYPE_NOTIFY_EXEC, 123, 123);
  metrics->AddRateLimitingMetrics(123);
  metrics->SetFileAccessEventMetrics("v1.0", "rule_abc", FileAccessMetricStatus::kOK,
                                     ES_EVENT_TYPE_AUTH_OPEN, FileAccessPolicyDecision::kDenied);
  metrics->DrainEventQueue();

  // First ensure we have the expected cached values
  auto& counts = metrics->event_counts_cache_[static_cast<size_t>(Processor::kAuthorizer)];
  auto& times = metrics->event_times_cache_[static_cast<size_t>(Processor::kAuthorizer)];
  auto& dropRow = metrics->drop_cache_[static_cast<size_t>(Processor::kRecorder)];
  size_t processed = static_cast<size_t>(EventDisposition::kProcessed);
  XCTAssertEqual(counts[ES_EVENT_TYPE_AUTH_EXEC][processed].load(), 1);
  XCTAssertEqual(counts[ES_EVENT_TYPE_AUTH_OPEN][processed].load(), 1);
  XCTAssertEqual(times[ES_EVENT_TYPE_AUTH_EXEC].load(), nanos);
  XCTAssertEqual(times[ES_EVENT_TYPE_AUTH_OPEN].load(), nanos * 2);
  XCTAssertEqual(dropRow[ES_EVENT_TYPE_NOTIFY_EXEC].load(), 123);
  XCTAssertEqual(dropRow[ES_EVENT_TYPE_LAST].load(), 123);
  XCTAssertEqual(metrics->rate_limit_counts_cache_.load(), 123);
  XCTAssertEqual(metrics->faa_event_counts_cache_.size(), 1);

  // The strict mocks fail on any call not expected here
  OCMExpect([mockEventCounts incrementBy:1
                          forFieldValues:(@[ @"Authorizer", @"AuthExec", @"Processed" ])]);
  OCMExpect([mockEventCounts incrementBy:1
                          forFieldValues:(@[ @"Authorizer", @"AuthOpen", @"Processed" ])]);
  OCMExpect([(SNTMetricInt64Gauge*)mockEventProcessingTimes set:nanos
                                                 forFieldValues:(@[ @"Authorizer", @"AuthExec" ])]);
  OCMExpect([(SNTMetricInt64Gauge*)mockEventProcessingTimes set:nanos * 2
                                                 forFieldValues:(@[ @"Authorizer", @"AuthOpen" ])]);
  OCMExpect([mockDropCounts incrementBy:123 forFieldValues:(@[ @"Recorder", @"NotifyExec" ])]);
  OCMExpect([mockDropCounts incrementBy:123 forFieldValues:(@[ @"Recorder", @"Global" ])]);
  OCMExpect([mockRateLimitCounts incrementBy:123 forFieldValues:(@[])]);
  OCMExpect([mockFAAEventCounts
         incrementBy:1
      forFieldValues:(@[ @"v1.0", @"access", @"rule_abc", @"OK", @"AuthOpen", @"Denied" ])]);

  metrics->FlushMetrics();

  OCMVerifyAll(mockEventProcessingTimes);
  OCMVerifyAll(mockEventCounts);
  OCMVerifyAll(mockRateLimitCounts);
  OCMVerifyAll(mockFAAEventCounts);
  OCMVerifyAll(mockDropCounts);

  // After a flush, cached values should be reset
  XCTAssertEqual(counts[ES_EVENT_TYPE_AUTH_EXEC][processed].load(), 0);
  XCTAssertEqual(counts[ES_EVENT_TYPE_AUTH_OPEN][processed].load(), 0);
  XCTAssertEqual(times[ES_EVENT_TYPE_AUTH_EXEC].load(), MetricsPeer::kNoEventTime);
  XCTAssertEqual(times[ES_EVENT_TYPE_AUTH_OPEN].load(), MetricsPeer::kNoEventTime);
  XCTAssertEqual(dropRow[ES_EVENT_TYPE_NOTIFY_EXEC].load(), 0);
  XCTAssertEqual(dropRow[ES_EVENT_TYPE_LAST].load(), 0);
  XCTAssertEqual(metrics->rate_limit_counts_cache_.load(), 0);
  XCTAssertEqual(metrics->faa_event_counts_cache_.size(), 0);
}

- (void)testFlushMetricsReportsOnlyNewDrops {
  id mockEventProcessingTimes = OCMStrictClassMock([SNTMetricInt64Gauge class]);
  id mockEventCounts = OCMStrictClassMock([SNTMetricCounter class]);
  id mockRateLimitCounts = OCMStrictClassMock([SNTMetricCounter class]);
  id mockFAAEventCounts = OCMStrictClassMock([SNTMetricCounter class]);
  id mockDropCounts = OCMStrictClassMock([SNTMetricCounter class]);

  dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, self.q);
  auto metrics =
      std::make_shared<MetricsPeer>(self.q, timer, 100, mockEventProcessingTimes, mockEventCounts,
                                    mockRateLimitCounts, mockFAAEventCounts, mockDropCounts, nil,
                                    ^(santa::Metrics* m){
                                        // This block intentionally left blank
                                    });

  // The rate limit count is reported on every flush, even when zero
  OCMExpect([mockRateLimitCounts incrementBy:0 forFieldValues:(@[])]);
  OCMExpect([mockDropCounts incrementBy:123 forFieldValues:(@[ @"Recorder", @"NotifyExec" ])]);
  OCMExpect([mockDropCounts incrementBy:123 forFieldValues:(@[ @"Recorder", @"Global" ])]);

  metrics->RecordDrops(Processor::kRecorder, ES_EVENT_TYPE_NOTIFY_EXEC, 123, 123);
  metrics->FlushMetrics();

  OCMVerifyAll(mockRateLimitCounts);
  OCMVerifyAll(mockDropCounts);

  // The second flush reports only the drops recorded since the first
  OCMExpect([mockRateLimitCounts incrementBy:0 forFieldValues:(@[])]);
  OCMExpect([mockDropCounts incrementBy:5 forFieldValues:(@[ @"Recorder", @"NotifyExec" ])]);
  OCMExpect([mockDropCounts incrementBy:2 forFieldValues:(@[ @"Recorder", @"Global" ])]);

  metrics->RecordDrops(Processor::kRecorder, ES_EVENT_TYPE_NOTIFY_EXEC, 5, 2);
  metrics->FlushMetrics();

  OCMVerifyAll(mockEventProcessingTimes);
  OCMVerifyAll(mockEventCounts);
  OCMVerifyAll(mockRateLimitCounts);
  OCMVerifyAll(mockFAAEventCounts);
  OCMVerifyAll(mockDropCounts);
}

@end
