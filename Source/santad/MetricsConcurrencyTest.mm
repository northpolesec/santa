/// Copyright 2026 North Pole Security, Inc.
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

// Concurrency stress test for the atomic per-message metric cells in Metrics:
// many threads call SetEventMetrics and RecordDrops while another thread
// flushes, then every exported total is checked. Run plainly it catches lost
// or double-reported updates; the nightly sanitizer job also runs it under
// ThreadSanitizer (it is tagged "concurrency").

#include <EndpointSecurity/ESTypes.h>
#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>
#include <dispatch/dispatch.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <memory>
#include <thread>
#include <vector>

#import "Source/common/SNTMetricSet.h"
#include "Source/common/es/ESMetricsObserver.h"
#include "Source/santad/Metrics.h"

using santa::EventDisposition;
using santa::EventTypeToString;
using santa::Metrics;
using santa::Processor;

namespace santa {

class MetricsPeer : public Metrics {
 public:
  using Metrics::FlushMetrics;
  using Metrics::Metrics;
};

}  // namespace santa

using santa::MetricsPeer;

namespace {

constexpr int kWriters = 8;
constexpr int64_t kIterations = 50000;
constexpr int64_t kProgressInterval = 1024;

// Each writer also owns one Authorizer cell for this event type.
constexpr std::array<es_event_type_t, kWriters> kPerWriterEvents = {
    ES_EVENT_TYPE_AUTH_EXEC,   ES_EVENT_TYPE_AUTH_OPEN,     ES_EVENT_TYPE_AUTH_UNLINK,
    ES_EVENT_TYPE_AUTH_RENAME, ES_EVENT_TYPE_AUTH_LINK,     ES_EVENT_TYPE_AUTH_CREATE,
    ES_EVENT_TYPE_AUTH_CLONE,  ES_EVENT_TYPE_AUTH_TRUNCATE,
};

// The processing time a writer stores on an iteration. Never 0, and each
// writer's values fall in their own range.
int64_t TimeFor(int writer, int64_t iteration) {
  return writer * kIterations + iteration + 1;
}

}  // namespace

@interface MetricsConcurrencyTest : XCTestCase
@end

@implementation MetricsConcurrencyTest

- (void)testConcurrentWritesAndFlushesLoseNothing {
  SNTMetricSet* metricSet = [[SNTMetricSet alloc] init];
  SNTMetricInt64Gauge* eventTimes = [metricSet int64GaugeWithName:@"/test/event_processing_time"
                                                       fieldNames:@[ @"Processor", @"Event" ]
                                                         helpText:@"Test"];
  SNTMetricCounter* eventCounts =
      [metricSet counterWithName:@"/test/event_count"
                      fieldNames:@[ @"Processor", @"Event", @"Disposition" ]
                        helpText:@"Test"];
  SNTMetricCounter* rateLimitCounts = [metricSet counterWithName:@"/test/rate_limit_count"
                                                      fieldNames:@[]
                                                        helpText:@"Test"];
  SNTMetricCounter* faaEventCounts = [metricSet counterWithName:@"/test/faa_count"
                                                     fieldNames:@[]
                                                       helpText:@"Test"];
  SNTMetricCounter* dropCounts = [metricSet counterWithName:@"/test/event_drop_count"
                                                 fieldNames:@[ @"Processor", @"Event" ]
                                                   helpText:@"Test"];

  dispatch_queue_t q = dispatch_queue_create(NULL, DISPATCH_QUEUE_SERIAL);
  dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, q);
  // Shared ownership keeps these alive for the threads if the wait below times out.
  auto metrics =
      std::make_shared<MetricsPeer>(q, timer, 100, eventTimes, eventCounts, rateLimitCounts,
                                    faaEventCounts, dropCounts, metricSet,
                                    ^(Metrics*){
                                    });
  auto writersRemaining = std::make_shared<std::atomic<int>>(kWriters);
  auto start = std::make_shared<std::atomic<bool>>(false);
  auto overlappingFlushes = std::make_shared<std::atomic<int64_t>>(0);
  // Writers bump this every kProgressInterval iterations, so the flusher can
  // tell whether writes happened while it flushed.
  auto writerProgress = std::make_shared<std::atomic<int64_t>>(0);

  // Each thread leaves the group when done, so the wait below has a deadline.
  dispatch_group_t group = dispatch_group_create();
  std::vector<std::thread> threads;

  // The flusher starts first and flushes until every writer is done.
  dispatch_group_enter(group);
  threads.emplace_back([=] {
    while (!start->load(std::memory_order_acquire)) {
      std::this_thread::yield();
    }
    while (writersRemaining->load(std::memory_order_acquire) > 0) {
      int64_t progressBefore = writerProgress->load(std::memory_order_relaxed);
      metrics->FlushMetrics();
      // Writers made progress while this flush ran.
      if (writerProgress->load(std::memory_order_relaxed) != progressBefore) {
        overlappingFlushes->fetch_add(1, std::memory_order_relaxed);
      }
    }
    dispatch_group_leave(group);
  });

  for (int w = 0; w < kWriters; w++) {
    dispatch_group_enter(group);
    threads.emplace_back([=] {
      while (!start->load(std::memory_order_acquire)) {
        std::this_thread::yield();
      }
      es_event_type_t ownEvent = kPerWriterEvents[w];
      for (int64_t i = 0; i < kIterations; i++) {
        // Cells all writers share
        metrics->SetEventMetrics(Processor::kRecorder, EventDisposition::kProcessed, TimeFor(w, i),
                                 ES_EVENT_TYPE_NOTIFY_CLOSE);
        metrics->RecordDrops(Processor::kRecorder, ES_EVENT_TYPE_NOTIFY_CLOSE, 1, 2);

        // Cells only this writer touches
        metrics->SetEventMetrics(Processor::kAuthorizer, EventDisposition::kDropped, TimeFor(w, i),
                                 ownEvent);
        metrics->RecordDrops(Processor::kAuthorizer, ownEvent, w + 1, 0);

        if (i % kProgressInterval == 0) {
          writerProgress->fetch_add(1, std::memory_order_relaxed);
        }
      }
      writersRemaining->fetch_sub(1, std::memory_order_release);
      dispatch_group_leave(group);
    });
  }

  start->store(true, std::memory_order_release);

  // Well under the test target's timeout, so a hang reports this failure.
  long timedOut = dispatch_group_wait(group, dispatch_time(DISPATCH_TIME_NOW, 120 * NSEC_PER_SEC));
  if (timedOut) {
    for (std::thread& t : threads) {
      t.detach();
    }
    XCTFail(@"Writers and flusher did not finish in time");
    return;
  }
  for (std::thread& t : threads) {
    t.join();
  }

  // Without this, the test would only check the single-threaded final flush.
  XCTAssertGreaterThan(overlappingFlushes->load(), 0, @"No flush ran while writers were writing");

  metrics->FlushMetrics();

  // Shared cells
  long long sharedCount =
      [eventCounts getCountForFieldValues:@[ @"Recorder", @"NotifyClose", @"Processed" ]];
  long long sharedEventDrops = [dropCounts getCountForFieldValues:@[ @"Recorder", @"NotifyClose" ]];
  long long sharedGlobalDrops = [dropCounts getCountForFieldValues:@[ @"Recorder", @"Global" ]];
  long long sharedTime = [eventTimes getGaugeValueForFieldValues:@[ @"Recorder", @"NotifyClose" ]];
  XCTAssertEqual(sharedCount, kWriters * kIterations);
  XCTAssertEqual(sharedEventDrops, kWriters * kIterations);
  XCTAssertEqual(sharedGlobalDrops, 2 * kWriters * kIterations);
  XCTAssertGreaterThanOrEqual(sharedTime, TimeFor(0, 0));
  XCTAssertLessThanOrEqual(sharedTime, TimeFor(kWriters - 1, kIterations - 1));

  // Per-writer cells
  for (int w = 0; w < kWriters; w++) {
    NSString* event = EventTypeToString(kPerWriterEvents[w]);
    long long count = [eventCounts getCountForFieldValues:@[ @"Authorizer", event, @"Dropped" ]];
    long long drops = [dropCounts getCountForFieldValues:@[ @"Authorizer", event ]];
    long long time = [eventTimes getGaugeValueForFieldValues:@[ @"Authorizer", event ]];
    XCTAssertEqual(count, kIterations, @"%@", event);
    XCTAssertEqual(drops, (w + 1) * kIterations, @"%@", event);
    // Only this writer stores to its cell, so the exported time is its last one
    XCTAssertEqual(time, TimeFor(w, kIterations - 1), @"%@", event);
  }

  // No writer recorded global drops for the Authorizer
  long long authorizerGlobalDrops =
      [dropCounts getCountForFieldValues:@[ @"Authorizer", @"Global" ]];
  XCTAssertEqual(authorizerGlobalDrops, 0);
}

@end
