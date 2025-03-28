/// Copyright 2022 Google LLC
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

#include "Source/santad/EventProviders/RateLimiter.h"

#include "Source/common/BranchPrediction.h"
#include "Source/common/SystemResources.h"

using santa::Metrics;
using santa::Processor;

namespace santa {

RateLimiter RateLimiter::Create(std::shared_ptr<Metrics> metrics, uint16_t max_qps,
                                NSTimeInterval reset_duration) {
  return RateLimiter(std::move(metrics), max_qps, reset_duration);
}

RateLimiter::RateLimiter(std::shared_ptr<Metrics> metrics, uint16_t max_qps,
                         NSTimeInterval reset_duration)
    : metrics_(std::move(metrics)),
      max_log_count_total_(reset_duration * max_qps),
      reset_mach_time_(0),
      reset_duration_ns_(reset_duration * NSEC_PER_SEC) {
  q_ = dispatch_queue_create(
      "com.northpolesec.santa.daemon.rate_limiter",
      dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL,
                                              QOS_CLASS_USER_INTERACTIVE, 0));
}

bool RateLimiter::ShouldRateLimitSerialized() {
  return log_count_total_ > max_log_count_total_;
}

size_t RateLimiter::EventsRateLimitedSerialized() {
  if (unlikely(ShouldRateLimitSerialized())) {
    return log_count_total_ - max_log_count_total_;
  } else {
    return 0;
  }
}

void RateLimiter::TryResetSerialized(uint64_t cur_mach_time) {
  if (cur_mach_time > reset_mach_time_) {
    if (metrics_) {
      metrics_->AddRateLimitingMetrics(EventsRateLimitedSerialized());
    }

    log_count_total_ = 0;
    reset_mach_time_ = AddNanosecondsToMachTime(reset_duration_ns_, cur_mach_time);
  }
}

RateLimiter::Decision RateLimiter::Decide(uint64_t cur_mach_time) {
  __block RateLimiter::Decision decision;

  dispatch_sync(q_, ^{
    TryResetSerialized(cur_mach_time);

    ++log_count_total_;

    if (unlikely(ShouldRateLimitSerialized())) {
      decision = Decision::kRateLimited;
    } else {
      decision = RateLimiter::Decision::kAllowed;
    }
  });

  return decision;
}

}  // namespace santa
