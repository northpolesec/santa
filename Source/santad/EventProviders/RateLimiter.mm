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

#include <limits>

#include "Source/common/BranchPrediction.h"
#include "Source/common/SNTLogging.h"
#include "Source/common/SystemResources.h"

namespace santa {

RateLimiter RateLimiter::Create(std::shared_ptr<santa::Metrics> metrics, uint32_t logs_per_sec,
                                uint32_t window_size_sec) {
  return RateLimiter(std::move(metrics), logs_per_sec, window_size_sec);
}

RateLimiter::RateLimiter(std::shared_ptr<santa::Metrics> metrics, uint32_t logs_per_sec,
                         uint32_t window_size_sec, uint32_t max_window_size)
    : metrics_(std::move(metrics)), max_window_size_(max_window_size) {
  q_ = dispatch_queue_create(
      "com.northpolesec.santa.daemon.rate_limiter",
      dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL,
                                              QOS_CLASS_USER_INTERACTIVE, 0));
  ModifySettingsSerialized(logs_per_sec, window_size_sec);
}

void RateLimiter::ModifySettingsSerialized(uint32_t logs_per_sec, uint32_t window_size_sec) {
  // Semi-arbitrary window size limit of 1 hour
  if (window_size_sec > max_window_size_) {
    window_size_sec = max_window_size_;
    LOGW(@"Window size must be between 0 and %u. Clamped to: %u", max_window_size_,
         window_size_sec);
  }

  if (logs_per_sec == 0 || window_size_sec == 0) {
    // If either setting is 0, rate limiting is disabled.
    // Max out these values to ensure never to return RateLimiter::Decision::kRateLimited;
    max_log_count_total_ = std::numeric_limits<decltype(max_log_count_total_)>::max();
    reset_mach_time_ = std::numeric_limits<decltype(reset_mach_time_)>::max();
  } else {
    max_log_count_total_ = logs_per_sec * window_size_sec;
    reset_duration_ns_ = window_size_sec * NSEC_PER_SEC;
    reset_mach_time_ = 0;
  }
}

void RateLimiter::ModifySettings(uint32_t logs_per_sec, uint32_t window_size_sec) {
  dispatch_sync(q_, ^{
    ModifySettingsSerialized(logs_per_sec, window_size_sec);
  });
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
