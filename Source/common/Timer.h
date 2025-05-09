/// Copyright 2025 North Pole Security, Inc.
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

#ifndef SANTA__COMMON__TIMER_H
#define SANTA__COMMON__TIMER_H

#include <Foundation/Foundation.h>
#include <dispatch/dispatch.h>
#include <sys/qos.h>

#include <algorithm>

namespace santa {

template <typename T>
class Timer {
 public:
  explicit Timer(NSTimeInterval minimum_interval,
                 dispatch_qos_class_t qos_class = QOS_CLASS_UTILITY)
      : interval_seconds_(minimum_interval), minimum_interval_(minimum_interval) {
    static_assert(
        requires(T t) { t.OnTimer(); }, "Classes using Timer<T> must implement 'void OnTimer()'");

    timer_queue_ = dispatch_get_global_queue(qos_class, 0);
  }

  virtual ~Timer() { StopTimer(); }

  /// Start a new timer if not already running.
  void StartTimer() {
    if (timer_source_) {
      return;  // No-op if already running
    }

    timer_source_ = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, timer_queue_);

    dispatch_source_set_event_handler(timer_source_, ^{
      TimerCallback();
    });

    UpdateTimingParameters();

    dispatch_resume(timer_source_);
  }

  /// Stop the timer if running.
  void StopTimer() {
    if (!timer_source_) {
      return;  // No-op if not running
    }

    ReleaseTimerSource();
  }

  /// Set new timer parameters. If the timer is running, it will fire immediately.
  void SetTimerInterval(NSTimeInterval interval_seconds) {
    interval_seconds_ = std::max(interval_seconds, minimum_interval_);
    UpdateTimingParameters();
  }

  void TimerCallback() { static_cast<T *>(this)->OnTimer(); }

 private:
  /// Update the timer firing settings. If a timer is currently active, will
  /// result in it firing in 10 seconds and then again at the current interval.
  /// The 10 second delay is to allow the sync service to launch and settle
  /// since it is often launched around the same time this timer is started.
  void UpdateTimingParameters() {
    if (timer_source_) {
      dispatch_source_set_timer(timer_source_,
                                dispatch_time(DISPATCH_WALLTIME_NOW, 10 * NSEC_PER_SEC),
                                interval_seconds_ * NSEC_PER_SEC, 0);
    }
  }

  /// Cancels the dispatch timer source.
  void ReleaseTimerSource() {
    if (timer_source_) {
      dispatch_source_cancel(timer_source_);
      timer_source_ = nullptr;
    }
  }

  dispatch_queue_t timer_queue_{nullptr};
  dispatch_source_t timer_source_{nullptr};
  NSTimeInterval interval_seconds_;
  NSTimeInterval minimum_interval_;
};

}  // namespace santa

#endif  // SANTA__COMMON__TIMER_H
