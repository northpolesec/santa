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
  enum class Mode {
    kContinuous,  // Default: timer fires repeatedly at intervals
    kSingleShot,  // Timer is cancelled while OnTimer fires and restarted once complete
  };

  explicit Timer(NSTimeInterval minimum_interval, Mode mode = Mode::kContinuous,
                 dispatch_qos_class_t qos_class = QOS_CLASS_UTILITY)
      : interval_seconds_(minimum_interval), minimum_interval_(minimum_interval), mode_(mode) {
    static_assert(
        requires(T t) { t.OnTimer(); }, "Classes using Timer<T> must implement 'void OnTimer()'");

    timer_queue_ = dispatch_get_global_queue(qos_class, 0);
  }

  virtual ~Timer() { StopTimer(); }

  /// Start a new timer if not already running.
  void StartTimer() { StartTimer(false); }

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
    UpdateTimingParameters(false);
  }

  void TimerCallback() {
    if (mode_ == Mode::kSingleShot) {
      // In SingleShot mode, call OnTimer between cancelling and restarting the timer
      ReleaseTimerSource();
      static_cast<T *>(this)->OnTimer();
      StartTimer(true);
    } else {
      // Continuous mode - just call OnTimer
      static_cast<T *>(this)->OnTimer();
    }
  }

 private:
  void StartTimer(bool is_restart) {
    if (timer_source_) {
      return;  // No-op if already running
    }

    timer_source_ = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, timer_queue_);

    dispatch_source_set_event_handler(timer_source_, ^{
      TimerCallback();
    });

    UpdateTimingParameters(is_restart);

    dispatch_resume(timer_source_);
  }

  /// Update the timer firing settings.
  /// In SingleShot Mode:
  ///   If the update is from a restart, will wait a full interval cycle.
  ///   Otherwise, will use a 10 second "startup" value to allow changes to settle.
  /// In Continuous Mode:
  ///   An initial 10 second "startup" value is used to allow the system to settle
  ///   and will then fire continuously on every interval cycle.
  void UpdateTimingParameters(bool is_restart) {
    if (!timer_source_) {
      return;
    }

    dispatch_time_t start_time;

    if (is_restart && mode_ == Mode::kSingleShot) {
      // On restart in SingleShot mode, use the normal interval as the start time argument
      start_time = dispatch_time(DISPATCH_WALLTIME_NOW, interval_seconds_ * NSEC_PER_SEC);
    } else {
      // On initial start or timing interval changes, use 10 second delay
      start_time = dispatch_time(DISPATCH_WALLTIME_NOW, 10 * NSEC_PER_SEC);
    }

    if (mode_ == Mode::kSingleShot) {
      // For single-shot mode, set up a one-time timer
      dispatch_source_set_timer(timer_source_, start_time, DISPATCH_TIME_FOREVER, 0);
    } else {
      // For continuous mode, set up repeating timer
      dispatch_source_set_timer(timer_source_, start_time, interval_seconds_ * NSEC_PER_SEC, 0);
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
  Mode mode_;
};

}  // namespace santa

#endif  // SANTA__COMMON__TIMER_H
