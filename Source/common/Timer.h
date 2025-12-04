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
#include <string>

#import "Source/common/SNTLogging.h"

namespace santa {

// This is a CRTP mixin class template. Derived classes must provide the interface:
//   bool OnTimer(void);
// Derived classes can prevent future timer scheduling by returning `false` from `OnTimer`.
//
// NB: This class is thread safe. However, OnTimer implementations currently cannot call
// back into public methods as this will create a deadlock.
template <typename T>
class Timer : public std::enable_shared_from_this<Timer<T>> {
 public:
  enum class RescheduleMode {
    // Default: timer is reschedule immediately, prior to OnTimer being called
    kLeadingEdge,
    // Timer is rescheduled after OnTimer returns
    kTrailingEdge,
  };

  enum class OnStart {
    // The timer will fire immediately on start, then at each subsequent interval
    kFireImmediately,
    // The timer will fire after the first interval and each subsequent interval
    kWaitOneCycle,
  };

  Timer(uint32_t minimum_interval, uint32_t maximum_interval, OnStart startup_option,
        std::string backing_config_var,
        RescheduleMode reschedule_mode = RescheduleMode::kLeadingEdge,
        dispatch_qos_class_t qos_class = QOS_CLASS_UTILITY)
      : interval_seconds_(minimum_interval),
        minimum_interval_(minimum_interval),
        maximum_interval_(maximum_interval),
        startup_option_(startup_option),
        backing_config_var_(std::move(backing_config_var)),
        reschedule_mode_(reschedule_mode) {
    static_assert(
        requires(T t) {
          { t.OnTimer() } -> std::same_as<bool>;
        }, "Classes using Timer<T> must implement 'bool OnTimer()'");

    timer_queue_ = dispatch_queue_create("com.northpolesec.santa.timer", DISPATCH_QUEUE_SERIAL);
    dispatch_set_target_queue(timer_queue_, dispatch_get_global_queue(qos_class, 0));
  }

  virtual ~Timer() { StopTimer(); }

  /// Start a new timer if not already running.
  bool StartTimer() {
    __block bool did_start_new_timer;
    dispatch_sync(timer_queue_, ^{
      did_start_new_timer = StartTimerSerialized();
    });
    return did_start_new_timer;
  }

  /// Stop the timer if running.
  bool StopTimer() {
    __block bool did_stop;
    dispatch_sync(timer_queue_, ^{
      did_stop = StopTimerSerialized();
    });
    return did_stop;
  }

  void TimerCallback() {
    if (reschedule_mode_ == RescheduleMode::kTrailingEdge) {
      // If rescheduling on the trailing edge, Stop the timer and then
      // restart if requested.
      StopTimerSerialized();
      if (static_cast<T *>(this)->OnTimer()) {
        // When restarting the timer on the trailing edge, always wait one cycle.
        StartTimerSerialized(OnStart::kWaitOneCycle);
      }
    } else {
      // If rescheduling on the leading edge, the timer will have already
      // started, but stop it if requested.
      if (!static_cast<T *>(this)->OnTimer()) {
        StopTimerSerialized();
      }
    }
  }

  bool StartTimerWithInterval(uint32_t interval_seconds) {
    __block bool did_start_new_timer;
    dispatch_sync(timer_queue_, ^{
      SetTimerIntervalSerialized(interval_seconds);
      did_start_new_timer = StartTimerSerialized();
    });
    return did_start_new_timer;
  }

  /// Set new timer parameters. If the timer is running, the new parameters will take effect
  /// immediately, and may fire immediately based on the OnStart mode used during construction.
  void SetTimerInterval(uint32_t interval_seconds) {
    dispatch_sync(timer_queue_, ^{
      SetTimerIntervalSerialized(interval_seconds);
    });
  }

  bool IsStarted() const {
    __block bool is_started;
    dispatch_sync(timer_queue_, ^{
      is_started = (timer_source_ != nullptr);
    });
    return is_started;
  }

 protected:
  // Convenience method to provide shared_from_this to derived classes
  template <typename U>
  std::shared_ptr<U> shared_from_base() {
    return std::static_pointer_cast<T>(this->shared_from_this());
  }

  // Convenience method to provide weak_from_this to derived classes
  template <typename U>
  std::weak_ptr<U> weak_from_base() {
    return std::weak_ptr<U>(std::static_pointer_cast<U>(this->shared_from_this()));
  }

  // Like SetTimerInterval, but doesn't clamp to min/max
  // This is a protected interface that is exposed for testing.
  void ForceSetIntervalForTestingUnsafe(uint32_t interval_seconds) {
    interval_seconds_ = interval_seconds;
    UpdateTimingParametersSerialized(startup_option_);
  }

 private:
  inline bool StartTimerSerialized() { return StartTimerSerialized(startup_option_); }

  bool StartTimerSerialized(OnStart on_start) {
    if (timer_source_) {
      return false;  // No-op if already running
    }

    timer_source_ = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, timer_queue_);

    std::weak_ptr<Timer<T>> weak_self = this->shared_from_this();
    dispatch_source_set_event_handler(timer_source_, ^{
      if (auto strong_self = weak_self.lock()) {
        strong_self->TimerCallback();
      }
    });

    UpdateTimingParametersSerialized(on_start);

    dispatch_resume(timer_source_);

    return true;
  }

  /// Update the timer firing settings.
  /// In trailing edge scheduling, if the update is from a restart, will wait a full interval cycle.
  /// Otherwise, the startup delay is based on `startup_option_` to determine if
  /// the timer should fire immediately or wait a full cycle first.
  void UpdateTimingParametersSerialized(OnStart on_start) {
    if (!timer_source_) {
      return;
    }

    dispatch_time_t start_time;

    if (on_start == OnStart::kFireImmediately) {
      start_time = dispatch_time(DISPATCH_WALLTIME_NOW, 0);
    } else {
      start_time = dispatch_time(DISPATCH_WALLTIME_NOW, interval_seconds_ * NSEC_PER_SEC);
    }

    if (reschedule_mode_ == RescheduleMode::kTrailingEdge) {
      // For trailing edge scheduling, set up a one-time timer
      dispatch_source_set_timer(timer_source_, start_time, DISPATCH_TIME_FOREVER, 0);
    } else {
      // For leading edge scheduling, set up repeating timer
      dispatch_source_set_timer(timer_source_, start_time, interval_seconds_ * NSEC_PER_SEC, 0);
    }
  }

  void SetTimerIntervalSerialized(uint32_t interval_seconds) {
    interval_seconds_ = std::clamp(interval_seconds, minimum_interval_, maximum_interval_);
    if (interval_seconds_ != interval_seconds) {
      LOGW(@"Invalid config value for \"%s\": %u. Must be between %u and %u. Clamped to: %u.",
           backing_config_var_.c_str(), interval_seconds, minimum_interval_, maximum_interval_,
           interval_seconds_);
    }
    UpdateTimingParametersSerialized(startup_option_);
  }

  /// Cancels the dispatch timer source.
  inline bool StopTimerSerialized() {
    if (timer_source_) {
      dispatch_source_cancel(timer_source_);
      timer_source_ = nullptr;
      return true;
    } else {
      return false;
    }
  }

  dispatch_queue_t timer_queue_{nullptr};
  dispatch_source_t timer_source_{nullptr};
  uint32_t interval_seconds_;
  uint32_t minimum_interval_;
  uint32_t maximum_interval_;
  OnStart startup_option_;
  std::string backing_config_var_;
  RescheduleMode reschedule_mode_;
};

}  // namespace santa

#endif  // SANTA__COMMON__TIMER_H
