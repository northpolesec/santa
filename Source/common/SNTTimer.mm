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

#import "Source/common/SNTTimer.h"

#include <memory>

#include "Source/common/Timer.h"

namespace santa {

class TimerBridge : public Timer<TimerBridge> {
 public:
  TimerBridge(SNTOnTimerCallback callback, uint32_t min_interval, uint32_t max_interval,
              Timer::OnStart on_start, std::string name, Timer::RescheduleMode reschedule_mode,
              qos_class_t qos)
      : Timer(min_interval, max_interval, on_start, std::move(name), reschedule_mode, qos),
        callback_([callback copy]) {}

  bool OnTimer() { return callback_(); }

 private:
  SNTOnTimerCallback callback_;
};

}  // namespace santa

@implementation SNTTimer {
  std::shared_ptr<santa::TimerBridge> _timer;
}

- (instancetype)initWithMinInterval:(uint32_t)minInterval
                        maxInterval:(uint32_t)maxInterval
                               name:(NSString *)name
                        fireOnStart:(BOOL)fireOnStart
                     rescheduleMode:(SNTTimerRescheduleMode)rescheduleMode
                           qosClass:(qos_class_t)qosClass
                           callback:(SNTOnTimerCallback)callback {
  if (name.length == 0) {
    return nil;
  }

  self = [super init];
  if (self) {
    _timer = std::make_shared<santa::TimerBridge>(
        callback, minInterval, maxInterval,
        fireOnStart ? santa::Timer<santa::TimerBridge>::OnStart::kFireImmediately
                    : santa::Timer<santa::TimerBridge>::OnStart::kWaitOneCycle,
        name.UTF8String ?: "<unnamed>",
        (rescheduleMode == SNTTimerRescheduleModeLeadingEdge)
            ? santa::Timer<santa::TimerBridge>::RescheduleMode::kLeadingEdge
            : santa::Timer<santa::TimerBridge>::RescheduleMode::kTrailingEdge,
        qosClass);

    if (!_timer) {
      self = nil;
    }
  }
  return self;
}

- (void)dealloc {
  if (_timer) {
    _timer->StopTimer();
  }
}

- (BOOL)startWithInterval:(uint32_t)seconds {
  return _timer->StartTimerWithInterval(seconds);
}

- (void)stop {
  _timer->StopTimer();
}

- (BOOL)isStarted {
  return _timer->IsStarted();
}

@end
