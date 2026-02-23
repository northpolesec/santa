/// Copyright 2026 North Pole Security, Inc.
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

#ifndef SANTA__COMMON__POWERMONITOR_H
#define SANTA__COMMON__POWERMONITOR_H

#include <IOKit/IOKitLib.h>
#include <IOKit/pwr_mgt/IOPMLib.h>
#include <dispatch/dispatch.h>

#include <memory>

#include "Source/common/PassKey.h"

namespace santa {

enum class PowerEvent {
  kCanSleep,
  kWillNotSleep,
  kWillSleep,
  kWillPowerOn,
  kHasPoweredOn,
};

using PowerEventBlock = void (^)(PowerEvent event);

class PowerMonitor : public PassKey<PowerMonitor> {
 public:
  static std::unique_ptr<PowerMonitor> Create(PowerEventBlock callback);

  PowerMonitor(PassKey, PowerEventBlock callback, io_connect_t connect,
               IONotificationPortRef notify_port, io_object_t notifier, dispatch_queue_t queue);

  // WARNING: Must not be destroyed from within the PowerEventBlock callback.
  // The destructor synchronously drains the dispatch queue, so destroying
  // from a callback running on that queue will deadlock. E.g., don't do this:
  // ```
  //   __block std::unique_ptr<PowerMonitor> monitor;
  //   monitor = PowerMonitor::Create(^(PowerEvent event) {
  //     monitor.reset();  // destructor runs on queue_, dispatch_sync deadlocks
  //   });
  // ```
  ~PowerMonitor();

  // Non-copyable and non-movable because `this` is used as the IOKit refcon.
  PowerMonitor(const PowerMonitor &) = delete;
  PowerMonitor &operator=(const PowerMonitor &) = delete;
  PowerMonitor(PowerMonitor &&) = delete;
  PowerMonitor &operator=(PowerMonitor &&) = delete;

 private:
  static void PowerCallback(void *refcon, io_service_t service, natural_t message_type,
                            void *message_argument);

  void HandlePowerEvent(natural_t message_type, void *message_argument);

  PowerEventBlock callback_;
  io_connect_t connect_;
  IONotificationPortRef notify_port_;
  io_object_t notifier_;
  dispatch_queue_t queue_;
};

}  // namespace santa

#endif  // SANTA__COMMON__POWERMONITOR_H
