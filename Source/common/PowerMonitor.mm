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

#include "Source/common/PowerMonitor.h"

#include <IOKit/IOMessage.h>
#include <IOKit/pwr_mgt/IOPMLib.h>

#import "Source/common/SNTLogging.h"

namespace santa {

std::unique_ptr<PowerMonitor> PowerMonitor::Create(PowerEventBlock callback) {
  if (!callback) {
    return nullptr;
  }

  dispatch_queue_t queue = dispatch_queue_create_with_target(
      "com.northpolesec.santa.power_monitor", DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL,
      dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0));

  // Allocate the PowerMonitor with placeholder handles. This gives us a stable
  // `this` pointer to use as the refcon for IORegisterForSystemPower. No
  // callbacks will fire until we set the dispatch queue on the notification port.
  auto monitor = std::make_unique<PowerMonitor>(PassKey(), callback, IO_OBJECT_NULL, nullptr,
                                                IO_OBJECT_NULL, queue);

  io_object_t notifier = IO_OBJECT_NULL;
  IONotificationPortRef notify_port = nullptr;

  monitor->connect_ =
      IORegisterForSystemPower(monitor.get(), &notify_port, PowerCallback, &notifier);

  if (monitor->connect_ == IO_OBJECT_NULL) {
    LOGE(@"Failed to register for system power notifications");
    return nullptr;
  }

  monitor->notify_port_ = notify_port;
  monitor->notifier_ = notifier;

  // Start delivering callbacks now that all handles are assigned.
  IONotificationPortSetDispatchQueue(notify_port, queue);

  return monitor;
}

PowerMonitor::PowerMonitor(PassKey, PowerEventBlock callback, io_connect_t connect,
                           IONotificationPortRef notify_port, io_object_t notifier,
                           dispatch_queue_t queue)
    : callback_([callback copy]),
      connect_(connect),
      notify_port_(notify_port),
      notifier_(notifier),
      queue_(queue) {}

PowerMonitor::~PowerMonitor() {
  // Stop new callbacks from being dispatched.
  if (notifier_ != IO_OBJECT_NULL) {
    IODeregisterForSystemPower(&notifier_);
  }

  // Drain any in-flight callbacks on the queue.
  if (queue_) {
    dispatch_sync(queue_, ^{
                  });
  }

  if (notify_port_ != nullptr) {
    IONotificationPortDestroy(notify_port_);
  }

  if (connect_ != IO_OBJECT_NULL) {
    IOServiceClose(connect_);
  }
}

void PowerMonitor::PowerCallback(void *refcon, io_service_t service, natural_t message_type,
                                 void *message_argument) {
  auto *monitor = static_cast<PowerMonitor *>(refcon);
  monitor->HandlePowerEvent(message_type, message_argument);
}

void PowerMonitor::HandlePowerEvent(natural_t message_type, void *message_argument) {
  switch (message_type) {
    case kIOMessageCanSystemSleep:
      callback_(PowerEvent::kCanSleep);
      IOAllowPowerChange(connect_, reinterpret_cast<long>(message_argument));
      break;
    case kIOMessageSystemWillSleep:
      callback_(PowerEvent::kWillSleep);
      IOAllowPowerChange(connect_, reinterpret_cast<long>(message_argument));
      break;
    case kIOMessageSystemWillNotSleep: callback_(PowerEvent::kWillNotSleep); break;
    case kIOMessageSystemWillPowerOn: callback_(PowerEvent::kWillPowerOn); break;
    case kIOMessageSystemHasPoweredOn: callback_(PowerEvent::kHasPoweredOn); break;
    default: break;
  }
}

}  // namespace santa
