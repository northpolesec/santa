/// Copyright 2024 North Pole Security, Inc.
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

#include "Source/santad/MachServiceDeadWaiter.h"
#include "Source/common/SNTLogging.h"

MachServiceDeadWaiter::MachServiceDeadWaiter(std::string service_name)
    : send_port_(MACH_PORT_NULL), receive_port_(MACH_PORT_NULL) {
  if (bootstrap_look_up(bootstrap_port, service_name.c_str(), &send_port_) != KERN_SUCCESS) {
    return;
  }

  // Create a port to listen for `MACH_NOTIFY_DEAD_NAME` from `service_name`.
  if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &receive_port_) !=
      KERN_SUCCESS) {
    LOGE(@"MACH_PORT_RIGHT_RECEIVE failed\n");
    return;
  }
  mach_port_t previous_port;
  if (kern_return_t kr = mach_port_request_notification(
                           mach_task_self(), send_port_, MACH_NOTIFY_DEAD_NAME, 0, receive_port_,
                           MACH_MSG_TYPE_MAKE_SEND_ONCE, &previous_port) != KERN_SUCCESS) {
    LOGE(@"MACH_NOTIFY_DEAD_NAME notification request failed\n");
    return;
  }

  LOGI(@"wating for MACH_NOTIFY_DEAD_NAME for: %s\n", service_name.c_str());

  mach_dead_name_notification_t msg = {};
  if (mach_msg_return_t mr =
        mach_msg((mach_msg_header_t *)&msg, MACH_RCV_MSG, 0, sizeof(msg), receive_port_,
                 MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL) != MACH_MSG_SUCCESS) {
    LOGE(@"mach_msg failed: %i\n", mr);
    return;
  }

  LOGI(@"mach_msg received: %i", msg.not_header.msgh_id);
}

MachServiceDeadWaiter::~MachServiceDeadWaiter() {
  if (send_port_ != MACH_PORT_NULL) {
    mach_port_deallocate(mach_task_self(), send_port_);
  }
  if (receive_port_ != MACH_PORT_NULL) {
    mach_port_mod_refs(mach_task_self(), receive_port_, MACH_PORT_RIGHT_RECEIVE, -1);
  }
}
