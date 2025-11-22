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

#include <memory>
#include <optional>

#include "Source/common/PassKey.h"
#include "Source/common/SNTConfigurator.h"
#include "Source/common/SNTModeTransition.h"
#include "Source/common/Timer.h"
#import "Source/santad/SNTNotificationQueue.h"

#ifndef SANTA__SANTAD__TEMPORARYMONITORMODE_H
#define SANTA__SANTAD__TEMPORARYMONITORMODE_H

namespace santa {

class TemporaryMonitorMode : public Timer<TemporaryMonitorMode>,
                             public PassKey<TemporaryMonitorMode> {
 public:
  // Factory
  static std::shared_ptr<TemporaryMonitorMode> Create(SNTNotificationQueue *not_queue,
                                                      NSDictionary *tmm);

  // Construction and setup require a PassKey, can only be used internally.
  TemporaryMonitorMode(PassKey, SNTNotificationQueue *not_queue);
  void SetupFromState(PassKey, NSDictionary *tmm);

  // No moves, no copies
  TemporaryMonitorMode(TemporaryMonitorMode &&other) = delete;
  TemporaryMonitorMode &operator=(TemporaryMonitorMode &&rhs) = delete;
  TemporaryMonitorMode(const TemporaryMonitorMode &other) = delete;
  TemporaryMonitorMode &operator=(const TemporaryMonitorMode &other) = delete;

  // Enter Monitor Mode temporarily for the requested duration.
  // Returns the actual number of minutes allowed, or 0 if error.
  uint32_t RequestMinutes(NSNumber *requested_duration, NSError **err);

  // Cancel an existing temporary Monitor Mode session.
  // Return true if a session was active, otherwise false.
  bool Cancel();

  // Cancel an existing temporary Monitor Mode session and revoke any
  // stored mode transition sync setting to prevent future sessions.
  // Return true if a session was active, otherwise false.
  bool Revoke();

  bool OnTimer();

  // If a temporary Monitor Mode session is active, return the number of
  // of seconds remaining. Otherwise nullopt.
  std::optional<uint64_t> SecondsRemaining();

  // If the mode transition was authorization was revoked, immediate cancel
  // any existing session. The configurator sync settings are also updated.
  void NewModeTransitionReceived(SNTModeTransition *mode_transition);

 private:
  // Require at least 15 seconds left of Monitor Mode a previously authorized
  // Temporary Monitor Mode session in order to re-enter. Otherwise don't bother.
  static constexpr uint64_t kMinAllowedStateRemainingSeconds = 15;

  void Begin(uint32_t seconds);
  bool End();
  uint64_t GetSecondsRemainingFromInitialState(NSDictionary *tmm);
  std::optional<uint64_t> SecondsRemaining(uint64_t deadline_mach_time);

  // hide the base class Start/Stop methods
  void StartTimer();
  void StopTimer();

  SNTNotificationQueue *notification_queue_;
  SNTConfigurator *configurator_;
  uint64_t deadline_;
};

}  // namespace santa

#endif  // SANTA__SANTAD__TEMPORARYMONITORMODE_H
