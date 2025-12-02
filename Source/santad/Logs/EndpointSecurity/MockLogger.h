/// Copyright 2022 Google LLC
/// Copyright 2024 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     http://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#ifndef SANTA__SANTAD__LOGS_ENDPOINTSECURITY_MOCKLOGGER_H
#define SANTA__SANTAD__LOGS_ENDPOINTSECURITY_MOCKLOGGER_H

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "Source/common/TelemetryEventMap.h"
#include "Source/santad/EventProviders/EndpointSecurity/EnrichedTypes.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/Logs/EndpointSecurity/Logger.h"

class MockLogger : public santa::Logger {
 public:
  using Logger::Logger;

  MockLogger()
      : Logger(nil, nil, santa::TelemetryEvent::kEverything, 0, 0, 0, nullptr,
               nullptr) {}

  MOCK_METHOD(void, Log, (std::unique_ptr<santa::EnrichedMessage>));

  MOCK_METHOD(void, LogFileAccess,
              (const std::string &policy_version,
               const std::string &policy_name, const santa::Message &msg,
               const santa::EnrichedProcess &enriched_process,
               size_t target_index,
               std::optional<santa::EnrichedFile> enriched_event_target,
               FileAccessPolicyDecision decision));
};

#endif
