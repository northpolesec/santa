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

#ifndef SANTA__SANTAD__EVENTPROVIDERS_ENDPOINTSECURITY_MOCKENRICHER_H
#define SANTA__SANTAD__EVENTPROVIDERS_ENDPOINTSECURITY_MOCKENRICHER_H

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <memory>
#include <optional>

#include "Source/santad/EventProviders/EndpointSecurity/Message.h"

namespace santa {

class MockEnricher : public Enricher {
 public:
  virtual ~MockEnricher() {}

  MOCK_METHOD(std::unique_ptr<EnrichedMessage>, Enrich, (Message &&));
  MOCK_METHOD(std::optional<std::shared_ptr<std::string>>, UsernameForUID,
              (uid_t uid, EnrichOptions options));
};

}  // namespace santa

#endif  // SANTA__SANTAD__EVENTPROVIDERS_ENDPOINTSECURITY_MOCKENRICHER_H
