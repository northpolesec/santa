/// Copyright 2026 North Pole Security, Inc.
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

#ifndef SANTA__COMMON__ES__ESMETRICSOBSERVER_H
#define SANTA__COMMON__ES__ESMETRICSOBSERVER_H

#include <EndpointSecurity/ESTypes.h>

#include <cstdint>

namespace santa {

enum class Processor {
  kUnknown = 0,
  kAuthorizer,
  kDeviceManager,
  kRecorder,
  kTamperResistance,
  kDataFileAccessAuthorizer,
  kProcessFileAccessAuthorizer,
};

enum class EventDisposition {
  kProcessed = 0,
  kDropped,
};

class ESMetricsObserver {
 public:
  virtual ~ESMetricsObserver() = default;
  virtual void UpdateEventStats(Processor processor, es_event_type_t event_type,
                                uint64_t seq_num, uint64_t global_seq_num) = 0;
  virtual void SetEventMetrics(Processor processor,
                               EventDisposition disposition, int64_t nanos,
                               es_event_type_t event_type) = 0;
};

}  // namespace santa

#endif  // SANTA__COMMON__ES__ESMETRICSOBSERVER_H
