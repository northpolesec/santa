/// Copyright 2022 Google Inc. All rights reserved.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///    http://www.apache.org/licenses/LICENSE-2.0
///
///    Unless required by applicable law or agreed to in writing, software
///    distributed under the License is distributed on an "AS IS" BASIS,
///    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
///    See the License for the specific language governing permissions and
///    limitations under the License.

#include "Source/santad/Logs/EndpointSecurity/Writers/Syslog.h"

#include <os/log.h>

namespace santa {

// Max length of data that should be displayed in a single line.
// Typed as size_type to match vector.size(), but must be convertible to int.
static constexpr std::vector<uint8_t>::size_type kMaxLineLength = 1024;
static_assert(kMaxLineLength <= INT_MAX);

std::shared_ptr<Syslog> Syslog::Create() {
  return std::make_shared<Syslog>();
}

void Syslog::Write(std::vector<uint8_t> &&bytes) {
  os_log(OS_LOG_DEFAULT, "%{public}.*s", (int)std::min(kMaxLineLength, bytes.size()), bytes.data());
}

void Syslog::Flush() {
  // Nothing to do here
}

}  // namespace santa
