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

#ifndef SANTA__SANTAD__CSOPSHELPER_H
#define SANTA__SANTAD__CSOPSHELPER_H

#include <Kernel/kern/cs_blobs.h>
#include <sys/cdefs.h>
#include <sys/types.h>

#include <cstdint>
#include <functional>
#include <optional>
#include <string>

__BEGIN_DECLS
int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);
__END_DECLS

namespace santa {

// csops operations (from XNU bsd/sys/codesign.h)
static constexpr unsigned int kCsopStatus = 0;
static constexpr unsigned int kCsopCDHash = 5;
static constexpr unsigned int kCsopIdentity = 11;
static constexpr unsigned int kCsopTeamID = 14;

// Some csops operations return data wrapped in this structure.
struct csops_blob {
  uint32_t type;
  uint32_t len;
  char data[];
};

// Injectable csops function signature for testing.
using CSOpsFunc = std::function<int(pid_t, unsigned int, void *, size_t)>;

// Retrieve the code signing status flags for a process.
std::optional<uint32_t> CSOpsStatusFlags(pid_t pid,
                                         CSOpsFunc csops_func = csops);

// Retrieve the CDHash as a lowercase hex string.
std::optional<std::string> CSOpsGetCDHash(pid_t pid,
                                          CSOpsFunc csops_func = csops);

// Retrieve the Team ID string. Returns nullopt for unsigned, adhoc, or on
// error.
std::optional<std::string> CSOpsGetTeamID(pid_t pid,
                                          CSOpsFunc csops_func = csops);

// Retrieve the Signing ID string. Returns nullopt for unsigned, adhoc, or on
// error.
std::optional<std::string> CSOpsGetSigningID(pid_t pid,
                                             CSOpsFunc csops_func = csops);

}  // namespace santa

#endif  // SANTA__SANTAD__CSOPSHELPER_H
