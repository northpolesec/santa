/// Copyright 2025 North Pole Security, Inc.
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

#ifndef SANTA_COMMON_ACCOUNTLOOKUP_H
#define SANTA_COMMON_ACCOUNTLOOKUP_H

#include <sys/types.h>

#include <optional>
#include <string>
#include <string_view>

namespace santa {
namespace account {

// Thread-safe wrappers around the passwd/group database. Each uses the
// reentrant getXXX_r variant with a caller-owned, growable buffer, so
// concurrent lookups on different threads cannot clobber the process-wide
// static buffer that the non-reentrant getpwuid/getgrgid/getpwnam share.
// Each returns std::nullopt when the entry does not resolve or the lookup
// errors, and an owned value on success (no dependency on any internal buffer).

// Login name (pw_name) for a uid.
std::optional<std::string> UsernameForUID(uid_t uid);

// Home directory (pw_dir) for a uid.
std::optional<std::string> HomeDirForUID(uid_t uid);

// Group name (gr_name) for a gid.
std::optional<std::string> GroupNameForGID(gid_t gid);

// uid (pw_uid) for a login name.
std::optional<uid_t> UIDForUsername(std::string_view username);

}  // namespace account
}  // namespace santa

#endif  // SANTA_COMMON_ACCOUNTLOOKUP_H
