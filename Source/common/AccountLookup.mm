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

#include "Source/common/AccountLookup.h"

#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <unistd.h>

#include <algorithm>
#include <string>
#include <vector>

namespace santa {
namespace account {

namespace {

// Invokes `lookup(buf_ptr, buf_len)` — which must call a getXXX_r function and
// return its rc — using `buf` as the scratch storage. getXXX_r returns ERANGE
// when the entry doesn't fit; grow `buf` and retry so directory-backed
// (LDAP/AD) entries larger than the initial buffer still resolve. Cap the
// growth so a pathological entry can't drive unbounded allocation. `buf` is
// owned by the caller so the string members of the filled struct (which point
// into it) stay valid while the caller copies out the field it needs.
template <typename Fn>
int LookupWithGrowingBuffer(std::vector<char>& buf, long initial_size, Fn&& lookup) {
  static constexpr size_t kMaxSize = 1 << 20;  // 1 MiB ceiling (see comment above).
  size_t size = initial_size > 0 ? static_cast<size_t>(initial_size) : 1024;
  buf.resize(std::min(size, kMaxSize));
  int rc;
  while ((rc = lookup(buf.data(), buf.size())) == ERANGE && buf.size() < kMaxSize) {
    buf.resize(std::min(buf.size() * 2, kMaxSize));
  }
  return rc;
}

}  // namespace

std::optional<std::string> UsernameForUID(uid_t uid) {
  struct passwd pwd;
  struct passwd* result = nullptr;
  std::vector<char> buf;
  int rc = LookupWithGrowingBuffer(buf, sysconf(_SC_GETPW_R_SIZE_MAX), [&](char* b, size_t n) {
    return getpwuid_r(uid, &pwd, b, n, &result);
  });
  if (rc != 0 || result == nullptr || pwd.pw_name == nullptr) {
    return std::nullopt;
  }
  return std::string(pwd.pw_name);
}

std::optional<std::string> HomeDirForUID(uid_t uid) {
  struct passwd pwd;
  struct passwd* result = nullptr;
  std::vector<char> buf;
  int rc = LookupWithGrowingBuffer(buf, sysconf(_SC_GETPW_R_SIZE_MAX), [&](char* b, size_t n) {
    return getpwuid_r(uid, &pwd, b, n, &result);
  });
  if (rc != 0 || result == nullptr || pwd.pw_dir == nullptr) {
    return std::nullopt;
  }
  return std::string(pwd.pw_dir);
}

std::optional<std::string> GroupNameForGID(gid_t gid) {
  struct group grp;
  struct group* result = nullptr;
  std::vector<char> buf;
  int rc = LookupWithGrowingBuffer(buf, sysconf(_SC_GETGR_R_SIZE_MAX), [&](char* b, size_t n) {
    return getgrgid_r(gid, &grp, b, n, &result);
  });
  if (rc != 0 || result == nullptr || grp.gr_name == nullptr) {
    return std::nullopt;
  }
  return std::string(grp.gr_name);
}

std::optional<uid_t> UIDForUsername(std::string_view username) {
  std::string name(username);  // getpwnam_r requires a NUL-terminated string.
  struct passwd pwd;
  struct passwd* result = nullptr;
  std::vector<char> buf;
  int rc = LookupWithGrowingBuffer(buf, sysconf(_SC_GETPW_R_SIZE_MAX), [&](char* b, size_t n) {
    return getpwnam_r(name.c_str(), &pwd, b, n, &result);
  });
  if (rc != 0 || result == nullptr) {
    return std::nullopt;
  }
  return pwd.pw_uid;
}

}  // namespace account
}  // namespace santa
