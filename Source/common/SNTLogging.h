/// Copyright 2015 Google Inc. All rights reserved.
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

#ifndef SANTA_COMMON_SNTLOGGING_H
#define SANTA_COMMON_SNTLOGGING_H

#import <Foundation/Foundation.h>
#include <os/log.h>
#include <sys/cdefs.h>

// Every Santa component logs under a single subsystem, which lets the whole
// product be configured with one logging configuration profile. This is the
// reason not to use OS_LOG_DEFAULT: os_log(5) states that "behavior involving
// the OS_LOG_DEFAULT constant is not affected by configuration profiles", so
// logging through it cannot have its level, persistence, or message size limit
// changed for Santa alone - only system-wide.
#ifndef SNT_LOG_SUBSYSTEM
#define SNT_LOG_SUBSYSTEM "com.northpolesec.santa"
#endif

// Categories subdivide the subsystem and are the unit that configuration
// profiles address. A target that needs its own category can define this in its
// copts; everything else shares the default. Note that the process name is
// already recorded on every log message, so there is no need to spend a
// category distinguishing Santa's components from each other.
#ifndef SNT_LOG_CATEGORY
#define SNT_LOG_CATEGORY "santa"
#endif

namespace santa {

// The handle used by the LOG* macros below. The logging system interns handles,
// so all translation units including this header share a single object per
// (subsystem, category) pair.
static inline os_log_t LogHandle() {
  // C++11 onward guarantees thread-safe initialization of function-local
  // statics, so this needs no explicit synchronization.
  static os_log_t handle = os_log_create(SNT_LOG_SUBSYSTEM, SNT_LOG_CATEGORY);
  return handle;
}

// Creates a handle for an explicit category within Santa's subsystem, for the
// uncommon call site that should not log under its target's default category.
// os_log_create costs roughly 40ns even when the category already exists, so
// callers on a hot path must cache the result rather than calling this per
// message.
static inline os_log_t LogHandleForCategory(const char* category) {
  return os_log_create(SNT_LOG_SUBSYSTEM, category);
}

}  // namespace santa

__BEGIN_DECLS

#define SNT_LOG_WITH_TYPE(type, fmt, ...)                  \
  os_log_with_type(santa::LogHandle(), type, "%{public}s", \
                   [[NSString stringWithFormat:fmt, ##__VA_ARGS__] UTF8String])

#define SNT_PRINT_LOG(file, fmt, ...) \
  fprintf(file, "%s\n", [[NSString stringWithFormat:fmt, ##__VA_ARGS__] UTF8String]);

#define LOGD(logFormat, ...) SNT_LOG_WITH_TYPE(OS_LOG_TYPE_DEBUG, logFormat, ##__VA_ARGS__)
#define LOGI(logFormat, ...) SNT_LOG_WITH_TYPE(OS_LOG_TYPE_INFO, logFormat, ##__VA_ARGS__)
#define LOGW(logFormat, ...) SNT_LOG_WITH_TYPE(OS_LOG_TYPE_DEFAULT, logFormat, ##__VA_ARGS__)
#define LOGE(logFormat, ...) SNT_LOG_WITH_TYPE(OS_LOG_TYPE_ERROR, logFormat, ##__VA_ARGS__)

// The TEE_LOG* variants print both via os_log and to either stdout or stderr.
// These are largely intended to be used by santactl.
#define TEE_LOGD(logFormat, ...)                     \
  do {                                               \
    LOGD(logFormat, ##__VA_ARGS__);                  \
    SNT_PRINT_LOG(stdout, logFormat, ##__VA_ARGS__); \
  } while (0)

#define TEE_LOGI(logFormat, ...)                     \
  do {                                               \
    LOGI(logFormat, ##__VA_ARGS__);                  \
    SNT_PRINT_LOG(stdout, logFormat, ##__VA_ARGS__); \
  } while (0)

// TEE_LOGW will log to the system log as a default log type, but output to
// the terminal will be sent to stderr so as not to interfere with stdout.
#define TEE_LOGW(logFormat, ...)                     \
  do {                                               \
    LOGW(logFormat, ##__VA_ARGS__);                  \
    SNT_PRINT_LOG(stderr, logFormat, ##__VA_ARGS__); \
  } while (0)

#define TEE_LOGE(logFormat, ...)                     \
  do {                                               \
    LOGE(logFormat, ##__VA_ARGS__);                  \
    SNT_PRINT_LOG(stderr, logFormat, ##__VA_ARGS__); \
  } while (0)

__END_DECLS

#endif  // SANTA_COMMON_SNTLOGGING_H
