/// Copyright 2022 Google Inc. All rights reserved.
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

#include <os/log.h>
#include <sys/cdefs.h>

#import "src/common/SNTLogging.h"

__BEGIN_DECLS

void LogSyncMessage(os_log_type_t logType, NSString *message);

///  Send logs to the standard pipeline AND to any active sync
///  listeners, such as santactl or the UI.
#define SLOGD(logFormat, ...)                                                                \
  do {                                                                                       \
    LOGD(logFormat, ##__VA_ARGS__);                                                          \
    LogSyncMessage(OS_LOG_TYPE_DEBUG, [NSString stringWithFormat:logFormat, ##__VA_ARGS__]); \
  } while (0)
#define SLOGI(logFormat, ...)                                                               \
  do {                                                                                      \
    LOGI(logFormat, ##__VA_ARGS__);                                                         \
    LogSyncMessage(OS_LOG_TYPE_INFO, [NSString stringWithFormat:logFormat, ##__VA_ARGS__]); \
  } while (0)
#define SLOGW(logFormat, ...)                                                                  \
  do {                                                                                         \
    LOGW(logFormat, ##__VA_ARGS__);                                                            \
    LogSyncMessage(OS_LOG_TYPE_DEFAULT, [NSString stringWithFormat:logFormat, ##__VA_ARGS__]); \
  } while (0)
#define SLOGE(logFormat, ...)                                                                \
  do {                                                                                       \
    LOGE(logFormat, ##__VA_ARGS__);                                                          \
    LogSyncMessage(OS_LOG_TYPE_ERROR, [NSString stringWithFormat:logFormat, ##__VA_ARGS__]); \
  } while (0)

__END_DECLS
