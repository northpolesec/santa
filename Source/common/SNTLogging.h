/// Copyright 2015 Google Inc. All rights reserved.
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

#ifndef SANTA__COMMON__LOGGING_H
#define SANTA__COMMON__LOGGING_H

#import <Foundation/Foundation.h>
#include <os/log.h>
#include <sys/cdefs.h>

__BEGIN_DECLS

#define SNT_LOG_WITH_TYPE(type, fmt, ...)      \
  os_log_with_type(OS_LOG_DEFAULT, type, "%s", \
                   [[NSString stringWithFormat:fmt, ##__VA_ARGS__] UTF8String])

#define LOGD(logFormat, ...) SNT_LOG_WITH_TYPE(OS_LOG_TYPE_DEBUG, logFormat, ##__VA_ARGS__)
#define LOGI(logFormat, ...) SNT_LOG_WITH_TYPE(OS_LOG_TYPE_INFO, logFormat, ##__VA_ARGS__)
#define LOGW(logFormat, ...) SNT_LOG_WITH_TYPE(OS_LOG_TYPE_DEFAULT, logFormat, ##__VA_ARGS__)
#define LOGE(logFormat, ...) SNT_LOG_WITH_TYPE(OS_LOG_TYPE_ERROR, logFormat, ##__VA_ARGS__)

__END_DECLS

#endif  // SANTA__COMMON__LOGGING_H
