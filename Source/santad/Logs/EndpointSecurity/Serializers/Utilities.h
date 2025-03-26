/// Copyright 2022 Google LLC
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

#ifndef SANTA__SANTAD__LOGS_ENDPOINTSECURITY_SERIALIZERS_UTILITIES_H
#define SANTA__SANTAD__LOGS_ENDPOINTSECURITY_SERIALIZERS_UTILITIES_H

#include <EndpointSecurity/EndpointSecurity.h>
#import <Foundation/Foundation.h>
#include <IOKit/IOKitLib.h>
#include <bsm/libbsm.h>

#include "Source/santad/EventProviders/EndpointSecurity/Message.h"

namespace santa {

static inline NSString *NonNull(NSString *str) {
  return str ?: @"";
}

NSString *OriginalPathForTranslocation(const es_process_t *es_proc);
NSString *SerialForDevice(NSString *devPath);
NSString *DiskImageForDevice(NSString *devPath);
NSString *MountFromName(NSString *path);

es_file_t *GetAllowListTargetFile(const santa::Message &msg);

/// Convert the given string token, which might be a URL, to a path
NSString *NormalizePath(es_string_token_t path);
/// Concat `path` onto `prefix` if `path` is relative
NSString *ConcatPrefixIfRelativePath(es_string_token_t path, es_string_token_t prefix);

static inline const mach_port_t GetDefaultIOKitCommsPort() {
  return kIOMainPortDefault;
}

}  // namespace santa

#endif
