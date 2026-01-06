/// Copyright 2024 North Pole Security, Inc.
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

#include "src/common/EncodeEntitlements.h"

#include <algorithm>

#include "src/common/SNTLogging.h"

namespace santa {

static constexpr NSUInteger kMaxEncodeObjectEntries = 64;
static constexpr NSUInteger kMaxEncodeObjectLevels = 5;

id StandardizedNestedObjects(id obj, int level) {
  if (!obj) {
    return nil;
  } else if (level-- == 0) {
    return [obj description];
  }

  if ([obj isKindOfClass:[NSNumber class]] || [obj isKindOfClass:[NSString class]]) {
    return obj;
  } else if ([obj isKindOfClass:[NSArray class]]) {
    NSMutableArray *arr = [NSMutableArray array];
    for (id item in obj) {
      [arr addObject:StandardizedNestedObjects(item, level)];
    }
    return arr;
  } else if ([obj isKindOfClass:[NSDictionary class]]) {
    NSMutableDictionary *dict = [NSMutableDictionary dictionary];
    for (id key in obj) {
      [dict setObject:StandardizedNestedObjects(obj[key], level) forKey:key];
    }
    return dict;
  } else if ([obj isKindOfClass:[NSData class]]) {
    return [obj base64EncodedStringWithOptions:0];
  } else if ([obj isKindOfClass:[NSDate class]]) {
    return [NSISO8601DateFormatter stringFromDate:obj
                                         timeZone:[NSTimeZone timeZoneWithAbbreviation:@"UTC"]
                                    formatOptions:NSISO8601DateFormatWithFractionalSeconds |
                                                  NSISO8601DateFormatWithInternetDateTime];

  } else {
    LOGW(@"Unexpected object encountered: %@", obj);
    return [obj description];
  }
}

void EncodeEntitlementsCommon(NSDictionary *entitlements, BOOL entitlements_filtered,
                              void (^EncodeInitBlock)(NSUInteger count, bool is_filtered),
                              void (^EncodeEntitlementBlock)(NSString *entitlement,
                                                             NSString *value)) {
  NSDictionary *standardized_entitlements =
      StandardizedNestedObjects(entitlements, kMaxEncodeObjectLevels);
  __block int num_objects_to_encode =
      (int)std::min(kMaxEncodeObjectEntries, standardized_entitlements.count);

  EncodeInitBlock(
      num_objects_to_encode,
      entitlements_filtered != NO || num_objects_to_encode != standardized_entitlements.count);

  [standardized_entitlements enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
    if (num_objects_to_encode-- == 0) {
      *stop = YES;
      return;
    }

    if (![key isKindOfClass:[NSString class]]) {
      LOGW(@"Skipping entitlement key with unexpected key type: %@", key);
      return;
    }

    NSError *err;
    NSData *json_data;
    @try {
      json_data = [NSJSONSerialization dataWithJSONObject:obj
                                                  options:NSJSONWritingFragmentsAllowed
                                                    error:&err];
    } @catch (NSException *e) {
      LOGW(@"Encountered entitlement that cannot directly convert to JSON: %@: %@", key, obj);
    }

    if (!json_data) {
      // If the first attempt to serialize to JSON failed, get a string
      // representation of the object via the `description` method and attempt
      // to serialize that instead. Serialization can fail for a number of
      // reasons, such as arrays including invalid types.
      @try {
        json_data = [NSJSONSerialization dataWithJSONObject:[obj description]
                                                    options:NSJSONWritingFragmentsAllowed
                                                      error:&err];
      } @catch (NSException *e) {
        LOGW(@"Unable to create fallback string: %@: %@", key, obj);
      }

      if (!json_data) {
        // As a final fallback, simply serialize an error message so that the
        // entitlement key is still logged.
        json_data = [NSJSONSerialization dataWithJSONObject:@"JSON Serialization Failed"
                                                    options:NSJSONWritingFragmentsAllowed
                                                      error:&err];
      }
    }

    // This shouldn't be possible given the fallback code above. But handle it
    // just in case to prevent a crash.
    if (!json_data) {
      LOGW(@"Failed to create valid JSON for entitlement: %@", key);
      return;
    }

    EncodeEntitlementBlock(key, [[NSString alloc] initWithData:json_data
                                                      encoding:NSUTF8StringEncoding]);
  }];
}

}  // namespace santa
