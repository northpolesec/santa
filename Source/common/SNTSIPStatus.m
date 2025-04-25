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

#import "SNTSIPStatus.h"

#import "SNTLogging.h"

// https://github.com/apple/darwin-xnu/blob/2ff845c2e033bd0ff64b5b6aa6063a1f8f65aa32/bsd/sys/csr.h#L38C18-L38C30
typedef uint32_t csr_config_t;

// https://github.com/apple/darwin-xnu/blob/2ff845c2e033bd0ff64b5b6aa6063a1f8f65aa32/bsd/sys/csr.h#L102
extern int csr_get_active_config(csr_config_t *) WEAK_IMPORT_ATTRIBUTE;

@implementation SNTSIPStatus

+ (csr_config_t)currentStatus {
  if (csr_get_active_config == NULL) {
    LOGW(@"csr_get_active_config is not available");
    // Returning MAX to indicate that we have been unable to get the status as returning
    // 0 would make it impossible to differentiate from SIP being fully enabled.
    return UINT32_MAX;
  };

  csr_config_t status;
  (void)csr_get_active_config(&status);
  return status;
}

@end
