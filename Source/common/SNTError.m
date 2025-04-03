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

#import "Source/common/SNTError.h"

#include <Foundation/Foundation.h>

const NSErrorDomain SantaErrorDomain = @"com.northpolesec.santa.error";

@implementation SNTError

+ (nonnull NSError *)errorWithCode:(SNTErrorCode)code
                           message:(nonnull NSString *)msg
                            detail:(nonnull NSString *)detail {
  return [NSError errorWithDomain:SantaErrorDomain
                             code:code
                         userInfo:@{
                           NSLocalizedDescriptionKey : msg,
                           NSLocalizedFailureReasonErrorKey : detail,
                         }];
}

+ (nonnull NSError *)errorWithCode:(SNTErrorCode)code message:(NSString *)msg {
  return [NSError errorWithDomain:SantaErrorDomain
                             code:code
                         userInfo:@{
                           NSLocalizedDescriptionKey : msg,
                         }];
}

+ (nonnull NSError *)errorWithMessage:(nonnull NSString *)msg {
  return [self errorWithCode:SNTErrorCodeUnknown message:msg];
}

@end
