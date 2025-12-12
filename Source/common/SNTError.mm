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

#import <Foundation/Foundation.h>

const NSErrorDomain SantaErrorDomain = @"com.northpolesec.santa.error";

@implementation SNTError

+ (void)populateError:(NSError **)error
             withCode:(SNTErrorCode)code
              message:(nonnull NSString *)msg
               detail:(nonnull NSString *)detail {
  if (!error) return;
  *error = [NSError errorWithDomain:SantaErrorDomain
                               code:code
                           userInfo:@{
                             NSLocalizedDescriptionKey : msg,
                             NSLocalizedFailureReasonErrorKey : detail,
                           }];
}

+ (nullable NSError *)createErrorWithCode:(SNTErrorCode)code
                                  message:(nonnull NSString *)msg
                                   detail:(nonnull NSString *)detail {
  NSError *err;
  [self populateError:&err withCode:code message:msg detail:detail];
  return err;
}

+ (void)populateError:(NSError **)error
             withCode:(SNTErrorCode)code
               format:(nonnull NSString *)format, ... NS_FORMAT_FUNCTION(3, 4) {
  if (!error) return;

  va_list args;
  va_start(args, format);
  NSString *msg = [[NSString alloc] initWithFormat:format arguments:args];
  va_end(args);

  *error = [NSError errorWithDomain:SantaErrorDomain
                               code:code
                           userInfo:@{NSLocalizedDescriptionKey : msg}];
}

+ (nullable NSError *)createErrorWithCode:(SNTErrorCode)code
                                   format:(nonnull NSString *)format, ... NS_FORMAT_FUNCTION(2, 3) {
  NSError *error;

  va_list args;
  va_start(args, format);
  NSString *msg = [[NSString alloc] initWithFormat:format arguments:args];
  va_end(args);

  [self populateError:&error withCode:code format:@"%@", msg];

  return error;
}

+ (void)populateError:(NSError **)error
           withFormat:(nonnull NSString *)format, ... NS_FORMAT_FUNCTION(2, 3) {
  if (!error) return;

  va_list args;
  va_start(args, format);
  NSString *msg = [[NSString alloc] initWithFormat:format arguments:args];
  va_end(args);

  *error = [NSError errorWithDomain:SantaErrorDomain
                               code:SNTErrorCodeUnknown
                           userInfo:@{NSLocalizedDescriptionKey : msg}];
}

+ (nullable NSError *)createErrorWithFormat:(nonnull NSString *)format,
                                            ... NS_FORMAT_FUNCTION(1, 2) {
  NSError *error = nil;

  va_list args;
  va_start(args, format);
  NSString *msg = [[NSString alloc] initWithFormat:format arguments:args];
  va_end(args);

  [self populateError:&error withFormat:@"%@", msg];

  return error;
}

@end
