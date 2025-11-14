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

#import <Foundation/Foundation.h>

extern const _Nonnull NSErrorDomain SantaErrorDomain;

typedef NS_ENUM(NSInteger, SNTErrorCode) {
  SNTErrorCodeUnknown,

  // General errors
  SNTErrorCodeInvalidType = 110,
  SNTErrorCodeManualRulesDisabled = 111,

  // I/O errors
  SNTErrorCodeFailedToResolvePath = 210,
  SNTErrorCodeEmptyPath = 220,
  SNTErrorCodeFailedToOpen = 230,
  SNTErrorCodeNonRegularFile = 240,

  // Sync errors
  SNTErrorCodeFailedToParseJSON = 310,
  SNTErrorCodeFailedToParseProto = 320,
  SNTErrorCodeFailedToHTTP = 330,

  // Config validation errors
  SNTErrorCodeRuleInvalid = 410,
  SNTErrorCodeRuleMissingIdentifier = 411,
  SNTErrorCodeRuleInvalidIdentifier = 412,
  SNTErrorCodeRuleMissingPolicy = 413,
  SNTErrorCodeRuleInvalidPolicy = 414,
  SNTErrorCodeRuleMissingRuleType = 415,
  SNTErrorCodeRuleInvalidRuleType = 416,
  SNTErrorCodeRuleInvalidCELExpression = 417,

  // Database errors
  SNTErrorCodeEmptyRuleArray = 510,
  SNTErrorCodeInsertOrReplaceRuleFailed = 511,
  SNTErrorCodeRemoveRuleFailed = 512,
};

@interface SNTError : NSObject

// Generate a new error using the provided code, message, and details and populate into the provided
// NSError. `msg` will populate the NSLocalizedErrorDescription key. `detail` will populate the
// NSLocalizedFailureReasonErrorKey key.
+ (void)populateError:(NSError *_Nullable *_Nullable)error
             withCode:(SNTErrorCode)code
              message:(nonnull NSString *)msg
               detail:(nonnull NSString *)detail;

// Generate a new error with the provided code and format-string message, and populate into the
// provided NSError; `msg` will populate the NSLocalizedErrorDescription key.
+ (void)populateError:(NSError *_Nullable *_Nullable)error
             withCode:(SNTErrorCode)code
               format:(nonnull NSString *)format, ... NS_FORMAT_FUNCTION(3, 4);

// Generate a new error with the provided format-string message, and populate into the provided
// NSError; `msg` will populate the NSLocalizedErrorDescription key. The error code will be
// SNTErrorCodeUnknown.
+ (void)populateError:(NSError *_Nullable *_Nullable)error
           withFormat:(nonnull NSString *)format, ... NS_FORMAT_FUNCTION(2, 3);

// Return a new SNTError with the provided format string message.
// `msg` will populate the NSLocalizedErrorDescription key. The error code
// will be SNTErrorCodeUnknown.
+ (nullable NSError *)createErrorWithFormat:(nonnull NSString *)format,
                                            ... NS_FORMAT_FUNCTION(1, 2);

@end
