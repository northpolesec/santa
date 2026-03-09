/// Copyright 2026 North Pole Security, Inc.
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

#import "Source/common/SNTCELFallbackRule.h"

#import "Source/common/CoderMacros.h"

@interface SNTCELFallbackRule ()
@property(readwrite, copy) NSString *celExpr;
@property(readwrite, copy) NSString *customMsg;
@property(readwrite, copy) NSString *customURL;
@end

@implementation SNTCELFallbackRule

- (instancetype)initWithCELExpr:(NSString *)celExpr
                      customMsg:(NSString *)customMsg
                      customURL:(NSString *)customURL {
  self = [super init];
  if (self) {
    _celExpr = [celExpr copy];
    _customMsg = [customMsg copy];
    _customURL = [customURL copy];
  }
  return self;
}

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder {
  ENCODE(coder, celExpr);
  ENCODE(coder, customMsg);
  ENCODE(coder, customURL);
}

- (instancetype)initWithCoder:(NSCoder *)decoder {
  self = [super init];
  if (self) {
    DECODE(decoder, celExpr, NSString);
    DECODE(decoder, customMsg, NSString);
    DECODE(decoder, customURL, NSString);
  }
  return self;
}

@end
