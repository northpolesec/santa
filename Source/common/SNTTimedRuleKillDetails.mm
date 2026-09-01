/// Copyright 2026 North Pole Security, Inc.
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

#import "Source/common/SNTTimedRuleKillDetails.h"

#import "Source/common/CoderMacros.h"

@implementation SNTTimedRuleKillDetails

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder*)coder {
  ENCODE(coder, application);
  ENCODE(coder, deadline);
  ENCODE_BOXABLE(coder, ruleType);
  ENCODE(coder, publisher);
  ENCODE(coder, user);
  ENCODE(coder, path);
  ENCODE(coder, signingID);
  ENCODE(coder, cdhash);
  ENCODE(coder, parentName);
  ENCODE(coder, ppid);
  ENCODE(coder, timeWindow);
}

- (instancetype)initWithCoder:(NSCoder*)decoder {
  self = [super init];
  if (self) {
    DECODE(decoder, application, NSString);
    DECODE(decoder, deadline, NSDate);
    DECODE_SELECTOR(decoder, ruleType, NSNumber, integerValue);
    DECODE(decoder, publisher, NSString);
    DECODE(decoder, user, NSString);
    DECODE(decoder, path, NSString);
    DECODE(decoder, signingID, NSString);
    DECODE(decoder, cdhash, NSString);
    DECODE(decoder, parentName, NSString);
    DECODE(decoder, ppid, NSNumber);
    DECODE(decoder, timeWindow, SNTRuleTimeWindow);
  }
  return self;
}

@end
