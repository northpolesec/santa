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

#import "Source/common/SNTStoredFileAccessEvent.h"

#import "Source/common/CoderMacros.h"
#import "Source/common/SNTStoredProcess.h"

@implementation SNTStoredFileAccessEvent

- (instancetype)init {
  self = [super init];
  if (self) {
    _process = [[SNTStoredProcess alloc] init];
  }
  return self;
}
+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder*)coder {
  [super encodeWithCoder:coder];
  ENCODE(coder, accessedPath);
  ENCODE(coder, ruleVersion);
  ENCODE(coder, ruleName);
  ENCODE(coder, process);
  ENCODE_BOXABLE(coder, decision);
  ENCODE_BOXABLE(coder, ruleId);
}

- (instancetype)initWithCoder:(NSCoder*)decoder {
  self = [super initWithCoder:decoder];
  if (self) {
    DECODE(decoder, ruleVersion, NSString);
    DECODE(decoder, ruleName, NSString);
    DECODE(decoder, accessedPath, NSString);
    DECODE(decoder, process, SNTStoredProcess);
    DECODE_SELECTOR(decoder, decision, NSNumber, intValue);
    DECODE_SELECTOR(decoder, ruleId, NSNumber, longLongValue);
  }
  return self;
}

- (NSString*)description {
  return [NSString stringWithFormat:@"SNTStoredFileAccessEvent[%@]: Accessed: %@, By: %@", self.idx,
                                    self.accessedPath, self.process];
}

- (NSString*)uniqueID {
  // NB: Not using `accessedPath` as part of the uniqe ID to prevent a noisy
  // rule from generating a large number of events to upload.
  return [NSString stringWithFormat:@"%@|%@|%@", _ruleName, _ruleVersion, _process.fileSHA256];
}

- (BOOL)unactionableEvent {
  return self.decision == FileAccessPolicyDecision::kAllowedAuditOnly;
}

@end
