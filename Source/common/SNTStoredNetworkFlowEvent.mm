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

#import "Source/common/SNTStoredNetworkFlowEvent.h"

#import "Source/common/CoderMacros.h"

@implementation SNTStoredNetworkFlowEvent

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
  ENCODE(coder, remoteAddress);
  ENCODE_BOXABLE(coder, remotePort);
  ENCODE(coder, localAddress);
  ENCODE_BOXABLE(coder, localPort);
  ENCODE_BOXABLE(coder, protocol);
  ENCODE_BOXABLE(coder, socketFamily);
  ENCODE_BOXABLE(coder, direction);
  ENCODE(coder, hostname);
  ENCODE(coder, flowTime);
  ENCODE_BOXABLE(coder, decision);
  ENCODE_BOXABLE(coder, ruleId);
  ENCODE(coder, competingRuleIds);
  ENCODE_BOXABLE(coder, totalCompetingRuleCount);
  ENCODE(coder, process);
  ENCODE_BOXABLE(coder, silent);
}

- (instancetype)initWithCoder:(NSCoder*)decoder {
  self = [super initWithCoder:decoder];
  if (self) {
    DECODE(decoder, remoteAddress, NSString);
    DECODE_SELECTOR(decoder, remotePort, NSNumber, unsignedShortValue);
    DECODE(decoder, localAddress, NSString);
    DECODE_SELECTOR(decoder, localPort, NSNumber, unsignedShortValue);
    DECODE_SELECTOR(decoder, protocol, NSNumber, intValue);
    DECODE_SELECTOR(decoder, socketFamily, NSNumber, intValue);
    DECODE_SELECTOR(decoder, direction, NSNumber, intValue);
    DECODE(decoder, hostname, NSString);
    DECODE(decoder, flowTime, NSDate);
    DECODE_SELECTOR(decoder, decision, NSNumber, intValue);
    DECODE_SELECTOR(decoder, ruleId, NSNumber, longLongValue);
    DECODE_ARRAY(decoder, competingRuleIds, NSNumber);
    DECODE_SELECTOR(decoder, totalCompetingRuleCount, NSNumber, unsignedIntValue);
    DECODE(decoder, process, SNTStoredProcess);
    DECODE_SELECTOR(decoder, silent, NSNumber, boolValue);
  }
  return self;
}

- (NSString*)description {
  return [NSString stringWithFormat:@"SNTStoredNetworkFlowEvent[%@]: %@ -> %@:%hu rule:%lld",
                                    self.idx, self.process.filePath, self.remoteAddress,
                                    self.remotePort, self.ruleId];
}

// Coarse on purpose: rule_id + originating process identity, NOT destination.
// Keeps the upload backoff and the (deferred) dialog de-dup keyed on the same
// dimension; per-destination breadth lives in NetworkActivity telemetry. Process
// identity is signature-derived: cdhash, else signingID.
- (NSString*)uniqueID {
  NSString* procIdentity = self.process.cdhash ?: (self.process.signingID ?: @"<unknown>");
  return [NSString stringWithFormat:@"%lld|%@", self.ruleId, procIdentity];
}

// Flow dialogs are informational only (no remediation/approval workflow).
- (BOOL)unactionableEvent {
  return YES;
}

@end
