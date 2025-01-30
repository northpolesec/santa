/// Copyright 2024 Google LLC
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

#import "Source/common/SNTRuleIdentifiers.h"

#import "Source/common/CoderMacros.h"

@implementation SNTRuleIdentifiers

- (instancetype)initWithRuleIdentifiers:(struct RuleIdentifiers)identifiers {
  self = [super init];
  if (self) {
    _cdhash = identifiers.cdhash;
    _binarySHA256 = identifiers.binarySHA256;
    _signingID = identifiers.signingID;
    _certificateSHA256 = identifiers.certificateSHA256;
    _teamID = identifiers.teamID;
  }
  return self;
}

- (struct RuleIdentifiers)toStruct {
  return (struct RuleIdentifiers){.cdhash = self.cdhash,
                                  .binarySHA256 = self.binarySHA256,
                                  .signingID = self.signingID,
                                  .certificateSHA256 = self.certificateSHA256,
                                  .teamID = self.teamID};
}

#pragma mark NSSecureCoding

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (instancetype)initWithCoder:(NSCoder *)decoder {
  self = [self init];
  if (self) {
    DECODE(decoder, cdhash, NSString);
    DECODE(decoder, binarySHA256, NSString);
    DECODE(decoder, signingID, NSString);
    DECODE(decoder, certificateSHA256, NSString);
    DECODE(decoder, teamID, NSString);
  }
  return self;
}

- (void)encodeWithCoder:(NSCoder *)coder {
  ENCODE(coder, cdhash);
  ENCODE(coder, binarySHA256);
  ENCODE(coder, signingID);
  ENCODE(coder, certificateSHA256);
  ENCODE(coder, teamID);
}

@end
