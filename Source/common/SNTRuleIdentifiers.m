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
#import "Source/common/StoredEventHelpers.h"

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

- (instancetype)initWithRuleIdentifiers:(struct RuleIdentifiers)ri
                       andSigningStatus:(SNTSigningStatus)signingStatus {
  NSString *cdhash;
  NSString *binarySHA256;
  NSString *signingID;
  NSString *certificateSHA256;
  NSString *teamID;

  // Waterfall thru the signing status in order of most-to-least permissive
  // in terms of identifiers allowed for policy match search. Fields from
  // the given SNTCachedDecision are assigned only when valid for a given
  // signing status.
  //
  // Do not evaluate TeamID/SigningID rules for dev-signed code based on the
  // assumption that orgs are generally more relaxed about dev signed cert
  // protections and users can more easily produce dev-signed code that
  // would otherwise be inadvertently allowed.
  //
  // Note: All labels fall through.
  // clang-format off
  switch (signingStatus) {
    case SNTSigningStatusProduction:
      signingID = ri.signingID;
      teamID = ri.teamID;
      OS_FALLTHROUGH;
    case SNTSigningStatusDevelopment:
      certificateSHA256 = ri.certificateSHA256;
      OS_FALLTHROUGH;
    case SNTSigningStatusAdhoc:
      cdhash = ri.cdhash;
      OS_FALLTHROUGH;
    case SNTSigningStatusInvalid:
      OS_FALLTHROUGH;
    case SNTSigningStatusUnsigned:
      binarySHA256 = ri.binarySHA256;
      break;
  }
  // clang-format on

  return [self initWithRuleIdentifiers:(struct RuleIdentifiers){
      .cdhash = cdhash,
      .binarySHA256 = binarySHA256,
      .signingID = signingID,
      .certificateSHA256 = certificateSHA256,
      .teamID = teamID,
  }];
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
