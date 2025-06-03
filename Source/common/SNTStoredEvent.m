/// Copyright 2015 Google Inc. All rights reserved.
/// Copyright 2024 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///    http://www.apache.org/licenses/LICENSE-2.0
///
///    Unless required by applicable law or agreed to in writing, software
///    distributed under the License is distributed on an "AS IS" BASIS,
///    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
///    See the License for the specific language governing permissions and
///    limitations under the License.

#import "Source/common/SNTStoredEvent.h"

#import "Source/common/CertificateHelpers.h"
#import "Source/common/CoderMacros.h"
#import "Source/common/MOLCertificate.h"

@implementation SNTStoredEvent

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder {
  ENCODE(coder, idx);
  ENCODE(coder, fileSHA256);
  ENCODE(coder, filePath);

  ENCODE_BOXABLE(coder, needsBundleHash);
  ENCODE(coder, fileBundleHash);
  ENCODE(coder, fileBundleHashMilliseconds);
  ENCODE(coder, fileBundleBinaryCount);
  ENCODE(coder, fileBundleName);
  ENCODE(coder, fileBundlePath);
  ENCODE(coder, fileBundleExecutableRelPath);
  ENCODE(coder, fileBundleID);
  ENCODE(coder, fileBundleVersion);
  ENCODE(coder, fileBundleVersionString);

  ENCODE(coder, signingChain);
  ENCODE(coder, teamID);
  ENCODE(coder, signingID);
  ENCODE(coder, cdhash);
  ENCODE_BOXABLE(coder, codesigningFlags);
  ENCODE_BOXABLE(coder, signingStatus);
  ENCODE(coder, entitlements);
  ENCODE_BOXABLE(coder, entitlementsFiltered);
  ENCODE(coder, signingTimestamp);

  ENCODE(coder, executingUser);
  ENCODE(coder, occurrenceDate);
  ENCODE_BOXABLE(coder, decision);
  ENCODE(coder, pid);
  ENCODE(coder, ppid);
  ENCODE(coder, parentName);

  ENCODE(coder, loggedInUsers);
  ENCODE(coder, currentSessions);

  ENCODE(coder, quarantineDataURL);
  ENCODE(coder, quarantineRefererURL);
  ENCODE(coder, quarantineTimestamp);
  ENCODE(coder, quarantineAgentBundleID);
}

- (instancetype)init {
  self = [super init];
  if (self) {
    _idx = @(arc4random());
  }
  return self;
}

- (instancetype)initWithCoder:(NSCoder *)decoder {
  self = [super init];
  if (self) {
    DECODE(decoder, idx, NSNumber);
    DECODE(decoder, fileSHA256, NSString);
    DECODE(decoder, filePath, NSString);

    DECODE_SELECTOR(decoder, needsBundleHash, NSNumber, boolValue);
    DECODE(decoder, fileBundleHash, NSString);
    DECODE(decoder, fileBundleHashMilliseconds, NSNumber);
    DECODE(decoder, fileBundleBinaryCount, NSNumber);
    DECODE(decoder, fileBundleName, NSString);
    DECODE(decoder, fileBundlePath, NSString);
    DECODE(decoder, fileBundleExecutableRelPath, NSString);
    DECODE(decoder, fileBundleID, NSString);
    DECODE(decoder, fileBundleVersion, NSString);
    DECODE(decoder, fileBundleVersionString, NSString);

    DECODE_ARRAY(decoder, signingChain, MOLCertificate);
    DECODE(decoder, teamID, NSString);
    DECODE(decoder, signingID, NSString);
    DECODE(decoder, cdhash, NSString);
    DECODE_SELECTOR(decoder, codesigningFlags, NSNumber, unsignedIntValue);
    DECODE_SELECTOR(decoder, signingStatus, NSNumber, integerValue);
    DECODE_DICT(decoder, entitlements);
    DECODE_SELECTOR(decoder, entitlementsFiltered, NSNumber, boolValue);
    DECODE(decoder, signingTimestamp, NSDate);

    DECODE(decoder, executingUser, NSString);
    DECODE(decoder, occurrenceDate, NSDate);
    DECODE_SELECTOR(decoder, decision, NSNumber, unsignedLongLongValue);
    DECODE(decoder, pid, NSNumber);
    DECODE(decoder, ppid, NSNumber);
    DECODE(decoder, parentName, NSString);

    DECODE_ARRAY(decoder, loggedInUsers, NSString);
    DECODE_ARRAY(decoder, currentSessions, NSString);

    DECODE(decoder, quarantineDataURL, NSString);
    DECODE(decoder, quarantineRefererURL, NSString);
    DECODE(decoder, quarantineTimestamp, NSDate);
    DECODE(decoder, quarantineAgentBundleID, NSString);
  }
  return self;
}

- (BOOL)isEqual:(id)other {
  if (other == self) return YES;
  if (![other isKindOfClass:[SNTStoredEvent class]]) return NO;
  SNTStoredEvent *o = other;
  return ([self.fileSHA256 isEqual:o.fileSHA256] && [self.idx isEqual:o.idx]);
}

- (NSUInteger)hash {
  NSUInteger prime = 31;
  NSUInteger result = 1;
  result = prime * result + [self.idx hash];
  result = prime * result + [self.fileSHA256 hash];
  result = prime * result + [self.occurrenceDate hash];
  return result;
}

- (NSString *)description {
  return
      [NSString stringWithFormat:@"SNTStoredEvent[%@] with SHA-256: %@", self.idx, self.fileSHA256];
}

- (NSString *)publisherInfo {
  return Publisher(self.signingChain, self.teamID);
}

- (NSArray *)signingChainCertRefs {
  return CertificateChain(self.signingChain);
}

@end
