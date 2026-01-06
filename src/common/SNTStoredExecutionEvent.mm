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

#import "src/common/SNTStoredExecutionEvent.h"

#import "src/common/CertificateHelpers.h"
#import "src/common/CoderMacros.h"
#import "src/common/MOLCertificate.h"
#import "src/common/MOLCodesignChecker.h"
#import "src/common/SNTFileInfo.h"
#import "src/common/SigningIDHelpers.h"

@implementation SNTStoredExecutionEvent

- (nullable instancetype)initWithFileInfo:(nullable SNTFileInfo *)fileInfo {
  self = [super init];
  if (self) {
    _filePath = fileInfo.path;
    _fileSHA256 = fileInfo.SHA256;
    NSError *csError;
    MOLCodesignChecker *cs = [fileInfo codesignCheckerWithError:&csError];
    if (csError) {
      _signingStatus =
          (csError.code == errSecCSUnsigned) ? SNTSigningStatusUnsigned : SNTSigningStatusInvalid;
      return self;
    }
    _signingChain = cs.certificates;
    _cdhash = cs.cdhash;
    _teamID = cs.teamID;
    _signingID = FormatSigningID(cs);
    _entitlements = cs.entitlements;
    _secureSigningTime = cs.secureSigningTime;
    _signingTime = cs.signingTime;
    _signingStatus = SigningStatus(cs, csError);
  }
  return self;
}

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder {
  [super encodeWithCoder:coder];
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
  ENCODE(coder, secureSigningTime);
  ENCODE(coder, signingTime);

  ENCODE(coder, executingUser);
  ENCODE_BOXABLE(coder, decision);
  ENCODE_BOXABLE(coder, holdAndAsk);
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

- (instancetype)initWithCoder:(NSCoder *)decoder {
  self = [super initWithCoder:decoder];
  if (self) {
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
    DECODE(decoder, secureSigningTime, NSDate);
    DECODE(decoder, signingTime, NSDate);

    DECODE(decoder, executingUser, NSString);
    DECODE_SELECTOR(decoder, decision, NSNumber, unsignedLongLongValue);
    DECODE_SELECTOR(decoder, holdAndAsk, NSNumber, boolValue);
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
  if (![other isKindOfClass:[SNTStoredExecutionEvent class]]) return NO;
  SNTStoredExecutionEvent *o = other;
  return ([self.fileSHA256 isEqual:o.fileSHA256] && [super isEqual:other]);
}

- (NSUInteger)hash {
  NSUInteger prime = 31;
  NSUInteger result = 1;
  result = [super hash];
  result = prime * result + [self.fileSHA256 hash];
  result = prime * result + [self.occurrenceDate hash];
  return result;
}

- (NSString *)description {
  return [NSString
      stringWithFormat:@"SNTStoredExecutionEvent[%@] with SHA-256: %@", self.idx, self.fileSHA256];
}

- (NSString *)publisherInfo {
  return Publisher(self.signingChain, self.teamID);
}

- (NSArray *)signingChainCertRefs {
  return CertificateChain(self.signingChain);
}

- (NSString *)uniqueID {
  return self.fileSHA256;
}

- (BOOL)unactionableEvent {
  return (self.decision & SNTEventStateAllow) != 0;
}

@end
