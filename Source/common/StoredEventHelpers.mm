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

#import "Source/common/StoredEventHelpers.h"

#import "Source/common/CertificateHelpers.h"
#import "Source/common/MOLCodesignChecker.h"
#import "Source/common/SNTFileInfo.h"
#import "Source/common/SigningIDHelpers.h"

SNTStoredEvent *StoredEventFromFileInfo(SNTFileInfo *fileInfo) {
  SNTStoredEvent *se = [[SNTStoredEvent alloc] init];
  se.filePath = fileInfo.path;
  se.fileSHA256 = fileInfo.SHA256;
  NSError *csError;
  MOLCodesignChecker *cs = [fileInfo codesignCheckerWithError:&csError];
  if (csError) {
    se.signingStatus =
        (csError.code == errSecCSUnsigned) ? SNTSigningStatusUnsigned : SNTSigningStatusInvalid;
    return se;
  }
  se.signingChain = cs.certificates;
  se.cdhash = cs.cdhash;
  se.teamID = cs.teamID;
  se.signingID = FormatSigningID(cs);
  se.entitlements = cs.entitlements;
  se.secureTimestamp = cs.secureTimestamp;
  se.insecureTimestamp = cs.insecureTimestamp;
  if (cs.signatureFlags & kSecCodeSignatureAdhoc) {
    se.signingStatus = SNTSigningStatusAdhoc;
  } else if (IsDevelopmentCert(cs.leafCertificate)) {
    se.signingStatus = SNTSigningStatusDevelopment;
  } else {
    se.signingStatus = SNTSigningStatusProduction;
  }
  return se;
}
