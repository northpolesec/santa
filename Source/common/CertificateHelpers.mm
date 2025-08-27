/// Copyright 2023 Google LLC
/// Copyright 2024 North Pole Security, Inc.
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

#import "Source/common/CertificateHelpers.h"

#include <Security/SecCertificate.h>

#import "Source/common/MOLCertificate.h"
#import "Source/common/MOLCodesignChecker.h"

NSString *Publisher(NSArray<MOLCertificate *> *certs, NSString *teamID) {
  MOLCertificate *leafCert = [certs firstObject];

  if ([leafCert.commonName isEqualToString:@"Apple Mac OS Application Signing"]) {
    return [NSString stringWithFormat:@"App Store (Team ID: %@)", teamID];
  } else if ([leafCert.commonName hasPrefix:@"Developer ID Application"]) {
    // Developer ID Application certs have the company name in the OrgName field
    // but also include it in the CommonName and we don't want to print it twice.
    return [NSString stringWithFormat:@"%@ (%@)", leafCert.orgName, teamID];
  } else if (leafCert.commonName && leafCert.orgName) {
    return [NSString stringWithFormat:@"%@ - %@", leafCert.orgName, leafCert.commonName];
  } else if (leafCert.commonName) {
    return leafCert.commonName;
  } else {
    return nil;
  }
}

NSArray<id> *CertificateChain(NSArray<MOLCertificate *> *certs) {
  NSMutableArray *certArray = [NSMutableArray arrayWithCapacity:certs.count];
  for (MOLCertificate *cert in certs) {
    [certArray addObject:(id)cert.certRef];
  }

  return certArray;
}

// IsProductionSigningCert is a helper function to determine if a certificate used
// for code-signing is a production certificate.
//
// Important: this does not check if the certificate was issued by Apple or that
// the code signature is valid, it is intended to be used _after_ validating the
// signature.
//
// It should also be noted that this is best-effort and should not be used for
// runtime or security-critical checks. Runtime checks are handled by ES and the
// status handed to us but the Security framework does not provide a way to
// do the same checks statically.
BOOL IsProductionSigningCert(MOLCertificate *cert) {
  // Production OID values defined by Apple and used by the Security Framework
  // https://developer.apple.com/documentation/technotes/tn3127-inside-code-signing-requirements#Xcode-designated-requirement-for-Developer-ID-code
  static NSArray *const keys = @[
    // Mac App Store Application
    @"1.2.840.113635.100.6.1.9",

    // Developer ID Application
    @"1.2.840.113635.100.6.1.13",

    // iOS App Store Application (to support iOS apps running on Apple Silicon)
    @"1.2.840.113635.100.6.1.3",

    // Apple software signing for its own binaries
    @"1.2.840.113635.100.6.22",
  ];

  if (!cert || !cert.certRef) {
    return NO;
  }

  NSDictionary *vals =
      CFBridgingRelease(SecCertificateCopyValues(cert.certRef, (__bridge CFArrayRef)keys, NULL));

  return vals.count > 0;
}

SNTSigningStatus SigningStatus(MOLCodesignChecker *csc, NSError *error) {
  if (error) {
    if (error.code == errSecCSUnsigned) {
      return SNTSigningStatusUnsigned;
    }
    return SNTSigningStatusInvalid;
  }
  if (csc.signatureFlags & kSecCodeSignatureAdhoc) {
    return SNTSigningStatusAdhoc;
  } else if (csc.platformBinary) {
    return SNTSigningStatusProduction;
  } else if (IsProductionSigningCert(csc.leafCertificate)) {
    return SNTSigningStatusProduction;
  }
  return SNTSigningStatusDevelopment;
}
