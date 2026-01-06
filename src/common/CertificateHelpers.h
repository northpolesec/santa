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

#import <Foundation/Foundation.h>
#include <sys/cdefs.h>

#import "src/common/SNTCommonEnums.h"

@class MOLCertificate;
@class MOLCodesignChecker;

__BEGIN_DECLS

/**
  Return a string representing publisher info from the provided certs

  @param certs A certificate chain
  @param teamID A team ID to be displayed for apps from the App Store

  @return A string that tries to be more helpful to users by extracting
  appropriate information from the certificate chain.
*/
NSString *Publisher(NSArray<MOLCertificate *> *certs, NSString *teamID);

/**
  Return an array of the underlying SecCertificateRef's for the given array
  of MOLCertificates.

  @param certs An array of MOLCertificates

  @return An array of SecCertificateRefs. WARNING: If the refs need to be used
  for a long time be careful to properly CFRetain/CFRelease the returned items.
*/
NSArray<id> *CertificateChain(NSArray<MOLCertificate *> *certs);

/**
  Test if the given certificate contains production OID values.

  @param cert The cert to test

  @return True if any production OIDs exist, otherwise false.
*/
BOOL IsProductionSigningCert(MOLCertificate *cert);

/**
  Determine the signing status of a binary based on the signature flags and error.

  @param csc The MOLCodesignChecker for this binary.
  @param error The error returned from MOLCodesignChecker

  @return The signing status of the binary
*/
SNTSigningStatus SigningStatus(MOLCodesignChecker *csc, NSError *error);

__END_DECLS
