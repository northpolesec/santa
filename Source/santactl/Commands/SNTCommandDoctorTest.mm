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

#import <XCTest/XCTest.h>

#import "Source/common/MOLCertificate.h"

// Defined in SNTCommandDoctor.mm.
typedef NS_ENUM(NSInteger, SNTDoctorClientCertValidity) {
  SNTDoctorClientCertValidityValid,
  SNTDoctorClientCertValidityExpired,
  SNTDoctorClientCertValidityNotYetValid,
};
extern SNTDoctorClientCertValidity SNTDoctorClassifyClientCertificate(MOLCertificate* cert,
                                                                      NSDate* now);

@interface SNTCommandDoctorTest : XCTestCase
@end

@implementation SNTCommandDoctorTest

// A client certificate valid from 2021-05-03 until 2032-07-20.
- (MOLCertificate*)testCertificate {
  NSString* path =
      [[NSBundle bundleForClass:[self class]] pathForResource:@"example_org_client_cert"
                                                       ofType:@"pem"];
  NSString* pem = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:NULL];
  return [[MOLCertificate alloc] initWithCertificateDataPEM:pem];
}

- (void)testCertificateWithinValidityWindowIsValid {
  MOLCertificate* cert = [self testCertificate];
  // 2025-06-01
  NSDate* now = [NSDate dateWithTimeIntervalSince1970:1748736000];
  XCTAssertEqual(SNTDoctorClassifyClientCertificate(cert, now), SNTDoctorClientCertValidityValid);
}

- (void)testExpiredCertificateIsExpired {
  MOLCertificate* cert = [self testCertificate];
  // 2033-01-01, after the 2032-07-20 notAfter date.
  NSDate* now = [NSDate dateWithTimeIntervalSince1970:1988150400];
  XCTAssertEqual(SNTDoctorClassifyClientCertificate(cert, now), SNTDoctorClientCertValidityExpired);
}

- (void)testNotYetValidCertificateIsNotYetValid {
  MOLCertificate* cert = [self testCertificate];
  // 2020-01-01, before the 2021-05-03 notBefore date.
  NSDate* now = [NSDate dateWithTimeIntervalSince1970:1577836800];
  XCTAssertEqual(SNTDoctorClassifyClientCertificate(cert, now),
                 SNTDoctorClientCertValidityNotYetValid);
}

// A certificate that is exactly at its boundaries should be considered valid: it is valid until its
// notAfter and is valid from its notBefore.
- (void)testBoundaryDatesAreValid {
  MOLCertificate* cert = [self testCertificate];
  XCTAssertEqual(SNTDoctorClassifyClientCertificate(cert, cert.validUntil),
                 SNTDoctorClientCertValidityValid);
  XCTAssertEqual(SNTDoctorClassifyClientCertificate(cert, cert.validFrom),
                 SNTDoctorClientCertValidityValid);
}

@end
