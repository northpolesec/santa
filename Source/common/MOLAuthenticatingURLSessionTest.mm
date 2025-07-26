/// Copyright 2021 Google Inc. All rights reserved.
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

#import <XCTest/XCTest.h>

#import "Source/common/MOLAuthenticatingURLSession.h"
#import "Source/common/MOLCertificate.h"

@interface MOLAuthenticatingURLSession (Testing)
- (NSArray<MOLCertificate *> *)filterAndSortArray:(NSArray<MOLCertificate *> *)array
                                       commonName:(NSString *)commonName
                                 issuerCommonName:(NSString *)issuerCommonName
                                issuerCountryName:(NSString *)issuerCountryName
                                    issuerOrgName:(NSString *)issuerOrgName
                                    issuerOrgUnit:(NSString *)issuerOrgUnit;
@end

@interface MOLAuthenticatingURLSessionTest : XCTestCase
@end

@implementation MOLAuthenticatingURLSessionTest

- (MOLCertificate *)certFromFilename:(NSString *)filename {
  NSString *path = [[NSBundle bundleForClass:[self class]] pathForResource:filename ofType:@"pem"];
  NSString *data = [NSString stringWithContentsOfFile:path
                                             encoding:NSUTF8StringEncoding
                                                error:NULL];
  return [[MOLCertificate alloc] initWithCertificateDataPEM:data];
}

- (void)testFilterAndSortArray {
  MOLCertificate *c1 = [self certFromFilename:@"example_org_client_cert_old"];
  MOLCertificate *c2 = [self certFromFilename:@"internet_widgits_client_cert"];
  MOLCertificate *c3 = [self certFromFilename:@"example_org_client_cert"];

  MOLAuthenticatingURLSession *s = [[MOLAuthenticatingURLSession alloc] init];

  NSArray *got = [s filterAndSortArray:@[ c1, c2, c3 ]
                            commonName:@"Example Organization Client Certificate"
                      issuerCommonName:nil
                     issuerCountryName:nil
                         issuerOrgName:nil
                         issuerOrgUnit:nil];

  NSArray *want = @[ c3, c1 ];
  XCTAssertEqualObjects(got, want, @"");
}

@end
