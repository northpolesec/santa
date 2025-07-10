/// Copyright 2015 Google Inc. All rights reserved.
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

#include <mach-o/fat.h>

#import "Source/common/MOLCodesignChecker.h"

/**
  Tests for `MOLCodesignChecker`

  Most of these tests rely on some facts about `launchd`:

  * launchd is in /sbin
  * launchd is PID 1
  * launchd is signed
  * launchd's leaf cert has a CN of "Software Signing"
  * launchd's leaf cert has an OU of "Apple Software"
  * launchd's leaf cert has an ON of "Apple Inc."

  These facts are pretty stable, so shouldn't be a problem.
*/
@interface MOLCodesignCheckerTest : XCTestCase
@end

@implementation MOLCodesignCheckerTest

- (void)testInitWithBinaryPath {
  MOLCodesignChecker *sut = [[MOLCodesignChecker alloc] initWithBinaryPath:@"/sbin/launchd"];
  XCTAssertNotNil(sut);
}

- (void)testInitWithInvalidBinaryPath {
  NSError *error;
  MOLCodesignChecker *sut =
      [[MOLCodesignChecker alloc] initWithBinaryPath:@"/tmp/this/file/doesnt/exist" error:&error];
  XCTAssertNil(sut);
  XCTAssertNotNil(error);
}

- (void)testInitWithPID {
  MOLCodesignChecker *sut = [[MOLCodesignChecker alloc] initWithPID:1];
  XCTAssertNotNil(sut);
}

- (void)testInitWithInvalidPID {
  NSError *error;
  MOLCodesignChecker *sut = [[MOLCodesignChecker alloc] initWithPID:999999999 error:&error];
  XCTAssertNil(sut);
  XCTAssertNotNil(error);
}

- (void)testInitWithSelf {
  // n.b: 'self' in this case is xctest, which should always be signed.
  MOLCodesignChecker *sut = [[MOLCodesignChecker alloc] initWithSelf];
  XCTAssertNotNil(sut);
}

- (void)testPlainInit {
  XCTAssertThrows([[MOLCodesignChecker alloc] init]);
}

- (void)testDescription {
  MOLCodesignChecker *sut = [[MOLCodesignChecker alloc] initWithPID:1];
  XCTAssertEqualObjects([sut description],
                        @"In-memory binary, signed by Apple Inc., located at: /sbin/launchd");
}

- (void)testLeafCertificate {
  MOLCodesignChecker *sut = [[MOLCodesignChecker alloc] initWithPID:1];
  XCTAssertNotNil(sut.leafCertificate);
}

- (void)testBinaryPath {
  MOLCodesignChecker *sut = [[MOLCodesignChecker alloc] initWithPID:1];
  XCTAssertEqualObjects(sut.binaryPath, @"/sbin/launchd");
}

- (void)testSigningInformationMatches {
  MOLCodesignChecker *sut1 = [[MOLCodesignChecker alloc] initWithBinaryPath:@"/sbin/launchd"];
  MOLCodesignChecker *sut2 = [[MOLCodesignChecker alloc] initWithPID:1];
  XCTAssertTrue([sut1 signingInformationMatches:sut2]);
}

- (void)testCodeRef {
  MOLCodesignChecker *sut = [[MOLCodesignChecker alloc] initWithSelf];
  XCTAssertNotNil((id)sut.codeRef);
}

- (void)testCodeRefCast {
  MOLCodesignChecker *sut = [[MOLCodesignChecker alloc] initWithSelf];
  XCTAssertEqual(CFGetTypeID(sut.codeRef), SecCodeGetTypeID());

  sut = [[MOLCodesignChecker alloc] initWithBinaryPath:@"/sbin/launchd"];
  XCTAssertEqual(CFGetTypeID(sut.codeRef), SecStaticCodeGetTypeID());
}

- (void)testSigningInformation {
  MOLCodesignChecker *sut = [[MOLCodesignChecker alloc] initWithPID:1];
  XCTAssertNotNil(sut.signingInformation);
  XCTAssertEqualObjects(sut.signingInformation[@"source"], @"embedded");
}

- (void)testValidateRequirement {
  MOLCodesignChecker *sut1 = [[MOLCodesignChecker alloc] initWithPID:1];
  MOLCodesignChecker *sut2 = [[MOLCodesignChecker alloc] initWithSelf];

  XCTAssertFalse([sut1 validateWithRequirement:sut2.requirement]);
}

- (void)testInitWithFileDescriptor {
  NSString *path = @"/usr/bin/yes";
  int fd = open(path.UTF8String, O_RDONLY | O_CLOEXEC);
  MOLCodesignChecker *sut = [[MOLCodesignChecker alloc] initWithBinaryPath:path fileDescriptor:fd];
  XCTAssertNotNil(sut.signingInformation);
  close(fd);
}

- (void)testAllArchitectures {
  NSError *error;
  NSBundle *bundle = [NSBundle bundleForClass:[self class]];
  NSString *path = [bundle pathForResource:@"cal-yikes-universal" ofType:@""];
  MOLCodesignChecker *sut = [[MOLCodesignChecker alloc] initWithBinaryPath:path error:&error];
  XCTAssertNotNil(sut.universalSigningInformation);
  XCTAssertNil(sut.leafCertificate);
  XCTAssertEqual(error.code, errSecCSSignatureInvalid);

  error = nil;
  path = [bundle pathForResource:@"cal-yikes-universal_adhoc" ofType:@""];
  sut = [[MOLCodesignChecker alloc] initWithBinaryPath:path error:&error];
  XCTAssertNotNil(sut.universalSigningInformation);
  XCTAssertNil(sut.leafCertificate);
  XCTAssertEqual(error.code, errSecCSSignatureInvalid);
  XCTAssertFalse(sut.signatureFlags & kSecCodeSignatureAdhoc);

  error = nil;
  path = [bundle pathForResource:@"cal-yikes-universal_signed" ofType:@""];
  sut = [[MOLCodesignChecker alloc] initWithBinaryPath:path error:&error];
  XCTAssertNotNil(sut.universalSigningInformation);
  XCTAssertNil(sut.leafCertificate);
  XCTAssertEqual(error.code, errSecCSSignatureInvalid);

  error = nil;
  path = [bundle pathForResource:@"yikes-universal" ofType:@""];
  sut = [[MOLCodesignChecker alloc] initWithBinaryPath:path error:&error];
  XCTAssertNotNil(sut.universalSigningInformation);
  XCTAssertNil(sut.leafCertificate);
  XCTAssertEqual(error.code, errSecCSUnsigned);

  error = nil;
  path = [bundle pathForResource:@"yikes-universal_adhoc" ofType:@""];
  sut = [[MOLCodesignChecker alloc] initWithBinaryPath:path error:&error];
  XCTAssertNotNil(sut.universalSigningInformation);
  XCTAssertNil(sut.leafCertificate);
  XCTAssertNil(error);
  XCTAssertTrue(sut.signatureFlags & kSecCodeSignatureAdhoc);

  error = nil;
  path = [bundle pathForResource:@"yikes-universal_signed" ofType:@""];
  sut = [[MOLCodesignChecker alloc] initWithBinaryPath:path error:&error];
  XCTAssertNotNil(sut.universalSigningInformation);
  XCTAssertNotNil(sut.leafCertificate);
  XCTAssertNil(error);
}

- (void)testTeamID {
  NSError *error;
  NSBundle *bundle = [NSBundle bundleForClass:[self class]];
  NSString *path = [bundle pathForResource:@"signed-with-teamid" ofType:@""];

  MOLCodesignChecker *sut = [[MOLCodesignChecker alloc] initWithBinaryPath:path error:&error];
  XCTAssertNotNil(sut.signingInformation);
  XCTAssertNil(error);
  XCTAssertEqualObjects(sut.teamID, @"EQHXZ8M8AV");
}

- (void)testCDHash {
  NSError *error;
  NSBundle *bundle = [NSBundle bundleForClass:[self class]];
  NSString *path = [bundle pathForResource:@"signed-with-teamid" ofType:@""];

  MOLCodesignChecker *sut = [[MOLCodesignChecker alloc] initWithBinaryPath:path error:&error];
  XCTAssertNotNil(sut.signingInformation);
  XCTAssertNil(error);
  XCTAssertEqualObjects(sut.cdhash, @"23cbe7039ac34bf26f0b1ccc22ff96d6f0d80b72");
}

- (void)testSigningID {
  NSError *error;
  NSBundle *bundle = [NSBundle bundleForClass:[self class]];
  NSString *path = [bundle pathForResource:@"signed-with-teamid" ofType:@""];

  MOLCodesignChecker *sut = [[MOLCodesignChecker alloc] initWithBinaryPath:path error:&error];
  XCTAssertNotNil(sut.signingInformation);
  XCTAssertNil(error);
  XCTAssertEqualObjects(sut.signingID, @"goodcert");
}

- (void)testPlatformBinary {
  NSError *error;
  NSBundle *bundle = [NSBundle bundleForClass:[self class]];
  NSString *path = [bundle pathForResource:@"signed-with-teamid" ofType:@""];

  MOLCodesignChecker *sut = [[MOLCodesignChecker alloc] initWithBinaryPath:path error:&error];
  XCTAssertNotNil(sut.signingInformation);
  XCTAssertNil(error);
  XCTAssertFalse(sut.platformBinary);

  sut = [[MOLCodesignChecker alloc] initWithBinaryPath:@"/sbin/launchd"];
  XCTAssertNotNil(sut);
  XCTAssertTrue(sut.platformBinary);
}

- (void)testEntitlements {
  NSError *error;
  NSBundle *bundle = [NSBundle bundleForClass:[self class]];
  NSString *path = [bundle pathForResource:@"signed-with-teamid" ofType:@""];

  MOLCodesignChecker *sut = [[MOLCodesignChecker alloc] initWithBinaryPath:path error:&error];
  XCTAssertNotNil(sut.signingInformation);
  XCTAssertNil(error);
  XCTAssertNil(sut.entitlements);

  sut = [[MOLCodesignChecker alloc] initWithBinaryPath:@"/usr/bin/eslogger"];
  XCTAssertNotNil(sut);
  NSDictionary *wantedEntitlements = @{
    @"com.apple.developer.endpoint-security.client" : @YES,
  };
  [wantedEntitlements enumerateKeysAndObjectsUsingBlock:^(id key, id value, BOOL *stop) {
    XCTAssertEqualObjects(sut.entitlements[key], value);
  }];
}

@end
