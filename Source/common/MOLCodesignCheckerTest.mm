/// Copyright 2015 Google Inc. All rights reserved.
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

#include <fcntl.h>
#include <mach-o/fat.h>
#include <unistd.h>

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
  MOLCodesignChecker* sut = [[MOLCodesignChecker alloc] initWithBinaryPath:@"/sbin/launchd"];
  XCTAssertNotNil(sut);
}

- (void)testInitWithInvalidBinaryPath {
  NSError* error;
  MOLCodesignChecker* sut =
      [[MOLCodesignChecker alloc] initWithBinaryPath:@"/tmp/this/file/doesnt/exist" error:&error];
  XCTAssertNil(sut);
  XCTAssertNotNil(error);
}

- (void)testInitWithPID {
  MOLCodesignChecker* sut = [[MOLCodesignChecker alloc] initWithPID:1];
  XCTAssertNotNil(sut);
}

- (void)testInitWithInvalidPID {
  NSError* error;
  MOLCodesignChecker* sut = [[MOLCodesignChecker alloc] initWithPID:999999999 error:&error];
  XCTAssertNil(sut);
  XCTAssertNotNil(error);
}

- (void)testInitWithSelf {
  // n.b: 'self' in this case is xctest, which should always be signed.
  MOLCodesignChecker* sut = [[MOLCodesignChecker alloc] initWithSelf];
  XCTAssertNotNil(sut);
}

- (void)testPlainInit {
  XCTAssertThrows([[MOLCodesignChecker alloc] init]);
}

- (void)testDescription {
  MOLCodesignChecker* sut = [[MOLCodesignChecker alloc] initWithPID:1];
  XCTAssertEqualObjects([sut description],
                        @"In-memory binary, signed by Apple Inc., located at: /sbin/launchd");
}

- (void)testLeafCertificate {
  MOLCodesignChecker* sut = [[MOLCodesignChecker alloc] initWithPID:1];
  XCTAssertNotNil(sut.leafCertificate);
}

- (void)testBinaryPath {
  MOLCodesignChecker* sut = [[MOLCodesignChecker alloc] initWithPID:1];
  XCTAssertEqualObjects(sut.binaryPath, @"/sbin/launchd");
}

- (void)testSigningInformationMatches {
  MOLCodesignChecker* sut1 = [[MOLCodesignChecker alloc] initWithBinaryPath:@"/sbin/launchd"];
  MOLCodesignChecker* sut2 = [[MOLCodesignChecker alloc] initWithPID:1];
  XCTAssertTrue([sut1 signingInformationMatches:sut2]);
}

- (void)testCodeRef {
  MOLCodesignChecker* sut = [[MOLCodesignChecker alloc] initWithSelf];
  XCTAssertNotNil((id)sut.codeRef);
}

- (void)testCodeRefCast {
  MOLCodesignChecker* sut = [[MOLCodesignChecker alloc] initWithSelf];
  XCTAssertEqual(CFGetTypeID(sut.codeRef), SecCodeGetTypeID());

  sut = [[MOLCodesignChecker alloc] initWithBinaryPath:@"/sbin/launchd"];
  XCTAssertEqual(CFGetTypeID(sut.codeRef), SecStaticCodeGetTypeID());
}

- (void)testSigningInformation {
  MOLCodesignChecker* sut = [[MOLCodesignChecker alloc] initWithPID:1];
  XCTAssertNotNil(sut.signingInformation);
  XCTAssertEqualObjects(sut.signingInformation[@"source"], @"embedded");
}

- (void)testValidateRequirement {
  MOLCodesignChecker* sut1 = [[MOLCodesignChecker alloc] initWithPID:1];
  MOLCodesignChecker* sut2 = [[MOLCodesignChecker alloc] initWithSelf];

  XCTAssertFalse([sut1 validateWithRequirement:sut2.requirement]);
}

- (void)testInitWithFileDescriptor {
  NSString* path = @"/usr/bin/yes";
  int fd = open(path.UTF8String, O_RDONLY | O_CLOEXEC);
  MOLCodesignChecker* sut = [[MOLCodesignChecker alloc] initWithBinaryPath:path fileDescriptor:fd];
  XCTAssertNotNil(sut.signingInformation);
  close(fd);
}

// fd-based init must reflect the caller's vnode, not the path. Stage two
// distinct signed binaries; open the fd of one; atomic-rename the other into
// the staged path; verify the fd-based checker still reports the original
// vnode's cdhash, and a path-based checker reports the swapped binary's
// cdhash.
- (void)testInitWithFileDescriptor_SurvivesAtomicRenameSwap {
  NSString* tmp = NSTemporaryDirectory();
  NSString* a =
      [tmp stringByAppendingPathComponent:[NSString stringWithFormat:@"mol_a_%d_%@", getpid(),
                                                                     [[NSUUID UUID] UUIDString]]];
  NSString* b =
      [tmp stringByAppendingPathComponent:[NSString stringWithFormat:@"mol_b_%d_%@", getpid(),
                                                                     [[NSUUID UUID] UUIDString]]];
  NSError* err;
  XCTAssertTrue([[NSFileManager defaultManager] copyItemAtPath:@"/usr/bin/yes"
                                                        toPath:a
                                                         error:&err]);
  XCTAssertTrue([[NSFileManager defaultManager] copyItemAtPath:@"/usr/bin/true"
                                                        toPath:b
                                                         error:&err]);

  int fd = open(a.UTF8String, O_RDONLY | O_CLOEXEC);
  XCTAssertGreaterThanOrEqual(fd, 0, "open: %s", strerror(errno));

  MOLCodesignChecker* aRef = [[MOLCodesignChecker alloc] initWithBinaryPath:a fileDescriptor:fd];
  MOLCodesignChecker* bRef = [[MOLCodesignChecker alloc] initWithBinaryPath:b];
  XCTAssertNotNil(aRef.cdhash);
  XCTAssertNotNil(bRef.cdhash);
  XCTAssertNotEqualObjects(aRef.cdhash, bRef.cdhash);
  NSString* originalACdhash = aRef.cdhash;
  NSString* originalBCdhash = bRef.cdhash;

  // Atomic swap: rename(b, a) makes path `a` point at b's vnode. Original
  // a-vnode survives only via the open fd.
  XCTAssertEqual(rename(b.UTF8String, a.UTF8String), 0, "rename: %s", strerror(errno));

  // fd-based: must still see A's identity.
  MOLCodesignChecker* afterFD = [[MOLCodesignChecker alloc] initWithBinaryPath:a fileDescriptor:fd];
  XCTAssertEqualObjects(afterFD.cdhash, originalACdhash);

  // Path-based control: now sees B's identity (proving the rename happened
  // and was visible to a path-based reader).
  MOLCodesignChecker* afterPath = [[MOLCodesignChecker alloc] initWithBinaryPath:a];
  XCTAssertEqualObjects(afterPath.cdhash, originalBCdhash);

  close(fd);
  [[NSFileManager defaultManager] removeItemAtPath:a error:nil];
}

// fd-based init must succeed even when the original path has been removed
// after the caller's open(): the fd holds the vnode regardless.
- (void)testInitWithFileDescriptor_SurvivesUnlink {
  NSString* tmp = NSTemporaryDirectory();
  NSString* path =
      [tmp stringByAppendingPathComponent:[NSString stringWithFormat:@"mol_unlink_%d_%@", getpid(),
                                                                     [[NSUUID UUID] UUIDString]]];
  NSError* err;
  XCTAssertTrue([[NSFileManager defaultManager] copyItemAtPath:@"/usr/bin/yes"
                                                        toPath:path
                                                         error:&err]);

  int fd = open(path.UTF8String, O_RDONLY | O_CLOEXEC);
  XCTAssertGreaterThanOrEqual(fd, 0);

  XCTAssertEqual(unlink(path.UTF8String), 0);

  MOLCodesignChecker* sut = [[MOLCodesignChecker alloc] initWithBinaryPath:path fileDescriptor:fd];
  XCTAssertNotNil(sut.cdhash);

  // Path-based at the now-missing path must fail, confirming the fd was the
  // load-bearing source.
  NSError* pathErr;
  MOLCodesignChecker* viaPath = [[MOLCodesignChecker alloc] initWithBinaryPath:path error:&pathErr];
  XCTAssertNil(viaPath);
  XCTAssertNotNil(pathErr);

  close(fd);
}

- (void)testAllArchitectures {
  NSError* error;
  NSBundle* bundle = [NSBundle bundleForClass:[self class]];
  NSString* path = [bundle pathForResource:@"cal-yikes-universal" ofType:@""];
  MOLCodesignChecker* sut = [[MOLCodesignChecker alloc] initWithBinaryPath:path error:&error];
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
  NSError* error;
  NSBundle* bundle = [NSBundle bundleForClass:[self class]];
  NSString* path = [bundle pathForResource:@"signed-with-teamid" ofType:@""];

  MOLCodesignChecker* sut = [[MOLCodesignChecker alloc] initWithBinaryPath:path error:&error];
  XCTAssertNotNil(sut.signingInformation);
  XCTAssertNil(error);
  XCTAssertEqualObjects(sut.teamID, @"EQHXZ8M8AV");
}

- (void)testCDHash {
  NSError* error;
  NSBundle* bundle = [NSBundle bundleForClass:[self class]];
  NSString* path = [bundle pathForResource:@"signed-with-teamid" ofType:@""];

  MOLCodesignChecker* sut = [[MOLCodesignChecker alloc] initWithBinaryPath:path error:&error];
  XCTAssertNotNil(sut.signingInformation);
  XCTAssertNil(error);
  XCTAssertEqualObjects(sut.cdhash, @"23cbe7039ac34bf26f0b1ccc22ff96d6f0d80b72");
}

- (void)testSigningID {
  NSError* error;
  NSBundle* bundle = [NSBundle bundleForClass:[self class]];
  NSString* path = [bundle pathForResource:@"signed-with-teamid" ofType:@""];

  MOLCodesignChecker* sut = [[MOLCodesignChecker alloc] initWithBinaryPath:path error:&error];
  XCTAssertNotNil(sut.signingInformation);
  XCTAssertNil(error);
  XCTAssertEqualObjects(sut.signingID, @"goodcert");
}

- (void)testPlatformBinary {
  NSError* error;
  NSBundle* bundle = [NSBundle bundleForClass:[self class]];
  NSString* path = [bundle pathForResource:@"signed-with-teamid" ofType:@""];

  MOLCodesignChecker* sut = [[MOLCodesignChecker alloc] initWithBinaryPath:path error:&error];
  XCTAssertNotNil(sut.signingInformation);
  XCTAssertNil(error);
  XCTAssertFalse(sut.platformBinary);

  sut = [[MOLCodesignChecker alloc] initWithBinaryPath:@"/sbin/launchd"];
  XCTAssertNotNil(sut);
  XCTAssertTrue(sut.platformBinary);
}

// MOLCodesignChecker must continue to populate `_signingInformation` even
// when SecStaticCodeCheckValidityWithErrors returns a non-fatal error. Bundle
// binaries opened by fd produce errSecCSInfoPlistFailed (the bundle's
// Info.plist hash slot in the Mach-O signature can't be matched against an
// on-disk Info.plist when SecStaticCode is fed /dev/fd/N), and downstream
// callers — notably SNTPolicyProcessor's identity verifier — depend on the
// signing dictionary remaining accessible so the cdhash / TeamID / SigningID
// can still be read off the binary. This test pins that contract: a future
// refactor that returns nil or skips dictionary population on any error
// would silently regress identity verification for every signed bundle
// binary on the system (~all GUI apps and many framework-housed tools).
- (void)testInitWithFileDescriptor_BundleBinary_PreservesSigningInfoOnPartialError {
  NSArray<NSString*>* candidates = @[
    @"/System/Applications/Calculator.app/Contents/MacOS/Calculator",
    @"/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
    @"/System/Library/Frameworks/Foundation.framework/Versions/Current/Foundation",
  ];
  NSString* path = nil;
  for (NSString* c in candidates) {
    if ([[NSFileManager defaultManager] fileExistsAtPath:c]) {
      path = c;
      break;
    }
  }
  if (!path) {
    XCTSkip(@"No signed bundle binary available on this host");
  }

  // Sanity baseline: path-based init succeeds cleanly and gives us reference
  // identity values to compare against.
  NSError* viaPathErr;
  MOLCodesignChecker* viaPath = [[MOLCodesignChecker alloc] initWithBinaryPath:path
                                                                         error:&viaPathErr];
  XCTAssertNotNil(viaPath);
  XCTAssertNil(viaPathErr);
  XCTAssertNotNil(viaPath.cdhash);

  int fd = open(path.UTF8String, O_RDONLY | O_CLOEXEC);
  XCTAssertGreaterThanOrEqual(fd, 0, "open(%@): %s", path, strerror(errno));

  // fd-based init must surface the validity error AND populate the signing
  // dictionary anyway. The two behaviors are independent — together they let
  // the SNT-377 verifier compare identity even when bundle context is
  // unavailable through /dev/fd/N.
  NSError* err;
  MOLCodesignChecker* sut = [[MOLCodesignChecker alloc] initWithBinaryPath:path
                                                            fileDescriptor:fd
                                                                     error:&err];
  XCTAssertNotNil(sut, @"init must return an instance, not nil, on partial validity failure");
  XCTAssertNotNil(err, @"validity check failure must surface to the caller");

  XCTAssertNotNil(sut.signingInformation, @"signing dictionary must be populated");
  XCTAssertEqualObjects(sut.cdhash, viaPath.cdhash,
                        @"fd-based cdhash must agree with path-based cdhash");
  XCTAssertEqualObjects(sut.signingID, viaPath.signingID);
  XCTAssertEqualObjects(sut.teamID, viaPath.teamID);
  XCTAssertNotNil(sut.leafCertificate, @"leaf certificate must be readable");

  close(fd);
}

- (void)testEntitlements {
  NSError* error;
  NSBundle* bundle = [NSBundle bundleForClass:[self class]];
  NSString* path = [bundle pathForResource:@"signed-with-teamid" ofType:@""];

  MOLCodesignChecker* sut = [[MOLCodesignChecker alloc] initWithBinaryPath:path error:&error];
  XCTAssertNotNil(sut.signingInformation);
  XCTAssertNil(error);
  XCTAssertNil(sut.entitlements);

  sut = [[MOLCodesignChecker alloc] initWithBinaryPath:@"/usr/bin/eslogger"];
  XCTAssertNotNil(sut);
  NSDictionary* wantedEntitlements = @{
    @"com.apple.developer.endpoint-security.client" : @YES,
  };
  [wantedEntitlements enumerateKeysAndObjectsUsingBlock:^(id key, id value, BOOL* stop) {
    XCTAssertEqualObjects(sut.entitlements[key], value);
  }];
}

@end
