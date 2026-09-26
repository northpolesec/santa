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

#import "Source/common/SNTStoredExecutionEvent.h"

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#import "Source/common/SNTFileInfo.h"

@interface StoredEventTest : XCTestCase
@end

@implementation StoredEventTest

- (NSString*)bundleExample {
  NSString* rp = [[NSBundle bundleForClass:[self class]] resourcePath];
  return [rp stringByAppendingPathComponent:@"testdata/BundleExample.app"];
}

- (NSString*)developerSignedExecutableExample {
  return [[NSBundle bundleForClass:[self class]] pathForResource:@"signed-with-teamid" ofType:nil];
}

- (void)testBundleEvent {
  NSString* path = [self bundleExample];
  SNTFileInfo* fi = [[SNTFileInfo alloc] initWithPath:path];
  SNTStoredExecutionEvent* sut = [[SNTStoredExecutionEvent alloc] initWithFileInfo:fi];

  XCTAssertNotNil(sut);
  XCTAssertEqualObjects(sut.filePath, fi.path);
  XCTAssertEqualObjects(sut.fileSHA256, fi.SHA256);
  XCTAssertEqual(sut.signingStatus, SNTSigningStatusUnsigned);
}

- (void)testDeveloperSignedEvent {
  NSString* path = [self developerSignedExecutableExample];
  SNTFileInfo* fi = [[SNTFileInfo alloc] initWithPath:path];
  SNTStoredExecutionEvent* sut = [[SNTStoredExecutionEvent alloc] initWithFileInfo:fi];

  XCTAssertNotNil(sut);
  XCTAssertEqualObjects(sut.filePath, fi.path);
  XCTAssertEqualObjects(sut.fileSHA256, fi.SHA256);
  XCTAssertEqual(sut.signingStatus, SNTSigningStatusDevelopment);
  XCTAssertEqualObjects(sut.cdhash, @"23cbe7039ac34bf26f0b1ccc22ff96d6f0d80b72");
  XCTAssertEqualObjects(sut.teamID, @"EQHXZ8M8AV");
  XCTAssertEqualObjects(sut.signingID, @"EQHXZ8M8AV:goodcert");
  XCTAssertEqual(sut.signingChain.count, 3);
  XCTAssertEqual(sut.entitlements.count, 0);
}

- (void)testProductionSignedEvent {
  SNTFileInfo* fi = [[SNTFileInfo alloc] initWithPath:@"/usr/bin/yes"];
  SNTStoredExecutionEvent* sut = [[SNTStoredExecutionEvent alloc] initWithFileInfo:fi];

  XCTAssertNotNil(sut);
  XCTAssertEqualObjects(sut.filePath, fi.path);
  XCTAssertEqualObjects(sut.fileSHA256, fi.SHA256);
  XCTAssertEqual(sut.signingStatus, SNTSigningStatusProduction);
}

- (void)testUniqueIDFallsBackWhenHashMissing {
  SNTStoredExecutionEvent* se = [[SNTStoredExecutionEvent alloc] init];
  se.decision = SNTEventStateBlockBinaryMismatch;
  se.filePath = @"/tmp/gone";
  se.cdhash = @"aabbccdd";
  XCTAssertEqualObjects([se uniqueID], @"cdhash:aabbccdd");
  se.cdhash = nil;
  XCTAssertEqualObjects([se uniqueID], @"path:/tmp/gone");
}

- (void)testUniqueIDComposesAuditAndMismatchSuffixes {
  // :mismatch keys on identityUnverified, not a decision value, so it cannot
  // silently stop firing if a decision enum member is removed.
  SNTStoredExecutionEvent* normal = [[SNTStoredExecutionEvent alloc] init];
  normal.fileSHA256 = @"abc";
  normal.decision = SNTEventStateAllowBinary;
  XCTAssertEqualObjects([normal uniqueID], @"abc");

  SNTStoredExecutionEvent* auditOnly = [[SNTStoredExecutionEvent alloc] init];
  auditOnly.fileSHA256 = @"abc";
  auditOnly.decision = SNTEventStateAllowBinary;
  auditOnly.auditReturn = YES;
  XCTAssertEqualObjects([auditOnly uniqueID], @"abc:audit");

  SNTStoredExecutionEvent* mismatchOnly = [[SNTStoredExecutionEvent alloc] init];
  mismatchOnly.fileSHA256 = @"abc";
  mismatchOnly.decision = SNTEventStateAllowBinary;
  mismatchOnly.identityUnverified = YES;
  XCTAssertEqualObjects([mismatchOnly uniqueID], @"abc:mismatch");

  SNTStoredExecutionEvent* auditAndMismatch = [[SNTStoredExecutionEvent alloc] init];
  auditAndMismatch.fileSHA256 = @"abc";
  auditAndMismatch.decision = SNTEventStateAllowBinary;
  auditAndMismatch.auditReturn = YES;
  auditAndMismatch.identityUnverified = YES;
  XCTAssertEqualObjects([auditAndMismatch uniqueID], @"abc:audit:mismatch");

  NSArray<NSString*>* keys = @[
    [normal uniqueID], [auditOnly uniqueID], [mismatchOnly uniqueID], [auditAndMismatch uniqueID]
  ];
  XCTAssertEqual([NSSet setWithArray:keys].count, keys.count);
}

- (void)testUnactionableEventNoWhenIdentityUnverifiedWithHash {
  SNTStoredExecutionEvent* se = [[SNTStoredExecutionEvent alloc] init];
  se.decision = SNTEventStateAllowBinary;
  se.fileSHA256 = @"abc";
  se.identityUnverified = YES;
  XCTAssertFalse([se unactionableEvent]);

  se.identityUnverified = NO;  // ordinary allow stays unactionable
  XCTAssertTrue([se unactionableEvent]);
}

- (void)testUnactionableEventYesWhenIdentityUnverifiedWithoutHash {
  SNTStoredExecutionEvent* se = [[SNTStoredExecutionEvent alloc] init];
  se.decision = SNTEventStateAllowUnknown;
  se.identityUnverified = YES;
  se.filePath = @"/tmp/gone";
  se.cdhash = @"aabbccdd";
  XCTAssertTrue([se unactionableEvent]);

  se.cdhash = nil;
  XCTAssertTrue([se unactionableEvent]);

  // A block is never unactionable, hash or no hash.
  se.decision = SNTEventStateBlockUnknown;
  XCTAssertFalse([se unactionableEvent]);
}

- (SNTStoredExecutionEvent*)roundTripped:(SNTStoredExecutionEvent*)se {
  NSData* data = [NSKeyedArchiver archivedDataWithRootObject:se
                                       requiringSecureCoding:YES
                                                       error:nil];
  XCTAssertNotNil(data);
  NSSet* allowed = [NSSet setWithObject:[SNTStoredExecutionEvent class]];
  return [NSKeyedUnarchiver unarchivedObjectOfClasses:allowed fromData:data error:nil];
}

- (void)testIdentityVendorMatchedSurvivesSecureCodingRoundTrip {
  SNTStoredExecutionEvent* se = [[SNTStoredExecutionEvent alloc] init];
  se.identityUnverified = YES;
  se.identityVendorMatched = YES;
  se.fileSHA256 = @"abc";

  SNTStoredExecutionEvent* out = [self roundTripped:se];
  XCTAssertTrue(out.identityUnverified);
  XCTAssertTrue(out.identityVendorMatched);
  XCTAssertEqualObjects(out.fileSHA256, @"abc");
}

- (void)testAnnotationsSurviveSecureCodingRoundTrip {
  SNTStoredExecutionEvent* se = [[SNTStoredExecutionEvent alloc] init];
  se.annotations = @[ @"alpha", @"zeta" ];

  SNTStoredExecutionEvent* out = [self roundTripped:se];
  XCTAssertEqualObjects(out.annotations, (@[ @"alpha", @"zeta" ]));
}

- (void)testIdentityVendorMatchedDefaultsToNoAndSurvivesRoundTrip {
  // A spurious identityVendorMatched on decode would route this through the
  // verified branches in -createRuleForStandaloneModeEvent:.
  SNTStoredExecutionEvent* se = [[SNTStoredExecutionEvent alloc] init];
  se.identityUnverified = YES;
  se.fileSHA256 = @"abc";

  SNTStoredExecutionEvent* out = [self roundTripped:se];
  XCTAssertTrue(out.identityUnverified);
  XCTAssertFalse(out.identityVendorMatched);
}

@end
