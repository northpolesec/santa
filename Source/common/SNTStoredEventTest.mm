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

#import "Source/common/SNTStoredEvent.h"
#import "Source/common/SNTStoredExecutionEvent.h"
#import "Source/common/SNTStoredFileAccessEvent.h"

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#import "Source/common/SNTFileInfo.h"

@interface StoredEventTest : XCTestCase
@end

@implementation StoredEventTest

- (NSString *)bundleExample {
  NSString *rp = [[NSBundle bundleForClass:[self class]] resourcePath];
  return [rp stringByAppendingPathComponent:@"testdata/BundleExample.app"];
}

- (NSString *)developerSignedExecutableExample {
  return [[NSBundle bundleForClass:[self class]] pathForResource:@"signed-with-teamid" ofType:nil];
}

- (void)testBundleEvent {
  NSString *path = [self bundleExample];
  SNTFileInfo *fi = [[SNTFileInfo alloc] initWithPath:path];
  SNTStoredExecutionEvent *sut = [[SNTStoredExecutionEvent alloc] initWithFileInfo:fi];

  XCTAssertNotNil(sut);
  XCTAssertEqualObjects(sut.filePath, fi.path);
  XCTAssertEqualObjects(sut.fileSHA256, fi.SHA256);
  XCTAssertEqual(sut.signingStatus, SNTSigningStatusUnsigned);
}

- (void)testDeveloperSignedEvent {
  NSString *path = [self developerSignedExecutableExample];
  SNTFileInfo *fi = [[SNTFileInfo alloc] initWithPath:path];
  SNTStoredExecutionEvent *sut = [[SNTStoredExecutionEvent alloc] initWithFileInfo:fi];

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
  SNTFileInfo *fi = [[SNTFileInfo alloc] initWithPath:@"/usr/bin/yes"];
  SNTStoredExecutionEvent *sut = [[SNTStoredExecutionEvent alloc] initWithFileInfo:fi];

  XCTAssertNotNil(sut);
  XCTAssertEqualObjects(sut.filePath, fi.path);
  XCTAssertEqualObjects(sut.fileSHA256, fi.SHA256);
  XCTAssertEqual(sut.signingStatus, SNTSigningStatusProduction);
}

- (void)testFileSHA256Property {
  // The base class should throw
  SNTStoredEvent *baseEvent = [[SNTStoredEvent alloc] init];
  XCTAssertThrows([baseEvent hashForEvent]);

  // Derived classes should not throw
  SNTStoredExecutionEvent *execEvent = [[SNTStoredExecutionEvent alloc] init];
  execEvent.fileSHA256 = @"foo";
  XCTAssertEqualObjects([execEvent hashForEvent], @"foo");

  SNTStoredFileAccessEvent *faaEvent = [[SNTStoredFileAccessEvent alloc] init];
  faaEvent.process.fileSHA256 = @"bar";
  XCTAssertEqualObjects([faaEvent hashForEvent], @"bar");
}

@end
