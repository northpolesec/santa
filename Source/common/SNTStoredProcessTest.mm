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

#import "Source/common/SNTStoredProcess.h"

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

@interface SNTStoredProcessTest : XCTestCase
@end

@implementation SNTStoredProcessTest

- (void)testEncodeDecodeRoundTripWithParent {
  SNTStoredProcess* p = [[SNTStoredProcess alloc] init];
  p.filePath = @"/usr/bin/curl";
  p.cdhash = @"deadbeef";
  p.fileSHA256 = @"abc123";
  p.signingID = @"com.apple.curl";
  p.teamID = @"TEAMID1234";
  p.pid = @(4242);
  p.executingUser = @"alice";
  p.parent = [[SNTStoredProcess alloc] init];
  p.parent.filePath = @"/sbin/launchd";
  p.parent.pid = @(1);

  NSData* data = [NSKeyedArchiver archivedDataWithRootObject:p requiringSecureCoding:YES error:nil];
  XCTAssertNotNil(data);

  NSSet* allowed = [NSSet setWithObjects:[SNTStoredProcess class], nil];
  SNTStoredProcess* decoded = [NSKeyedUnarchiver unarchivedObjectOfClasses:allowed
                                                                  fromData:data
                                                                     error:nil];
  XCTAssertEqualObjects(decoded.filePath, @"/usr/bin/curl");
  XCTAssertEqualObjects(decoded.cdhash, @"deadbeef");
  XCTAssertEqualObjects(decoded.fileSHA256, @"abc123");
  XCTAssertEqualObjects(decoded.signingID, @"com.apple.curl");
  XCTAssertEqualObjects(decoded.teamID, @"TEAMID1234");
  XCTAssertEqualObjects(decoded.pid, @(4242));
  XCTAssertEqualObjects(decoded.executingUser, @"alice");
  XCTAssertEqualObjects(decoded.parent.filePath, @"/sbin/launchd");
  XCTAssertEqualObjects(decoded.parent.pid, @(1));
  XCTAssertNil(decoded.parent.parent);
}

// Mimics an archive written by a Santa version from before the rename (the
// process object carries the legacy class name). The alias registered in
// +[SNTStoredProcess initialize] must decode it into the current type.
- (void)testDecodesLegacyArchivedClassName {
  SNTStoredProcess* p = [[SNTStoredProcess alloc] init];
  p.filePath = @"/usr/bin/curl";
  p.cdhash = @"deadbeef";
  p.pid = @(4242);
  p.parent = [[SNTStoredProcess alloc] init];
  p.parent.pid = @(1);

  NSKeyedArchiver* archiver = [[NSKeyedArchiver alloc] initRequiringSecureCoding:YES];
  [archiver setClassName:@"SNTStoredFileAccessProcess" forClass:[SNTStoredProcess class]];
  [archiver encodeObject:p forKey:NSKeyedArchiveRootObjectKey];
  [archiver finishEncoding];

  NSSet* allowed = [NSSet setWithObjects:[SNTStoredProcess class], nil];
  SNTStoredProcess* decoded = [NSKeyedUnarchiver unarchivedObjectOfClasses:allowed
                                                                  fromData:archiver.encodedData
                                                                     error:nil];
  XCTAssertNotNil(decoded);
  XCTAssertEqualObjects(decoded.filePath, @"/usr/bin/curl");
  XCTAssertEqualObjects(decoded.cdhash, @"deadbeef");
  XCTAssertEqualObjects(decoded.pid, @(4242));
  XCTAssertEqualObjects(decoded.parent.pid, @(1));
}

@end
