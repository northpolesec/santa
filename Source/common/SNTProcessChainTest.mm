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

#import "Source/common/SNTProcessChain.h"

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#import "Source/common/MOLCertificate.h"

@interface SNTProcessChainTest : XCTestCase
@end

@implementation SNTProcessChainTest

- (void)testSupportsSecureCoding {
  XCTAssertTrue([SNTProcessChain supportsSecureCoding]);
}

- (void)testEncodeDecodeBasicProperties {
  SNTProcessChain *chain = [[SNTProcessChain alloc] init];
  chain.filePath = @"/usr/bin/mount_smbfs";
  chain.fileSHA256 = @"abc123def456";
  chain.cdhash = @"deadbeef";
  chain.signingID = @"com.apple.mount_smbfs";
  chain.teamID = @"TEAMID123";
  chain.pid = @(12345);
  chain.pidversion = @(1);
  chain.executingUser = @"testuser";
  chain.executingUserID = @(501);

  // Archive the chain
  NSData *archivedChain = [NSKeyedArchiver archivedDataWithRootObject:chain
                                                requiringSecureCoding:YES
                                                                error:nil];

  XCTAssertNotNil(archivedChain);

  // Unarchive the chain
  NSSet *allowedClasses = [NSSet setWithObjects:[SNTProcessChain class], nil];
  SNTProcessChain *decodedChain = [NSKeyedUnarchiver unarchivedObjectOfClasses:allowedClasses
                                                                      fromData:archivedChain
                                                                         error:nil];

  XCTAssertNotNil(decodedChain);
  XCTAssertEqualObjects(decodedChain.filePath, @"/usr/bin/mount_smbfs");
  XCTAssertEqualObjects(decodedChain.fileSHA256, @"abc123def456");
  XCTAssertEqualObjects(decodedChain.cdhash, @"deadbeef");
  XCTAssertEqualObjects(decodedChain.signingID, @"com.apple.mount_smbfs");
  XCTAssertEqualObjects(decodedChain.teamID, @"TEAMID123");
  XCTAssertEqualObjects(decodedChain.pid, @(12345));
  XCTAssertEqualObjects(decodedChain.pidversion, @(1));
  XCTAssertEqualObjects(decodedChain.executingUser, @"testuser");
  XCTAssertEqualObjects(decodedChain.executingUserID, @(501));
  XCTAssertNil(decodedChain.parent);
}

- (void)testEncodeDecodeWithParent {
  // Create child process
  SNTProcessChain *child = [[SNTProcessChain alloc] init];
  child.filePath = @"/usr/bin/mount";
  child.pid = @(100);
  child.executingUser = @"user1";

  // Create parent process
  child.parent = [[SNTProcessChain alloc] init];
  child.parent.filePath = @"/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder";
  child.parent.pid = @(50);
  child.parent.executingUser = @"user1";
  child.parent.fileSHA256 = @"parent_sha256";

  // Archive
  NSData *archivedChain = [NSKeyedArchiver archivedDataWithRootObject:child
                                                requiringSecureCoding:YES
                                                                error:nil];

  XCTAssertNotNil(archivedChain);

  // Unarchive
  NSSet *allowedClasses = [NSSet setWithObjects:[SNTProcessChain class], nil];
  SNTProcessChain *decodedChain = [NSKeyedUnarchiver unarchivedObjectOfClasses:allowedClasses
                                                                      fromData:archivedChain
                                                                         error:nil];

  XCTAssertNotNil(decodedChain);
  XCTAssertEqualObjects(decodedChain.filePath, @"/usr/bin/mount");
  XCTAssertEqualObjects(decodedChain.pid, @(100));

  // Verify parent
  XCTAssertNotNil(decodedChain.parent);
  XCTAssertEqualObjects(decodedChain.parent.filePath,
                        @"/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder");
  XCTAssertEqualObjects(decodedChain.parent.pid, @(50));
  XCTAssertEqualObjects(decodedChain.parent.fileSHA256, @"parent_sha256");
  XCTAssertNil(decodedChain.parent.parent);
}

- (void)testEncodeDecodeWithMultipleGenerations {
  // Create grandchild process
  SNTProcessChain *grandchild = [[SNTProcessChain alloc] init];
  grandchild.filePath = @"/usr/bin/curl";
  grandchild.pid = @(300);

  // Create child (parent of grandchild)
  grandchild.parent = [[SNTProcessChain alloc] init];
  grandchild.parent.filePath = @"/bin/bash";
  grandchild.parent.pid = @(200);

  // Create grandparent (parent of child)
  grandchild.parent.parent = [[SNTProcessChain alloc] init];
  grandchild.parent.parent.filePath = @"/Applications/Terminal.app/Contents/MacOS/Terminal";
  grandchild.parent.parent.pid = @(100);

  // Archive
  NSData *archivedChain = [NSKeyedArchiver archivedDataWithRootObject:grandchild
                                                requiringSecureCoding:YES
                                                                error:nil];

  XCTAssertNotNil(archivedChain);

  // Unarchive
  NSSet *allowedClasses = [NSSet setWithObjects:[SNTProcessChain class], nil];
  SNTProcessChain *decodedChain = [NSKeyedUnarchiver unarchivedObjectOfClasses:allowedClasses
                                                                      fromData:archivedChain
                                                                         error:nil];

  XCTAssertNotNil(decodedChain);
  XCTAssertEqualObjects(decodedChain.filePath, @"/usr/bin/curl");
  XCTAssertEqualObjects(decodedChain.pid, @(300));

  // Verify parent
  XCTAssertNotNil(decodedChain.parent);
  XCTAssertEqualObjects(decodedChain.parent.filePath, @"/bin/bash");
  XCTAssertEqualObjects(decodedChain.parent.pid, @(200));

  // Verify grandparent
  XCTAssertNotNil(decodedChain.parent.parent);
  XCTAssertEqualObjects(decodedChain.parent.parent.filePath,
                        @"/Applications/Terminal.app/Contents/MacOS/Terminal");
  XCTAssertEqualObjects(decodedChain.parent.parent.pid, @(100));
  XCTAssertNil(decodedChain.parent.parent.parent);
}

- (void)testEncodeDecodeWithNilValues {
  SNTProcessChain *chain = [[SNTProcessChain alloc] init];
  chain.filePath = @"/usr/bin/test";
  chain.pid = @(999);
  // Leave all other properties as nil

  NSData *archivedChain = [NSKeyedArchiver archivedDataWithRootObject:chain
                                                requiringSecureCoding:YES
                                                                error:nil];

  XCTAssertNotNil(archivedChain);

  NSSet *allowedClasses = [NSSet setWithObjects:[SNTProcessChain class], nil];
  SNTProcessChain *decodedChain = [NSKeyedUnarchiver unarchivedObjectOfClasses:allowedClasses
                                                                      fromData:archivedChain
                                                                         error:nil];

  XCTAssertNotNil(decodedChain);
  XCTAssertEqualObjects(decodedChain.filePath, @"/usr/bin/test");
  XCTAssertEqualObjects(decodedChain.pid, @(999));
  XCTAssertNil(decodedChain.fileSHA256);
  XCTAssertNil(decodedChain.cdhash);
  XCTAssertNil(decodedChain.signingID);
  XCTAssertNil(decodedChain.teamID);
  XCTAssertNil(decodedChain.signingChain);
  XCTAssertNil(decodedChain.pidversion);
  XCTAssertNil(decodedChain.executingUser);
  XCTAssertNil(decodedChain.executingUserID);
  XCTAssertNil(decodedChain.parent);
}

@end
