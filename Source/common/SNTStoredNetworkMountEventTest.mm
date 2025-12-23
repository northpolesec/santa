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

#import "Source/common/SNTStoredNetworkMountEvent.h"

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

@interface SNTStoredNetworkMountEventTest : XCTestCase
@end

@implementation SNTStoredNetworkMountEventTest

- (void)testUniqueID {
  SNTStoredNetworkMountEvent *event = [[SNTStoredNetworkMountEvent alloc] init];
  event.mountFromName = @"//server/share";
  event.mountOnName = @"/Volumes/share";
  event.fsType = @"smbfs";

  XCTAssertEqualObjects([event uniqueID], @"//server/share");

  // Change mountFromName and verify uniqueID changes
  event.mountFromName = @"//otherserver/data";
  XCTAssertEqualObjects([event uniqueID], @"//otherserver/data");
}

- (void)testUnactionableEvent {
  // Network mount events should be unactionable (OK to be part of backoff cache)
  SNTStoredNetworkMountEvent *event = [[SNTStoredNetworkMountEvent alloc] init];
  XCTAssertTrue([event unactionableEvent]);
}

- (void)testEncodeDecode {
  SNTStoredNetworkMountEvent *event = [[SNTStoredNetworkMountEvent alloc] init];
  event.mountFromName = @"//server/share";
  event.mountOnName = @"/Volumes/share";
  event.fsType = @"smbfs";

  // Set process chain properties
  event.process.filePath = @"/usr/bin/mount_smbfs";
  event.process.fileSHA256 = @"abc123def456";
  event.process.pid = @(12345);
  event.process.executingUser = @"testuser";
  event.process.executingUserID = @(501);
  event.process.cdhash = @"deadbeef";
  event.process.signingID = @"com.apple.mount_smbfs";
  event.process.teamID = @"TEAMID123";

  // Add parent process
  event.process.parent = [[SNTProcessChain alloc] init];
  event.process.parent.filePath = @"/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder";
  event.process.parent.pid = @(100);

  // Archive the event
  NSData *archivedEvent = [NSKeyedArchiver archivedDataWithRootObject:event
                                                requiringSecureCoding:YES
                                                                error:nil];

  XCTAssertNotNil(archivedEvent);

  // Unarchive the event
  NSSet *allowedClasses =
      [NSSet setWithObjects:[SNTStoredNetworkMountEvent class], [SNTProcessChain class], nil];
  SNTStoredEvent *unarchivedEvent = [NSKeyedUnarchiver unarchivedObjectOfClasses:allowedClasses
                                                                        fromData:archivedEvent
                                                                           error:nil];

  XCTAssertNotNil(unarchivedEvent);
  XCTAssertTrue([unarchivedEvent isKindOfClass:[SNTStoredNetworkMountEvent class]]);

  SNTStoredNetworkMountEvent *decodedEvent = (SNTStoredNetworkMountEvent *)unarchivedEvent;

  // Verify mount properties
  XCTAssertEqualObjects(decodedEvent.mountFromName, @"//server/share");
  XCTAssertEqualObjects(decodedEvent.mountOnName, @"/Volumes/share");
  XCTAssertEqualObjects(decodedEvent.fsType, @"smbfs");

  // Verify process properties
  XCTAssertNotNil(decodedEvent.process);
  XCTAssertEqualObjects(decodedEvent.process.filePath, @"/usr/bin/mount_smbfs");
  XCTAssertEqualObjects(decodedEvent.process.fileSHA256, @"abc123def456");
  XCTAssertEqualObjects(decodedEvent.process.pid, @(12345));
  XCTAssertEqualObjects(decodedEvent.process.executingUser, @"testuser");
  XCTAssertEqualObjects(decodedEvent.process.executingUserID, @(501));
  XCTAssertEqualObjects(decodedEvent.process.cdhash, @"deadbeef");
  XCTAssertEqualObjects(decodedEvent.process.signingID, @"com.apple.mount_smbfs");
  XCTAssertEqualObjects(decodedEvent.process.teamID, @"TEAMID123");

  // Verify parent process
  XCTAssertNotNil(decodedEvent.process.parent);
  XCTAssertEqualObjects(decodedEvent.process.parent.filePath,
                        @"/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder");
  XCTAssertEqualObjects(decodedEvent.process.parent.pid, @(100));
  XCTAssertNil(decodedEvent.process.parent.parent);
}

- (void)testEncodeDecodeWithNilValues {
  // Test that encoding/decoding works with nil process
  SNTStoredNetworkMountEvent *event = [[SNTStoredNetworkMountEvent alloc] init];
  event.mountFromName = @"//server/share";
  event.mountOnName = nil;  // Test nil value
  event.fsType = @"nfs";
  event.process = nil;  // Test nil process

  NSData *archivedEvent = [NSKeyedArchiver archivedDataWithRootObject:event
                                                requiringSecureCoding:YES
                                                                error:nil];

  XCTAssertNotNil(archivedEvent);

  NSSet *allowedClasses =
      [NSSet setWithObjects:[SNTStoredNetworkMountEvent class], [SNTProcessChain class], nil];
  SNTStoredEvent *unarchivedEvent = [NSKeyedUnarchiver unarchivedObjectOfClasses:allowedClasses
                                                                        fromData:archivedEvent
                                                                           error:nil];

  XCTAssertNotNil(unarchivedEvent);
  XCTAssertTrue([unarchivedEvent isKindOfClass:[SNTStoredNetworkMountEvent class]]);

  SNTStoredNetworkMountEvent *decodedEvent = (SNTStoredNetworkMountEvent *)unarchivedEvent;

  XCTAssertEqualObjects(decodedEvent.mountFromName, @"//server/share");
  XCTAssertNil(decodedEvent.mountOnName);
  XCTAssertEqualObjects(decodedEvent.fsType, @"nfs");
  XCTAssertNil(decodedEvent.process);
}

@end
