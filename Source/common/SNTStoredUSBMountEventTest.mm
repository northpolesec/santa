/// Copyright 2026 North Pole Security, Inc.
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

#import "Source/common/SNTStoredUSBMountEvent.h"

#import <XCTest/XCTest.h>

@interface SNTStoredUSBMountEventTest : XCTestCase
@end

@implementation SNTStoredUSBMountEventTest

- (void)testUUID {
  SNTStoredUSBMountEvent *event = [[SNTStoredUSBMountEvent alloc] init];
  XCTAssertNotNil(event.uuid);
  XCTAssertGreaterThan(event.uuid.length, 0);

  SNTStoredUSBMountEvent *event2 = [[SNTStoredUSBMountEvent alloc] init];
  XCTAssertNotEqualObjects(event.uuid, event2.uuid);
}

- (void)testUniqueID {
  SNTStoredUSBMountEvent *event = [[SNTStoredUSBMountEvent alloc] init];
  event.mountOnName = @"/Volumes/USB_DRIVE";

  XCTAssertEqualObjects([event uniqueID], @"/Volumes/USB_DRIVE");

  // Change mountOnName and verify uniqueID changes
  event.mountOnName = @"/Volumes/ANOTHER_DRIVE";
  XCTAssertEqualObjects([event uniqueID], @"/Volumes/ANOTHER_DRIVE");
}

- (void)testUnactionableEvent {
  // USB mount events should be unactionable (OK to be part of backoff cache)
  SNTStoredUSBMountEvent *event = [[SNTStoredUSBMountEvent alloc] init];
  XCTAssertTrue([event unactionableEvent]);
}

- (void)testEncodeDecode {
  SNTStoredUSBMountEvent *event = [[SNTStoredUSBMountEvent alloc] init];
  event.mountOnName = @"/Volumes/USB_DRIVE";
  event.deviceModel = @"USB Flash Drive";
  event.deviceVendor = @"SanDisk";

  NSString *originalUUID = event.uuid;

  // Archive the event
  NSData *archivedEvent = [NSKeyedArchiver archivedDataWithRootObject:event
                                                requiringSecureCoding:YES
                                                                error:nil];

  XCTAssertNotNil(archivedEvent);

  // Unarchive the event
  NSSet *allowedClasses = [NSSet setWithObject:[SNTStoredUSBMountEvent class]];
  SNTStoredEvent *unarchivedEvent = [NSKeyedUnarchiver unarchivedObjectOfClasses:allowedClasses
                                                                        fromData:archivedEvent
                                                                           error:nil];

  XCTAssertNotNil(unarchivedEvent);
  XCTAssertTrue([unarchivedEvent isKindOfClass:[SNTStoredUSBMountEvent class]]);

  SNTStoredUSBMountEvent *decodedEvent = (SNTStoredUSBMountEvent *)unarchivedEvent;

  // Verify all properties survived encode/decode
  XCTAssertEqualObjects(decodedEvent.uuid, originalUUID);
  XCTAssertEqualObjects(decodedEvent.mountOnName, @"/Volumes/USB_DRIVE");
  XCTAssertEqualObjects(decodedEvent.deviceModel, @"USB Flash Drive");
  XCTAssertEqualObjects(decodedEvent.deviceVendor, @"SanDisk");
}

- (void)testEncodeDecodeWithNilValues {
  SNTStoredUSBMountEvent *event = [[SNTStoredUSBMountEvent alloc] init];
  event.mountOnName = @"/Volumes/USB_DRIVE";
  event.deviceModel = nil;
  event.deviceVendor = nil;

  NSData *archivedEvent = [NSKeyedArchiver archivedDataWithRootObject:event
                                                requiringSecureCoding:YES
                                                                error:nil];

  XCTAssertNotNil(archivedEvent);

  NSSet *allowedClasses = [NSSet setWithObject:[SNTStoredUSBMountEvent class]];
  SNTStoredEvent *unarchivedEvent = [NSKeyedUnarchiver unarchivedObjectOfClasses:allowedClasses
                                                                        fromData:archivedEvent
                                                                           error:nil];

  XCTAssertNotNil(unarchivedEvent);
  XCTAssertTrue([unarchivedEvent isKindOfClass:[SNTStoredUSBMountEvent class]]);

  SNTStoredUSBMountEvent *decodedEvent = (SNTStoredUSBMountEvent *)unarchivedEvent;

  XCTAssertEqualObjects(decodedEvent.mountOnName, @"/Volumes/USB_DRIVE");
  XCTAssertNil(decodedEvent.deviceModel);
  XCTAssertNil(decodedEvent.deviceVendor);
}

- (void)testDescription {
  SNTStoredUSBMountEvent *event = [[SNTStoredUSBMountEvent alloc] init];
  event.mountOnName = @"/Volumes/USB_DRIVE";
  event.deviceModel = @"USB Flash Drive";

  NSString *description = [event description];

  XCTAssertTrue([description containsString:@"SNTStoredUSBMountEvent"]);
  XCTAssertTrue([description containsString:@"USB Flash Drive"]);
  XCTAssertTrue([description containsString:@"/Volumes/USB_DRIVE"]);
}

@end
