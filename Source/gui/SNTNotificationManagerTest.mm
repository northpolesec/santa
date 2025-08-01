/// Copyright 2022 Google Inc. All rights reserved.
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

#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>

#import "Source/gui/SNTNotificationManager.h"

#import "Source/common/SNTStoredExecutionEvent.h"

@class SNTBinaryMessageWindowController;

@interface SNTNotificationManager (Testing)
- (void)hashBundleBinariesForEvent:(SNTStoredEvent *)event
                    withController:(SNTBinaryMessageWindowController *)controller;
@end

@interface SNTNotificationManagerTest : XCTestCase
@end

@implementation SNTNotificationManagerTest

- (void)setUp {
  [super setUp];
  fclose(stdout);
}

- (void)testPostBlockNotificationSendsDistributedNotification {
  SNTStoredExecutionEvent *ev = [[SNTStoredExecutionEvent alloc] init];
  ev.fileSHA256 = @"the-sha256";
  ev.filePath = @"/Applications/Safari.app/Contents/MacOS/Safari";
  ev.fileBundleName = @"Safari";
  ev.fileBundlePath = @"/Applications/Safari.app";
  ev.fileBundleID = @"com.apple.Safari";
  ev.fileBundleVersion = @"18614.1.14.1.15";
  ev.fileBundleVersionString = @"16.0";
  ev.executingUser = @"rah";
  ev.occurrenceDate = [NSDate dateWithTimeIntervalSince1970:1660221048];
  ev.decision = SNTEventStateBlockBinary;
  ev.pid = @84156;
  ev.ppid = @1;
  ev.parentName = @"launchd";

  SNTNotificationManager *sut = OCMPartialMock([[SNTNotificationManager alloc] init]);
  OCMStub([sut hashBundleBinariesForEvent:OCMOCK_ANY withController:OCMOCK_ANY]).andDo(nil);

  id dncMock = OCMClassMock([NSDistributedNotificationCenter class]);
  OCMStub([dncMock defaultCenter]).andReturn(dncMock);

  [sut postBlockNotification:ev
           withCustomMessage:@""
                   customURL:@""
                 configState:nil
                    andReply:^(BOOL authenticated){
                    }];

  OCMVerify([dncMock postNotificationName:@"com.northpolesec.santa.notification.blockedeexecution"
                                   object:@"com.northpolesec.santa"
                                 userInfo:[OCMArg checkWithBlock:^BOOL(NSDictionary *userInfo) {
                                   XCTAssertEqualObjects(userInfo[@"file_sha256"], @"the-sha256");
                                   XCTAssertEqualObjects(userInfo[@"pid"], @84156);
                                   XCTAssertEqualObjects(userInfo[@"ppid"], @1);
                                   XCTAssertEqualObjects(userInfo[@"execution_time"], @1660221048);
                                   return YES;
                                 }]
                       deliverImmediately:YES]);
}

- (void)testDidRegisterForAPNS {
  SNTNotificationManager *nm = [[SNTNotificationManager alloc] init];

  // The manager has not registered with APNS, the token in the reply block should be nil.
  __block NSString *token;
  [nm requestAPNSToken:^(NSString *reply) {
    token = reply;
  }];
  NSString *wantToken;
  XCTAssertEqualObjects(token, wantToken);

  // Register with APNS, the token should now be returned.
  wantToken = @"123";
  token = nil;
  [nm didRegisterForAPNS:wantToken];
  [nm requestAPNSToken:^(NSString *reply) {
    token = reply;
  }];
  XCTAssertEqualObjects(token, wantToken);

  // Subsequent requests should also return the token.
  token = nil;
  [nm requestAPNSToken:^(NSString *reply) {
    token = reply;
  }];
  XCTAssertEqualObjects(token, wantToken);
}

@end
