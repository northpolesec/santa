/// Copyright 2015 Google Inc. All rights reserved.
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

#import <NetworkExtension/NetworkExtension.h>
#import <OCMock/OCMock.h>
#import <SystemExtensions/SystemExtensions.h>
#import <XCTest/XCTest.h>

#import "Source/common/SNTXPCControlInterface.h"
#import "Source/gui/SNTSystemExtensionDelegate.h"

@interface SNTSystemExtensionDelegate (Testing)
- (void)enableFilterConfiguration;
- (void)disableFilterConfiguration;
@end

@interface SNTSystemExtensionDelegateTest : XCTestCase
@end

@implementation SNTSystemExtensionDelegateTest

- (void)setUp {
  [super setUp];
  fclose(stdout);
}

- (void)testDelegateForSantadActivation {
  SNTSystemExtensionDelegate *delegate = [SNTSystemExtensionDelegate delegateForSantadActivation];

  XCTAssertNotNil(delegate);
  XCTAssertFalse(delegate.isNetworkExtension);
  XCTAssertTrue(delegate.isActivation);
  XCTAssertNotNil(delegate.request);
  XCTAssertEqualObjects(delegate.request.identifier,
                        [SNTXPCControlInterface santaExtensionBundleID]);
}

- (void)testDelegateForSantadDeactivation {
  SNTSystemExtensionDelegate *delegate = [SNTSystemExtensionDelegate delegateForSantadDeactivation];

  XCTAssertNotNil(delegate);
  XCTAssertFalse(delegate.isNetworkExtension);
  XCTAssertFalse(delegate.isActivation);
  XCTAssertNotNil(delegate.request);
  XCTAssertEqualObjects(delegate.request.identifier,
                        [SNTXPCControlInterface santaExtensionBundleID]);
}

- (void)testDelegateForSantanetdActivation {
  SNTSystemExtensionDelegate *delegate =
      [SNTSystemExtensionDelegate delegateForSantanetdActivation];

  XCTAssertNotNil(delegate);
  XCTAssertTrue(delegate.isNetworkExtension);
  XCTAssertTrue(delegate.isActivation);
  XCTAssertNotNil(delegate.request);
  XCTAssertEqualObjects(delegate.request.identifier,
                        [SNTXPCControlInterface santanetdExtensionBundleID]);
}

- (void)testDelegateForSantanetdDeactivation {
  SNTSystemExtensionDelegate *delegate =
      [SNTSystemExtensionDelegate delegateForSantanetdDeactivation];

  XCTAssertNotNil(delegate);
  XCTAssertTrue(delegate.isNetworkExtension);
  XCTAssertFalse(delegate.isActivation);
  XCTAssertNotNil(delegate.request);
  XCTAssertEqualObjects(delegate.request.identifier,
                        [SNTXPCControlInterface santanetdExtensionBundleID]);
}

- (void)testRequestDelegateIsSetCorrectly {
  SNTSystemExtensionDelegate *delegate = [SNTSystemExtensionDelegate delegateForSantadActivation];

  XCTAssertEqualObjects(delegate.request.delegate, delegate);
}

- (void)testSubmit {
  SNTSystemExtensionDelegate *delegate = [SNTSystemExtensionDelegate delegateForSantadActivation];

  id managerMock = OCMClassMock([OSSystemExtensionManager class]);

  OCMStub([managerMock sharedManager]).andReturn(managerMock);
  OCMExpect([managerMock submitRequest:delegate.request]);

  [delegate submit];

  OCMVerifyAll(managerMock);

  [managerMock stopMocking];
}

- (void)testEnableFilterConfiguration {
  SNTSystemExtensionDelegate *delegate =
      [SNTSystemExtensionDelegate delegateForSantanetdActivation];

  id managerMock = OCMClassMock([NEFilterManager class]);

  OCMStub([managerMock sharedManager]).andReturn(managerMock);

  // Stub loadFromPreferencesWithCompletionHandler to immediately call completion with no error
  OCMStub([managerMock
      loadFromPreferencesWithCompletionHandler:([OCMArg invokeBlockWithArgs:[NSNull null], nil])]);
  OCMExpect([managerMock setProviderConfiguration:[OCMArg checkWithBlock:^BOOL(id obj) {
                           NEFilterProviderConfiguration *config = obj;
                           XCTAssertNotNil(config);
                           XCTAssertTrue(config.filterSockets);
                           XCTAssertFalse(config.filterPackets);
                           XCTAssertEqualObjects(config.organization, @"North Pole Security");
                           XCTAssertFalse(config.filterBrowsers);
                           XCTAssertEqualObjects(config.filterDataProviderBundleIdentifier,
                                                 @"com.northpolesec.santa.netd");
                           return YES;
                         }]]);
  OCMExpect([managerMock setLocalizedDescription:@"Santa Network Extension"]);
  OCMExpect([managerMock setEnabled:YES]);
  OCMExpect([managerMock saveToPreferencesWithCompletionHandler:[OCMArg any]]);

  [delegate enableFilterConfiguration];

  OCMVerifyAll(managerMock);

  [managerMock stopMocking];
}

- (void)testDisableFilterConfiguration {
  SNTSystemExtensionDelegate *delegate =
      [SNTSystemExtensionDelegate delegateForSantanetdDeactivation];

  id managerMock = OCMClassMock([NEFilterManager class]);
  OCMStub([managerMock sharedManager]).andReturn(managerMock);

  OCMStub([managerMock
      loadFromPreferencesWithCompletionHandler:([OCMArg invokeBlockWithArgs:[NSNull null], nil])]);
  OCMExpect([managerMock removeFromPreferencesWithCompletionHandler:[OCMArg any]]);

  [delegate disableFilterConfiguration];

  // Verify removeFromPreferencesWithCompletionHandler was called
  OCMVerifyAll(managerMock);

  [managerMock stopMocking];
}

@end
