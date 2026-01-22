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

#import <OCMock/OCMock.h>
#import <SystemExtensions/SystemExtensions.h>
#import <XCTest/XCTest.h>

#import "Source/common/SNTXPCControlInterface.h"
#import "Source/common/TestUtils.h"
#import "Source/gui/SNTSystemExtensionDelegate.h"

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

- (void)testSubmitAndExitAsync {
  SNTSystemExtensionDelegate *delegate = [SNTSystemExtensionDelegate delegateForSantadActivation];

  dispatch_semaphore_t sema = dispatch_semaphore_create(0);

  id managerMock = OCMClassMock([OSSystemExtensionManager class]);

  OCMStub([managerMock sharedManager]).andReturn(managerMock);
  OCMStub([managerMock submitRequest:delegate.request]).andDo(^(NSInvocation *invocation) {
    dispatch_semaphore_signal(sema);
  });

  [delegate submitAndExitAsync];

  XCTAssertSemaTrue(sema, 5, @"submitRequest should be called within 5 seconds");

  [managerMock stopMocking];
}

@end
