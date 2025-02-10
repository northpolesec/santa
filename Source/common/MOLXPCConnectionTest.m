/// Copyright 2017 Google Inc. All rights reserved.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///    http://www.apache.org/licenses/LICENSE-2.0
///
///    Unless required by applicable law or agreed to in writing, software
///    distributed under the License is distributed on an "AS IS" BASIS,
///    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
///    See the License for the specific language governing permissions and
///    limitations under the License.

#import <XCTest/XCTest.h>

#import <OCMock/OCMock.h>

#import "Source/common/MOLCodesignChecker.h"
#import "Source/common/MOLXPCConnection.h"

@interface MOLXPCConnectionTest : XCTestCase
@end

@protocol DummyXPCProtocol
@end

@protocol DeepThoughtProtocol
- (void)theAnswerToLifeTheUniverseAndEverything:(void (^)(int))reply;
@end

@interface DeepThought : NSObject <DeepThoughtProtocol>
@end

@implementation DeepThought
- (void)theAnswerToLifeTheUniverseAndEverything:(void (^)(int))reply {
  reply(42);
}
@end

@implementation MOLXPCConnectionTest

- (NSXPCInterface *)deepThoughtInterface {
  static NSXPCInterface *interface;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    interface = [NSXPCInterface interfaceWithProtocol:@protocol(DeepThoughtProtocol)];
  });
  return interface;
}

- (void)testPlainInit {
  XCTAssertThrows([[MOLXPCConnection alloc] init]);
}

- (void)testInitClient {
  id mockConnection = OCMClassMock([NSXPCConnection class]);
  OCMStub([mockConnection alloc]).andReturn(mockConnection);
  OCMExpect([mockConnection initWithMachServiceName:@"Client" options:0]).andReturn(mockConnection);

  MOLXPCConnection *sut = [[MOLXPCConnection alloc] initClientWithName:@"Client" privileged:NO];
  XCTAssertNotNil(sut);

  OCMExpect([mockConnection initWithMachServiceName:@"Client" options:NSXPCConnectionPrivileged])
      .andReturn(mockConnection);
  sut = [[MOLXPCConnection alloc] initClientWithName:@"Client" privileged:YES];
  XCTAssertNotNil(sut);

  OCMVerifyAll(mockConnection);
  [mockConnection stopMocking];
}

- (void)testInitServer {
  id mockListener = OCMClassMock([NSXPCListener class]);
  OCMStub([mockListener alloc]).andReturn(mockListener);
  OCMExpect([mockListener initWithMachServiceName:@"TestServer"]).andReturn(mockListener);
  MOLXPCConnection *sut = [[MOLXPCConnection alloc] initServerWithName:@"TestServer"];
  XCTAssertNotNil(sut);
  OCMVerifyAll(mockListener);
  [mockListener stopMocking];
}

- (void)testConnectionRejection {
  pid_t pid = [[NSProcessInfo processInfo] processIdentifier];
  id mockCodesignChecker = OCMClassMock([MOLCodesignChecker class]);
  OCMStub([mockCodesignChecker alloc]).andReturn(mockCodesignChecker);
  OCMExpect([mockCodesignChecker initWithPID:pid]).andReturn(mockCodesignChecker);
  OCMExpect([mockCodesignChecker signingInformationMatches:OCMOCK_ANY]).andReturn(NO);

  NSXPCListener *listener = [NSXPCListener anonymousListener];

  MOLXPCConnection *sutServer = [[MOLXPCConnection alloc] initServerWithListener:listener];
  sutServer.unprivilegedInterface =
      [NSXPCInterface interfaceWithProtocol:@protocol(DummyXPCProtocol)];
  [sutServer resume];

  __block XCTestExpectation *exp1 = [self expectationWithDescription:@"Client Invalidated"];
  MOLXPCConnection *sutClient = [[MOLXPCConnection alloc] initClientWithListener:listener.endpoint];
  sutClient.invalidationHandler = ^{
    [exp1 fulfill];
    exp1 = nil;  // precent multiple fulfill violation
  };
  [sutClient resume];

  [self waitForExpectationsWithTimeout:3.0 handler:NULL];

  [mockCodesignChecker stopMocking];
}

- (void)testConnectionAcceptance {
  NSXPCListener *listener = [NSXPCListener anonymousListener];

  XCTestExpectation *exp1 = [self expectationWithDescription:@"Server Accepted"];
  MOLXPCConnection *sutServer = [[MOLXPCConnection alloc] initServerWithListener:listener];
  sutServer.unprivilegedInterface =
      [NSXPCInterface interfaceWithProtocol:@protocol(DummyXPCProtocol)];
  sutServer.acceptedHandler = ^{
    [exp1 fulfill];
  };
  [sutServer resume];

  XCTestExpectation *exp2 = [self expectationWithDescription:@"Client Accepted"];
  MOLXPCConnection *sutClient = [[MOLXPCConnection alloc] initClientWithListener:listener.endpoint];
  sutClient.acceptedHandler = ^{
    [exp2 fulfill];
  };
  [sutClient resume];

  [self waitForExpectationsWithTimeout:2.0 handler:NULL];
}

- (void)testConnectionInterruption {
  NSXPCListener *listener = [NSXPCListener anonymousListener];
  MOLXPCConnection *sutServer = [[MOLXPCConnection alloc] initServerWithListener:listener];
  sutServer.unprivilegedInterface =
      [NSXPCInterface interfaceWithProtocol:@protocol(DummyXPCProtocol)];
  [sutServer resume];

  __block XCTestExpectation *exp1 = [self expectationWithDescription:@"Client Invalidated"];
  MOLXPCConnection *sutClient = [[MOLXPCConnection alloc] initClientWithListener:listener.endpoint];
  sutClient.invalidationHandler = ^{
    [exp1 fulfill];
    exp1 = nil;  // prevent multiple fulfill violation
  };
  [sutClient resume];

  [sutServer invalidate];
  sutServer = nil;

  [self waitForExpectationsWithTimeout:1.0 handler:NULL];
}

- (void)testSynchronous {
  NSXPCListener *listener = [NSXPCListener anonymousListener];
  MOLXPCConnection *sutServer = [[MOLXPCConnection alloc] initServerWithListener:listener];
  sutServer.unprivilegedInterface = [self deepThoughtInterface];
  sutServer.exportedObject = [[DeepThought alloc] init];
  [sutServer resume];

  __block int answer = 0;
  MOLXPCConnection *sutClient = [[MOLXPCConnection alloc] initClientWithListener:listener.endpoint];
  sutClient.remoteInterface = [self deepThoughtInterface];
  [sutClient resume];
  [[sutClient synchronousRemoteObjectProxy] theAnswerToLifeTheUniverseAndEverything:^(int reply) {
    answer = reply;
  }];
  XCTAssertEqual(answer, 42);
}

@end
