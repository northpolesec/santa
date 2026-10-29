/// Copyright 2022 Google Inc. All rights reserved.
/// Copyright 2024 North Pole Security, Inc.
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

#include <EndpointSecurity/ESTypes.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <mach/machine.h>

#include <map>
#include <memory>
#include <set>
#include <vector>

#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#include "Source/common/SantaVnode.h"
#include "Source/common/SystemResources.h"
#include "Source/common/TestUtils.h"
#include "Source/common/es/Client.h"
#include "Source/common/es/Message.h"
#include "Source/common/es/MockEndpointSecurityAPI.h"
#include "Source/santad/EventProviders/AuthResultCache.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityAuthorizer.h"
#include "Source/santad/Metrics.h"
#import "Source/santad/SNTCompilerController.h"
#import "Source/santad/SNTExecutionController.h"
#include "Source/santad/TTYWriter.h"

using santa::AuthResultCache;
using santa::EventDisposition;
using santa::Message;

class MockAuthResultCache : public AuthResultCache {
 public:
  // A Reserve past a test's scripted answers still wins, so processMessage: returns
  // and the over-call fails the test instead of looping.
  MockAuthResultCache(std::shared_ptr<santa::ESCacheFlusher> es_cache_flusher,
                      SNTMetricCounter* flush_count)
      : AuthResultCache(std::move(es_cache_flusher), flush_count) {
    ON_CALL(*this, Reserve).WillByDefault(testing::Return(1));
  }

  MOCK_METHOD(uint64_t, Reserve,
              (const santa::ExecTarget& target, const santa::CachedAuthResult& expected));
  MOCK_METHOD(bool, AddToCache,
              (const santa::ExecTarget& target, SNTAction decision, SNTCachedDecision* cd,
               uint64_t reservation));
  MOCK_METHOD(santa::CachedAuthResult, CheckCache, (const santa::ExecTarget& target));
};

@interface SNTEndpointSecurityAuthorizer (Testing)
- (void)processMessage:(Message)msg;
- (bool)postAction:(SNTAction)action
        forMessage:(const Message&)esMsg
      withDecision:(SNTCachedDecision*)cd
       reservation:(uint64_t)reservation;
- (bool)respondToMessage:(const Message&)msg
          withAuthResult:(es_auth_result_t)result
       forcePreventCache:(BOOL)forcePreventCache;
- (NSString*)verifiedSHA256ForExecutable:(const es_file_t*)file;
@end

// This test fake exists due to limitations with OCMPartialMock. The partial mock object
// will retain all arguments until `stopMocking` is called. This interferes with tests
// that have explicit expectations set for actions such as ES message retain/release since
// the mock will hold a copy of a Message object (e.g. via the block passed to
// validateExecEvent:postAction:). The test fake here will simply signal the given
// semaphore when a method is called to mitigate the need to stub methods.
@interface FakeExecutionController : NSObject
@property dispatch_semaphore_t sema;
@property SNTCachedDecision* existingDecision;

- (instancetype)initWithSema:(dispatch_semaphore_t)sema;
- (void)validateExecEvent:(const santa::Message&)esMsg
           cachedDecision:(SNTCachedDecision*)existingDecision
               postAction:(bool (^)(SNTAction, SNTCachedDecision*))postAction;
@end

@implementation FakeExecutionController
- (instancetype)initWithSema:(dispatch_semaphore_t)sema {
  self = [super init];
  if (self) {
    _sema = sema;
  }
  return self;
}
- (void)validateExecEvent:(const santa::Message&)esMsg
           cachedDecision:(SNTCachedDecision*)existingDecision
               postAction:(bool (^)(SNTAction, SNTCachedDecision*))postAction {
  self.existingDecision = existingDecision;
  dispatch_semaphore_signal(self.sema);
}
@end

// A KVO-compliant stand-in for the configurator's re-check setting.
@interface FakeRecheckConfigurator : NSObject
@property BOOL disableExecutableIntegrityRecheck;
@end

@implementation FakeRecheckConfigurator
@end

@interface SNTEndpointSecurityAuthorizerTest : XCTestCase
@property id mockExecController;
// The re-check setting when the authorizer is created, and the value it changes to after.
@property BOOL disableRecheckAtInit;
@property BOOL disableRecheckAfterInit;
@end

@implementation SNTEndpointSecurityAuthorizerTest

- (void)setUp {
  self.mockExecController = OCMStrictClassMock([SNTExecutionController class]);
}

- (void)tearDown {
  [self.mockExecController stopMocking];
#ifdef DEBUG
  SetBootVolumeGroupDevForTesting(std::nullopt);
  SetBootVolumeGroupDevUnavailableForTesting(false);
#endif
}

- (void)testEnable {
  // Ensure the client subscribes to expected event types. As a tree-aware
  // client, the authorizer additionally subscribes to the process-tree
  // lifecycle events (NOTIFY_FORK, NOTIFY_EXEC, NOTIFY_EXIT) so the tree stays
  // consistent for the lineage of processes it authorizes. NOTIFY_EXEC is
  // required even though the authorizer sees AUTH_EXEC: ES suppresses AUTH_EXEC
  // delivery for binaries whose auth result is cached, so relying on AUTH_EXEC
  // alone would miss cached execs (e.g. a long-lived build server) from the
  // tree. The force-added NOTIFY_EXEC feeds the tree and is filtered out before
  // the authorizer's own message handling.
  std::set<es_event_type_t> expectedEventSubs{
      ES_EVENT_TYPE_AUTH_EXEC, ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME, ES_EVENT_TYPE_NOTIFY_FORK,
      ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_EXIT};
  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsESNewClient();

  // Use the full initializer so the tree-aware base class is properly set up
  // (the inherited 3-arg initializer does not initialize tree-aware state).
  id authClient = [[SNTEndpointSecurityAuthorizer alloc] initWithESAPI:mockESApi
                                                               metrics:nullptr
                                                        execController:nil
                                                    compilerController:nil
                                                       authResultCache:nullptr
                                                             ttyWriter:nullptr
                                                           processTree:nullptr];

  EXPECT_CALL(*mockESApi, ClearCache)
      .After(EXPECT_CALL(*mockESApi, Subscribe(testing::_, expectedEventSubs))
                 .WillOnce(testing::Return(true)))
      .WillOnce(testing::Return(true));

  [authClient enable];

  for (const auto& event : expectedEventSubs) {
    XCTAssertNoThrow(santa::EventTypeToString(event));
  }

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

// As a tree-aware client the authorizer observes NOTIFY_EXIT. It should evict the
// exiting process from the exec controller's sandboxed-seatbelt cache.
- (void)testHandleContextMessageEvictsSandboxedSeatbeltProcOnExit {
  es_file_t file = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&file);
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_EXIT, &proc);

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsESNewClient();
  mockESApi->SetExpectationsRetainReleaseMessage();

  // processTree:nullptr keeps the tree-aware superclass a no-op so only the
  // eviction side effect is exercised.
  SNTEndpointSecurityAuthorizer* authClient =
      [[SNTEndpointSecurityAuthorizer alloc] initWithESAPI:mockESApi
                                                   metrics:nullptr
                                            execController:self.mockExecController
                                        compilerController:nil
                                           authResultCache:nullptr
                                                 ttyWriter:nullptr
                                               processTree:nullptr];

  OCMExpect([self.mockExecController forgetSandboxedSeatbeltProc:proc.audit_token])
      .ignoringNonObjectArgs();

  {
    Message msg(mockESApi, &esMsg);
    [authClient handleContextMessage:msg];
  }

  XCTAssertTrue(OCMVerifyAll(self.mockExecController));
  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

- (void)testHandleMessage {
#ifdef THREAD_SANITIZER
  // TSAN and this test do not get along in multiple ways.
  // We get data race false positives in OCMock, and timeouts
  // waiting for messages processing (presumably due to tsan's scheduling).
  // Just skip it.
  XCTSkip(@"TSAN enabled");
  return;
#endif

  es_file_t file = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&file);
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_EXEC, &proc, ActionType::Auth);

  dispatch_semaphore_t semaMetrics = dispatch_semaphore_create(0);

  // Test unhandled event type
  {
    auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
    mockESApi->SetExpectationsESNewClient();
    mockESApi->SetExpectationsRetainReleaseMessage();

    // There is a benign leak of the mock object in this test.
    // `handleMessage:recordEventMetrics:` will call `processMessage:handler:` in the parent
    // class. This will dispatch to two blocks and create message copies. The block that
    // handles `deadline` timeouts will not complete before the test finishes, and the
    // mock object will think that it has been leaked.
    ::testing::Mock::AllowLeak(mockESApi.get());

    SNTEndpointSecurityAuthorizer* authClient =
        [[SNTEndpointSecurityAuthorizer alloc] initWithESAPI:mockESApi
                                                     metrics:nullptr
                                              execController:self.mockExecController
                                          compilerController:nil
                                             authResultCache:nullptr
                                                   ttyWriter:nullptr
                                                 processTree:nullptr];

    // Temporarily change the event type
    esMsg.event_type = ES_EVENT_TYPE_NOTIFY_EXEC;
    XCTAssertThrows([authClient handleMessage:Message(mockESApi, &esMsg)
                           recordEventMetrics:^(EventDisposition d) {
                             XCTFail("Unhandled event types shouldn't call metrics recorder");
                           }]);
    esMsg.event_type = ES_EVENT_TYPE_AUTH_EXEC;
    XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
  }

  // Test SNTExecutionController determines the event shouldn't be processed
  {
    auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
    mockESApi->SetExpectationsESNewClient();
    mockESApi->SetExpectationsRetainReleaseMessage();
    ::testing::Mock::AllowLeak(mockESApi.get());

    SNTEndpointSecurityAuthorizer* authClient =
        [[SNTEndpointSecurityAuthorizer alloc] initWithESAPI:mockESApi
                                                     metrics:nullptr
                                              execController:self.mockExecController
                                          compilerController:nil
                                             authResultCache:nullptr
                                                   ttyWriter:nullptr
                                                 processTree:nullptr];

    id mockAuthClient = OCMPartialMock(authClient);

    // Scope so msg is destructed (and calls ReleaseMessage) before stopMocking is called.
    {
      Message msg(mockESApi, &esMsg);

      OCMExpect([self.mockExecController synchronousShouldProcessExecEvent:msg])
          .ignoringNonObjectArgs()
          .andReturn(NO);

      OCMExpect([mockAuthClient postAction:SNTActionRespondDeny
                                forMessage:Message(mockESApi, &esMsg)
                              withDecision:nil
                               reservation:0])
          .ignoringNonObjectArgs();
      OCMStub([mockAuthClient postAction:SNTActionRespondDeny
                              forMessage:Message(mockESApi, &esMsg)
                            withDecision:nil
                             reservation:0])
          .ignoringNonObjectArgs()
          .andDo(nil);

      [mockAuthClient handleMessage:std::move(msg)
                 recordEventMetrics:^(EventDisposition d) {
                   XCTAssertEqual(d, EventDisposition::kDropped);
                   dispatch_semaphore_signal(semaMetrics);
                 }];

      XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");
      XCTAssertTrue(OCMVerifyAll(mockAuthClient));
    }

    [mockAuthClient stopMocking];
    XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
  }

  // Test SNTExecutionController determines the event should be processed and
  // processMessage:handler: is called.
  {
    auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
    mockESApi->SetExpectationsESNewClient();
    mockESApi->SetExpectationsRetainReleaseMessage();
    ::testing::Mock::AllowLeak(mockESApi.get());

    SNTEndpointSecurityAuthorizer* authClient =
        [[SNTEndpointSecurityAuthorizer alloc] initWithESAPI:mockESApi
                                                     metrics:nullptr
                                              execController:self.mockExecController
                                          compilerController:nil
                                             authResultCache:nullptr
                                                   ttyWriter:nullptr
                                                 processTree:nullptr];

    id mockAuthClient = OCMPartialMock(authClient);

    {
      OCMExpect(
          [self.mockExecController synchronousShouldProcessExecEvent:Message(mockESApi, &esMsg)])
          .ignoringNonObjectArgs()
          .andReturn(YES);

      OCMExpect([mockAuthClient processMessage:Message(mockESApi, &esMsg) handler:OCMOCK_ANY])
          .ignoringNonObjectArgs()
          .andDo(^(NSInvocation* invocation) {
            dispatch_semaphore_signal(semaMetrics);
          });

      [mockAuthClient handleMessage:Message(mockESApi, &esMsg)
                 recordEventMetrics:^(EventDisposition d){
                     // This block intentionally left blank
                 }];

      XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");
      XCTAssertTrue(OCMVerifyAll(mockAuthClient));
    }

    [mockAuthClient stopMocking];
    XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
  }
}

- (void)testProcessMessageWaitThenAllow {
  // This test ensures that if there is an outstanding action for
  // an item, it will check the cache again until a result exists.
  es_file_t file = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&file);
  es_file_t execFile = MakeESFile("bar");
  es_process_t execProc = MakeESProcess(&execFile, MakeAuditToken(12, 23), MakeAuditToken(34, 45));
  execProc.codesigning_flags = CS_VALID | CS_KILL;
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_EXEC, &proc, ActionType::Auth);
  esMsg.event.exec.target = &execProc;
  esMsg.event.exec.image_cputype = CPU_TYPE_ARM64;
  esMsg.event.exec.image_cpusubtype = CPU_SUBTYPE_ARM64E;

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsESNewClient();
  mockESApi->SetExpectationsRetainReleaseMessage();

  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  FakeExecutionController* fakeExecController = [[FakeExecutionController alloc] initWithSema:sema];

  auto mockAuthCache = std::make_shared<MockAuthResultCache>(nullptr, nil);
  EXPECT_CALL(*mockAuthCache, CheckCache)
      .WillOnce(testing::Return(santa::CachedAuthResult{SNTActionRequestBinary}))
      .WillOnce(testing::Return(santa::CachedAuthResult{SNTActionRequestBinary}))
      .WillOnce(testing::Return(santa::CachedAuthResult{SNTActionRespondAllowCompiler}))
      .WillOnce(testing::Return(santa::CachedAuthResult{}))
      .WillOnce(testing::Return(santa::CachedAuthResult{SNTActionRespondHold}));
  EXPECT_CALL(*mockAuthCache, Reserve).WillOnce(testing::Return(1));

  id mockCompilerController = OCMStrictClassMock([SNTCompilerController class]);
  OCMExpect([mockCompilerController setProcess:execProc.audit_token isCompiler:true]);

  SNTEndpointSecurityAuthorizer* authClient = [[SNTEndpointSecurityAuthorizer alloc]
           initWithESAPI:mockESApi
                 metrics:nullptr
          execController:(SNTExecutionController*)fakeExecController
      compilerController:mockCompilerController
         authResultCache:mockAuthCache
               ttyWriter:santa::TTYWriter::Create(true)
             processTree:nullptr];
  id mockAuthClient = OCMPartialMock(authClient);

  // This block tests that processing is held up until an outstanding thread
  // processing another event completes and returns a result. This test
  // specifically will check the `SNTActionRespondAllowCompiler` flow.
  {
    OCMExpect([mockAuthClient respondToMessage:Message(mockESApi, &esMsg)
                                withAuthResult:ES_AUTH_RESULT_ALLOW
                                     cacheable:true])
        .ignoringNonObjectArgs();

    [mockAuthClient processMessage:Message(mockESApi, &esMsg)];

    XCTAssertTrue(OCMVerifyAll(mockAuthClient));
    XCTAssertTrue(OCMVerifyAll(mockCompilerController));
  }

  // This block tests uncached events storing appropriate cache marker and then
  // running the exec controller to validate the exec event.
  {
    [mockAuthClient processMessage:Message(mockESApi, &esMsg)];

    // Note: This semaphore is triggered when the FakeExecutionController object
    // has its validateExecEvent:postAction: method called.
    XCTAssertSemaTrue(sema, 5, "validateExecEvent not called within expected window");

    XCTAssertTrue(OCMVerifyAll(mockAuthClient));
    XCTAssertTrue(OCMVerifyAll(mockCompilerController));
  }

  // Test that encountering SNTActionRespondHold results in denying the operation.
  {
    OCMExpect([mockAuthClient respondToMessage:Message(mockESApi, &esMsg)
                                withAuthResult:ES_AUTH_RESULT_DENY
                                     cacheable:false])
        .ignoringNonObjectArgs();

    [mockAuthClient processMessage:Message(mockESApi, &esMsg)];

    XCTAssertTrue(OCMVerifyAll(mockAuthClient));
    XCTAssertTrue(OCMVerifyAll(mockCompilerController));
  }

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
  XCTBubbleMockVerifyAndClearExpectations(mockAuthCache.get());

  [mockCompilerController stopMocking];
  [mockAuthClient stopMocking];
}

// Runs postAction: with the cache's AddToCache returning `published`, and reports
// what reached respondToMessage:withAuthResult:forcePreventCache:.
- (void)runPostAction:(SNTAction)action
             published:(bool)published
    compilerController:(id)compilerController
            authResult:(es_auth_result_t*)gotAuthResult
     forcePreventCache:(BOOL*)gotForcePreventCache {
  es_file_t file = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&file);
  es_file_t execFile = MakeESFile("bar");
  es_process_t execProc = MakeESProcess(&execFile, MakeAuditToken(12, 23), MakeAuditToken(34, 45));
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_EXEC, &proc, ActionType::Auth);
  esMsg.event.exec.target = &execProc;

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsESNewClient();
  mockESApi->SetExpectationsRetainReleaseMessage();

  auto mockAuthCache = std::make_shared<MockAuthResultCache>(nullptr, nil);
  EXPECT_CALL(*mockAuthCache, AddToCache(testing::_, action, testing::_, 7))
      .WillOnce(testing::Return(published));

  SNTEndpointSecurityAuthorizer* authClient =
      [[SNTEndpointSecurityAuthorizer alloc] initWithESAPI:mockESApi
                                                   metrics:nullptr
                                            execController:nil
                                        compilerController:compilerController
                                           authResultCache:mockAuthCache
                                                 ttyWriter:santa::TTYWriter::Create(true)
                                               processTree:nil];
  id mockAuthClient = OCMPartialMock(authClient);

  __block es_auth_result_t authResult = (es_auth_result_t)-1;
  __block BOOL forcePreventCache = NO;
  OCMStub([mockAuthClient respondToMessage:Message(mockESApi, &esMsg)
                            withAuthResult:(es_auth_result_t)0
                         forcePreventCache:NO])
      .ignoringNonObjectArgs()
      .andDo(^(NSInvocation* inv) {
        [inv getArgument:&authResult atIndex:3];
        [inv getArgument:&forcePreventCache atIndex:4];
      });

  {
    Message msg(mockESApi, &esMsg);
    [mockAuthClient postAction:action forMessage:msg withDecision:nil reservation:7];
  }

  [mockAuthClient stopMocking];
  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
  XCTBubbleMockVerifyAndClearExpectations(mockAuthCache.get());

  *gotAuthResult = authResult;
  *gotForcePreventCache = forcePreventCache;
}

- (void)testFailedPublishIsNotCached {
  es_auth_result_t result;
  BOOL forcePreventCache;
  [self runPostAction:SNTActionRespondAllow
               published:false
      compilerController:nil
              authResult:&result
       forcePreventCache:&forcePreventCache];
  XCTAssertEqual(result, ES_AUTH_RESULT_ALLOW);
  XCTAssertTrue(forcePreventCache);
}

- (void)testSuccessfulPublishIsCacheable {
  es_auth_result_t result;
  BOOL forcePreventCache;
  [self runPostAction:SNTActionRespondAllow
               published:true
      compilerController:nil
              authResult:&result
       forcePreventCache:&forcePreventCache];
  XCTAssertEqual(result, ES_AUTH_RESULT_ALLOW);
  XCTAssertFalse(forcePreventCache);
}

- (void)testFailedPublishCompilerStillMarksCompiler {
  id mockCompilerController = OCMStrictClassMock([SNTCompilerController class]);
  __block bool markedCompiler = false;
  OCMExpect([mockCompilerController setProcess:MakeAuditToken(12, 23) isCompiler:true])
      .ignoringNonObjectArgs()
      .andDo(^(NSInvocation* inv) {
        [inv getArgument:&markedCompiler atIndex:3];
      });

  es_auth_result_t result;
  BOOL forcePreventCache;
  [self runPostAction:SNTActionRespondAllowCompiler
               published:false
      compilerController:mockCompilerController
              authResult:&result
       forcePreventCache:&forcePreventCache];
  XCTAssertEqual(result, ES_AUTH_RESULT_ALLOW);
  XCTAssertTrue(forcePreventCache);
  XCTAssertTrue(OCMVerifyAll(mockCompilerController));
  XCTAssertTrue(markedCompiler);
  [mockCompilerController stopMocking];
}

- (void)testFailedPublishDenyStillDenies {
  es_auth_result_t result;
  BOOL forcePreventCache;
  [self runPostAction:SNTActionRespondDeny
               published:false
      compilerController:nil
              authResult:&result
       forcePreventCache:&forcePreventCache];
  XCTAssertEqual(result, ES_AUTH_RESULT_DENY);
  XCTAssertTrue(forcePreventCache);
}

- (void)testEarlyDenyPassesNoReservation {
  es_file_t file = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&file);
  es_file_t execFile = MakeESFile("bar");
  es_process_t execProc = MakeESProcess(&execFile, MakeAuditToken(12, 23), MakeAuditToken(34, 45));
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_EXEC, &proc, ActionType::Auth);
  esMsg.event.exec.target = &execProc;

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsESNewClient();
  mockESApi->SetExpectationsRetainReleaseMessage();
  ::testing::Mock::AllowLeak(mockESApi.get());

  auto mockAuthCache = std::make_shared<MockAuthResultCache>(nullptr, nil);
  EXPECT_CALL(*mockAuthCache, AddToCache(testing::_, SNTActionRespondDeny, testing::_, 0))
      .WillOnce(testing::Return(false));
  EXPECT_CALL(*mockAuthCache, Reserve).Times(0);

  SNTEndpointSecurityAuthorizer* authClient =
      [[SNTEndpointSecurityAuthorizer alloc] initWithESAPI:mockESApi
                                                   metrics:nullptr
                                            execController:self.mockExecController
                                        compilerController:nil
                                           authResultCache:mockAuthCache
                                                 ttyWriter:santa::TTYWriter::Create(true)
                                               processTree:nullptr];
  id mockAuthClient = OCMPartialMock(authClient);

  dispatch_semaphore_t semaMetrics = dispatch_semaphore_create(0);
  __block es_auth_result_t authResult = (es_auth_result_t)-1;
  __block BOOL forcePreventCache = NO;
  OCMStub([mockAuthClient respondToMessage:Message(mockESApi, &esMsg)
                            withAuthResult:(es_auth_result_t)0
                         forcePreventCache:NO])
      .ignoringNonObjectArgs()
      .andDo(^(NSInvocation* inv) {
        [inv getArgument:&authResult atIndex:3];
        [inv getArgument:&forcePreventCache atIndex:4];
      });

  {
    Message msg(mockESApi, &esMsg);
    OCMExpect([self.mockExecController synchronousShouldProcessExecEvent:msg])
        .ignoringNonObjectArgs()
        .andReturn(NO);

    [mockAuthClient handleMessage:std::move(msg)
               recordEventMetrics:^(EventDisposition d) {
                 XCTAssertEqual(d, EventDisposition::kDropped);
                 dispatch_semaphore_signal(semaMetrics);
               }];

    XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");
    XCTAssertTrue(OCMVerifyAll(self.mockExecController));
  }

  XCTAssertEqual(authResult, ES_AUTH_RESULT_DENY);
  XCTAssertTrue(forcePreventCache);

  [mockAuthClient stopMocking];
  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
  XCTBubbleMockVerifyAndClearExpectations(mockAuthCache.get());
}

- (void)testPostAction {
  es_file_t file = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&file);
  es_file_t execFile = MakeESFile("bar");
  es_process_t execProc = MakeESProcess(&execFile, MakeAuditToken(12, 23), MakeAuditToken(34, 45));
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_EXEC, &proc, ActionType::Auth);
  esMsg.event.exec.target = &execProc;
  esMsg.event.exec.image_cputype = CPU_TYPE_ARM64;
  esMsg.event.exec.image_cpusubtype = CPU_SUBTYPE_ARM64E;

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsESNewClient();
  mockESApi->SetExpectationsRetainReleaseMessage();

  // The cache is keyed by the executable's vnode plus the slice that was
  // actually selected for execution.
  santa::AuthResultKey expectedKey{SantaVnode::VnodeForFile(&execFile), CPU_TYPE_ARM64,
                                   CPU_SUBTYPE_ARM64E};
  auto hasExpectedKey = testing::Field(&santa::ExecTarget::key, expectedKey);

  // A target that is not system-protected is never ES-cacheable.
  std::vector<bool> systemProtectedPasses = {false};
#ifdef DEBUG
  systemProtectedPasses.push_back(true);
#endif
  const int passes = (int)systemProtectedPasses.size();

  auto mockAuthCache = std::make_shared<MockAuthResultCache>(nullptr, nil);
  EXPECT_CALL(*mockAuthCache,
              AddToCache(hasExpectedKey, SNTActionRespondAllowCompiler, testing::_, testing::_))
      .Times(passes)
      .WillRepeatedly(testing::Return(true));
  EXPECT_CALL(*mockAuthCache,
              AddToCache(hasExpectedKey, SNTActionRespondAllow, testing::_, testing::_))
      .Times(passes)
      .WillRepeatedly(testing::Return(true));
  EXPECT_CALL(*mockAuthCache,
              AddToCache(hasExpectedKey, SNTActionRespondDeny, testing::_, testing::_))
      .Times(passes)
      .WillRepeatedly(testing::Return(true));
  EXPECT_CALL(*mockAuthCache,
              AddToCache(hasExpectedKey, SNTActionRespondDenyOnce, testing::_, testing::_))
      .Times(passes)
      .WillRepeatedly(testing::Return(true));
  EXPECT_CALL(*mockAuthCache,
              AddToCache(hasExpectedKey, SNTActionRespondHold, testing::_, testing::_))
      .Times(passes)
      .WillRepeatedly(testing::Return(true));
  EXPECT_CALL(*mockAuthCache,
              AddToCache(hasExpectedKey, SNTActionRespondAllowNoCache, testing::_, testing::_))
      .Times(passes)
      .WillRepeatedly(testing::Return(true));
  EXPECT_CALL(*mockAuthCache, AddToCache(hasExpectedKey, SNTActionRespondAllowCompilerNoCache,
                                         testing::_, testing::_))
      .Times(passes)
      .WillRepeatedly(testing::Return(true));

  id mockCompilerController = OCMStrictClassMock([SNTCompilerController class]);

  SNTEndpointSecurityAuthorizer* authClient =
      [[SNTEndpointSecurityAuthorizer alloc] initWithESAPI:mockESApi
                                                   metrics:nullptr
                                            execController:nil
                                        compilerController:mockCompilerController
                                           authResultCache:mockAuthCache
                                                 ttyWriter:nullptr
                                               processTree:nullptr];
  id mockAuthClient = OCMPartialMock(authClient);

  {
    Message msg(mockESApi, &esMsg);

    XCTAssertThrows([mockAuthClient postAction:(SNTAction)123
                                    forMessage:msg
                                  withDecision:nil
                                   reservation:0]);

    std::map<SNTAction, es_auth_result_t> actions = {
        {SNTActionRespondAllowCompiler, ES_AUTH_RESULT_ALLOW},
        {SNTActionRespondAllowCompilerNoCache, ES_AUTH_RESULT_ALLOW},
        {SNTActionRespondAllow, ES_AUTH_RESULT_ALLOW},
        {SNTActionRespondDeny, ES_AUTH_RESULT_DENY},
        {SNTActionRespondDenyOnce, ES_AUTH_RESULT_DENY},
        {SNTActionRespondHold, ES_AUTH_RESULT_ALLOW},
        {SNTActionRespondAllowNoCache, ES_AUTH_RESULT_ALLOW},
    };

    __block es_auth_result_t gotAuthResult;
    __block bool gotCachable;
    OCMStub([mockAuthClient respondToMessage:Message(mockESApi, &esMsg)
                              withAuthResult:(es_auth_result_t)0
                                   cacheable:false])
        .ignoringNonObjectArgs()
        .andDo(^(NSInvocation* inv) {
          [inv getArgument:&gotAuthResult atIndex:3];
          [inv getArgument:&gotCachable atIndex:4];
        });

    for (bool systemProtected : systemProtectedPasses) {
#ifdef DEBUG
      if (systemProtected) {
        execFile.stat.st_flags |= SF_RESTRICTED;
        SetBootVolumeGroupDevForTesting(execFile.stat.st_dev);
      }
#endif
      // Both SNTActionRespondAllowCompiler and SNTActionRespondAllowCompilerNoCache
      // mark the just-authorized process as a compiler.
      OCMExpect([mockCompilerController setProcess:execProc.audit_token isCompiler:true]);
      OCMExpect([mockCompilerController setProcess:execProc.audit_token isCompiler:true]);

      for (const auto& kv : actions) {
        [mockAuthClient postAction:kv.first forMessage:msg withDecision:nil reservation:0];

        XCTAssertEqual(gotAuthResult, kv.second);
        XCTAssertEqual(gotCachable, systemProtected && kv.second == ES_AUTH_RESULT_ALLOW &&
                                        (kv.first != SNTActionRespondHold &&
                                         kv.first != SNTActionRespondAllowCompiler &&
                                         kv.first != SNTActionRespondAllowNoCache &&
                                         kv.first != SNTActionRespondAllowCompilerNoCache));
      }

      XCTAssertTrue(OCMVerifyAll(mockCompilerController));
    }
  }

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
  XCTBubbleMockVerifyAndClearExpectations(mockAuthCache.get());

  [mockCompilerController stopMocking];
  [mockAuthClient stopMocking];
}

- (void)testUnprotectedCacheHitIsNotKernelCached {
  es_file_t file = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&file);
  es_file_t execFile = MakeESFile("bar");
  es_process_t execProc = MakeESProcess(&execFile, MakeAuditToken(12, 23), MakeAuditToken(34, 45));
  execProc.codesigning_flags = CS_VALID | CS_KILL;
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_EXEC, &proc, ActionType::Auth);
  esMsg.event.exec.target = &execProc;

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsESNewClient();
  mockESApi->SetExpectationsRetainReleaseMessage();
  EXPECT_CALL(*mockESApi, RespondAuthResult(testing::_, testing::_, ES_AUTH_RESULT_ALLOW, false))
      .WillOnce(testing::Return(true));

  auto mockAuthCache = std::make_shared<MockAuthResultCache>(nullptr, nil);
  EXPECT_CALL(*mockAuthCache, CheckCache)
      .WillOnce(testing::Return(santa::CachedAuthResult{SNTActionRespondAllow}));
  EXPECT_CALL(*mockAuthCache, Reserve).Times(0);

  SNTEndpointSecurityAuthorizer* authClient =
      [[SNTEndpointSecurityAuthorizer alloc] initWithESAPI:mockESApi
                                                   metrics:nullptr
                                            execController:nil
                                        compilerController:nil
                                           authResultCache:mockAuthCache
                                                 ttyWriter:nullptr
                                               processTree:nullptr];

  [authClient processMessage:Message(mockESApi, &esMsg)];

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
  XCTBubbleMockVerifyAndClearExpectations(mockAuthCache.get());
}

- (void)runProcessMessageWithChecks:(std::vector<santa::CachedAuthResult>)checks
                           reserves:(std::vector<uint64_t>)reserves
                         authResult:(es_auth_result_t*)gotAuthResult
                          cacheable:(BOOL*)gotCacheable
                        evaluations:(int*)evaluations
                    reserveExpected:(std::vector<santa::CachedAuthResult>*)reserveExpected {
  [self runProcessMessageWithChecks:checks
                           reserves:reserves
                   codesigningFlags:CS_VALID | CS_KILL
                      recheckSHA256:nil
                      rejectRecheck:YES
                 compilerController:nil
                         authResult:gotAuthResult
                          cacheable:gotCacheable
                        evaluations:evaluations
                    reserveExpected:reserveExpected
                   existingDecision:nil];
}

// Runs processMessage: against a cache that returns `checks` in order and a Reserve that
// returns `reserves` in order, for a target with `codesigningFlags`. The content re-check
// returns `recheckSHA256`, or must not run if `rejectRecheck`. Reports the last response,
// the `cacheable:` argument of a direct response (YES if none), how often evaluation ran,
// the `expected` argument of each Reserve call, and the decision handed to the last
// evaluation.
- (void)runProcessMessageWithChecks:(std::vector<santa::CachedAuthResult>)checks
                           reserves:(std::vector<uint64_t>)reserves
                   codesigningFlags:(uint32_t)codesigningFlags
                      recheckSHA256:(NSString*)recheckSHA256
                      rejectRecheck:(BOOL)rejectRecheck
                 compilerController:(id)compilerController
                         authResult:(es_auth_result_t*)gotAuthResult
                          cacheable:(BOOL*)gotCacheable
                        evaluations:(int*)evaluations
                    reserveExpected:(std::vector<santa::CachedAuthResult>*)reserveExpected
                   existingDecision:(SNTCachedDecision**)gotExistingDecision {
  es_file_t file = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&file);
  es_file_t execFile = MakeESFile("bar");
  es_process_t execProc = MakeESProcess(&execFile, MakeAuditToken(12, 23), MakeAuditToken(34, 45));
  execProc.codesigning_flags = codesigningFlags;
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_EXEC, &proc, ActionType::Auth);
  esMsg.event.exec.target = &execProc;
  esMsg.event.exec.image_cputype = CPU_TYPE_ARM64;
  esMsg.event.exec.image_cpusubtype = CPU_SUBTYPE_ARM64E;

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsESNewClient();
  mockESApi->SetExpectationsRetainReleaseMessage();

  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  FakeExecutionController* fakeExecController = [[FakeExecutionController alloc] initWithSema:sema];

  auto mockAuthCache = std::make_shared<MockAuthResultCache>(nullptr, nil);
  auto& checkExpectation = EXPECT_CALL(*mockAuthCache, CheckCache).Times((int)checks.size());
  for (const auto& check : checks) {
    checkExpectation.WillOnce(testing::Return(check));
  }
  auto& reserveExpectation = EXPECT_CALL(*mockAuthCache, Reserve).Times((int)reserves.size());
  for (uint64_t reserve : reserves) {
    reserveExpectation.WillOnce(
        [reserveExpected, reserve](const santa::ExecTarget&, const santa::CachedAuthResult& e) {
          reserveExpected->push_back(e);
          return reserve;
        });
  }

  // The host's own configuration must not decide whether content is re-checked.
  FakeRecheckConfigurator* fakeConfigurator = [[FakeRecheckConfigurator alloc] init];
  fakeConfigurator.disableExecutableIntegrityRecheck = self.disableRecheckAtInit;
  id mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([mockConfigurator configurator]).andReturn(fakeConfigurator);

  SNTEndpointSecurityAuthorizer* authClient = [[SNTEndpointSecurityAuthorizer alloc]
           initWithESAPI:mockESApi
                 metrics:nullptr
          execController:(SNTExecutionController*)fakeExecController
      compilerController:compilerController
         authResultCache:mockAuthCache
               ttyWriter:santa::TTYWriter::Create(true)
             processTree:nullptr];
  id mockAuthClient = OCMPartialMock(authClient);

  if (self.disableRecheckAfterInit) fakeConfigurator.disableExecutableIntegrityRecheck = YES;

  es_file_t dummyFile{};
  __block const es_file_t* recheckedFile = nullptr;
  if (rejectRecheck) {
    OCMReject([mockAuthClient verifiedSHA256ForExecutable:&dummyFile]).ignoringNonObjectArgs();
  } else {
    OCMStub([mockAuthClient verifiedSHA256ForExecutable:&dummyFile])
        .ignoringNonObjectArgs()
        .andDo(^(NSInvocation* inv) {
          [inv getArgument:&recheckedFile atIndex:2];
        })
        .andReturn(recheckSHA256);
  }

  __block es_auth_result_t authResult = (es_auth_result_t)-1;
  __block BOOL cacheable = YES;
  OCMStub([mockAuthClient respondToMessage:Message(mockESApi, &esMsg)
                            withAuthResult:(es_auth_result_t)0
                         forcePreventCache:NO])
      .ignoringNonObjectArgs()
      .andDo(^(NSInvocation* inv) {
        [inv getArgument:&authResult atIndex:3];
      });
  OCMStub([mockAuthClient respondToMessage:Message(mockESApi, &esMsg)
                            withAuthResult:(es_auth_result_t)0
                                 cacheable:NO])
      .ignoringNonObjectArgs()
      .andDo(^(NSInvocation* inv) {
        [inv getArgument:&authResult atIndex:3];
        [inv getArgument:&cacheable atIndex:4];
      });

  [mockAuthClient processMessage:Message(mockESApi, &esMsg)];

  int evaluated = 0;
  while (dispatch_semaphore_wait(sema, DISPATCH_TIME_NOW) == 0)
    evaluated++;
  *evaluations = evaluated;
  *gotAuthResult = authResult;
  *gotCacheable = cacheable;
  if (gotExistingDecision) *gotExistingDecision = fakeExecController.existingDecision;
  // The target's executable is re-checked, not the instigator's.
  if (!rejectRecheck) XCTAssertEqual(recheckedFile, &execFile);

  XCTAssertTrue(OCMVerifyAll(mockAuthClient));
  [mockAuthClient stopMocking];
  [mockConfigurator stopMocking];
  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
  XCTBubbleMockVerifyAndClearExpectations(mockAuthCache.get());
}

- (void)testLostReservationJoinsInFlightEvaluation {
  es_auth_result_t result = (es_auth_result_t)-1;
  BOOL cacheable = YES;
  int evaluations = -1;
  std::vector<santa::CachedAuthResult> expected;
  [self runProcessMessageWithChecks:{santa::CachedAuthResult{},
                                     santa::CachedAuthResult{SNTActionRequestBinary},
                                     santa::CachedAuthResult{SNTActionRespondAllow}}
                           reserves:{0}
                         authResult:&result
                          cacheable:&cacheable
                        evaluations:&evaluations
                    reserveExpected:&expected];
  XCTAssertEqual(result, ES_AUTH_RESULT_ALLOW);
  XCTAssertEqual(evaluations, 0);
  XCTAssertEqual(expected.size(), 1);
  XCTAssertTrue(expected[0] == santa::CachedAuthResult{});
}

- (void)testLostReservationThenHoldIsDenied {
  es_auth_result_t result = (es_auth_result_t)-1;
  BOOL cacheable = YES;
  int evaluations = -1;
  std::vector<santa::CachedAuthResult> expected;
  [self runProcessMessageWithChecks:{santa::CachedAuthResult{},
                                     santa::CachedAuthResult{SNTActionRespondHold}}
                           reserves:{0}
                         authResult:&result
                          cacheable:&cacheable
                        evaluations:&evaluations
                    reserveExpected:&expected];
  XCTAssertEqual(result, ES_AUTH_RESULT_DENY);
  XCTAssertFalse(cacheable);
  XCTAssertEqual(evaluations, 0);
}

- (void)testLostReservationThenEmptySlotEvaluates {
  es_auth_result_t result = (es_auth_result_t)-1;
  BOOL cacheable = YES;
  int evaluations = -1;
  std::vector<santa::CachedAuthResult> expected;
  [self runProcessMessageWithChecks:{santa::CachedAuthResult{}, santa::CachedAuthResult{}}
                           reserves:{0, 7}
                         authResult:&result
                          cacheable:&cacheable
                        evaluations:&evaluations
                    reserveExpected:&expected];
  XCTAssertEqual(evaluations, 1);
}

- (void)testLostReservationAfterNoCacheEntryJoins {
  es_auth_result_t result = (es_auth_result_t)-1;
  BOOL cacheable = YES;
  int evaluations = -1;
  std::vector<santa::CachedAuthResult> expected;
  [self runProcessMessageWithChecks:{santa::CachedAuthResult{SNTActionRespondAllowNoCache, 42},
                                     santa::CachedAuthResult{SNTActionRequestBinary},
                                     santa::CachedAuthResult{SNTActionRespondAllow}}
                           reserves:{0}
                         authResult:&result
                          cacheable:&cacheable
                        evaluations:&evaluations
                    reserveExpected:&expected];
  XCTAssertEqual(result, ES_AUTH_RESULT_ALLOW);
  XCTAssertEqual(evaluations, 0);
  XCTAssertEqual(expected.size(), 1);
  XCTAssertTrue((expected[0] == santa::CachedAuthResult{SNTActionRespondAllowNoCache, 42}));
}

// Runs a single cached `entry` for an unenforced, unprotected target whose content
// re-check returns `recheckSHA256`, and asserts the hit was re-evaluated: Reserve ran
// over exactly `entry` and the hit sent no response.
- (void)runUnenforcedHit:(santa::CachedAuthResult)entry
           recheckSHA256:(NSString*)recheckSHA256
      compilerController:(id)compilerController {
  es_auth_result_t result = (es_auth_result_t)-1;
  BOOL cacheable = YES;
  int evaluations = -1;
  std::vector<santa::CachedAuthResult> expected;
  [self runProcessMessageWithChecks:{entry}
                           reserves:{1}
                   codesigningFlags:0
                      recheckSHA256:recheckSHA256
                      rejectRecheck:NO
                 compilerController:compilerController
                         authResult:&result
                          cacheable:&cacheable
                        evaluations:&evaluations
                    reserveExpected:&expected
                   existingDecision:nil];
  XCTAssertEqual(evaluations, 1);
  XCTAssertEqual(result, (es_auth_result_t)-1);
  XCTAssertEqual(expected.size(), 1);
  if (expected.size() != 1) return;
  XCTAssertEqual(expected[0].action, entry.action);
  XCTAssertEqual(expected[0].timestamp, entry.timestamp);
}

- (void)testUnenforcedHitServedWhenContentUnchanged {
  es_auth_result_t result = (es_auth_result_t)-1;
  BOOL cacheable = YES;
  int evaluations = -1;
  std::vector<santa::CachedAuthResult> expected;
  [self runProcessMessageWithChecks:{santa::CachedAuthResult{
                                        SNTActionRespondAllow, 1, nil, {}, @"aa"}}
                           reserves:{}
                   codesigningFlags:0
                      recheckSHA256:@"aa"
                      rejectRecheck:NO
                 compilerController:nil
                         authResult:&result
                          cacheable:&cacheable
                        evaluations:&evaluations
                    reserveExpected:&expected
                   existingDecision:nil];
  XCTAssertEqual(result, ES_AUTH_RESULT_ALLOW);
  XCTAssertEqual(evaluations, 0);
}

- (void)testUnenforcedHitReevaluatedWhenContentChanged {
  [self runUnenforcedHit:santa::CachedAuthResult{SNTActionRespondAllow, 1, nil, {}, @"aa"}
           recheckSHA256:@"bb"
      compilerController:nil];
}

- (void)testUnenforcedHitWithoutStoredHashIsReevaluated {
  [self runUnenforcedHit:santa::CachedAuthResult{SNTActionRespondAllow, 1}
           recheckSHA256:@"aa"
      compilerController:nil];
}

- (void)testUnenforcedHitUnreadableIsReevaluated {
  [self runUnenforcedHit:santa::CachedAuthResult{SNTActionRespondAllow, 1, nil, {}, @"aa"}
           recheckSHA256:nil
      compilerController:nil];
}

- (void)testUnenforcedCompilerHitRecheckedBeforeCompilerMark {
  id mockCompilerController = OCMStrictClassMock([SNTCompilerController class]);
  OCMReject([mockCompilerController setProcess:MakeAuditToken(12, 23) isCompiler:true])
      .ignoringNonObjectArgs();

  [self runUnenforcedHit:santa::CachedAuthResult{SNTActionRespondAllowCompiler, 1, nil, {}, @"aa"}
           recheckSHA256:@"bb"
      compilerController:mockCompilerController];

  XCTAssertTrue(OCMVerifyAll(mockCompilerController));
  [mockCompilerController stopMocking];
}

// Runs a single cached `entry` whose hit must be served without re-checking content.
- (es_auth_result_t)runServedHit:(santa::CachedAuthResult)entry
                codesigningFlags:(uint32_t)codesigningFlags {
  es_auth_result_t result = (es_auth_result_t)-1;
  BOOL cacheable = YES;
  int evaluations = -1;
  std::vector<santa::CachedAuthResult> expected;
  [self runProcessMessageWithChecks:{entry}
                           reserves:{}
                   codesigningFlags:codesigningFlags
                      recheckSHA256:nil
                      rejectRecheck:YES
                 compilerController:nil
                         authResult:&result
                          cacheable:&cacheable
                        evaluations:&evaluations
                    reserveExpected:&expected
                   existingDecision:nil];
  XCTAssertEqual(evaluations, 0);
  return result;
}

- (void)testEnforcedHitIsNotRechecked {
  es_auth_result_t result =
      [self runServedHit:santa::CachedAuthResult{SNTActionRespondAllow, 1, nil, {}, @"aa"}
          codesigningFlags:CS_VALID | CS_KILL];
  XCTAssertEqual(result, ES_AUTH_RESULT_ALLOW);
}

- (void)testCachedDenyIsNotRechecked {
  es_auth_result_t result = [self runServedHit:santa::CachedAuthResult{SNTActionRespondDeny, 1}
                              codesigningFlags:0];
  XCTAssertEqual(result, ES_AUTH_RESULT_DENY);
}

- (void)testRecheckDisabledByConfig {
  self.disableRecheckAtInit = YES;

  es_auth_result_t result =
      [self runServedHit:santa::CachedAuthResult{SNTActionRespondAllow, 1, nil, {}, @"aa"}
          codesigningFlags:0];
  XCTAssertEqual(result, ES_AUTH_RESULT_ALLOW);
}

- (void)testRecheckDisabledByConfigChange {
  self.disableRecheckAfterInit = YES;

  es_auth_result_t result =
      [self runServedHit:santa::CachedAuthResult{SNTActionRespondAllow, 1, nil, {}, @"aa"}
          codesigningFlags:0];
  XCTAssertEqual(result, ES_AUTH_RESULT_ALLOW);
}

- (void)testUnenforcedAllowNoCacheDropsCachedDecision {
  es_auth_result_t result = (es_auth_result_t)-1;
  BOOL cacheable = YES;
  int evaluations = -1;
  std::vector<santa::CachedAuthResult> expected;
  SNTCachedDecision* existingDecision = [[SNTCachedDecision alloc] init];
  [self runProcessMessageWithChecks:{santa::CachedAuthResult{SNTActionRespondAllowNoCache, 42,
                                                             [[SNTCachedDecision alloc] init]}}
                           reserves:{1}
                   codesigningFlags:0
                      recheckSHA256:nil
                      rejectRecheck:YES
                 compilerController:nil
                         authResult:&result
                          cacheable:&cacheable
                        evaluations:&evaluations
                    reserveExpected:&expected
                   existingDecision:&existingDecision];
  XCTAssertEqual(evaluations, 1);
  XCTAssertNil(existingDecision);
  XCTAssertEqual(expected.size(), 1);
  XCTAssertTrue((expected[0] == santa::CachedAuthResult{SNTActionRespondAllowNoCache, 42}));
}

- (void)testLostReservationDropsDecisionFromEarlierPass {
  es_auth_result_t result = (es_auth_result_t)-1;
  BOOL cacheable = YES;
  int evaluations = -1;
  std::vector<santa::CachedAuthResult> expected;
  SNTCachedDecision* existingDecision = [[SNTCachedDecision alloc] init];
  [self runProcessMessageWithChecks:{santa::CachedAuthResult{SNTActionRespondAllowNoCache, 42,
                                                             [[SNTCachedDecision alloc] init]},
                                     santa::CachedAuthResult{}}
                           reserves:{0, 1}
                   codesigningFlags:CS_VALID | CS_KILL
                      recheckSHA256:nil
                      rejectRecheck:YES
                 compilerController:nil
                         authResult:&result
                          cacheable:&cacheable
                        evaluations:&evaluations
                    reserveExpected:&expected
                   existingDecision:&existingDecision];
  XCTAssertEqual(evaluations, 1);
  XCTAssertNil(existingDecision);
}

@end
