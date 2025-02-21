/// Copyright 2022 Google LLC
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

#include <EndpointSecurity/EndpointSecurity.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <sys/fcntl.h>
#include <sys/types.h>
#include <cstring>
#include <utility>

#include <array>
#include <cstddef>
#include <map>
#include <memory>
#include <optional>
#include <variant>

#import "Source/common/MOLCertificate.h"
#import "Source/common/MOLCodesignChecker.h"
#include "Source/common/Platform.h"
#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#include "Source/common/TestUtils.h"
#include "Source/santad/DataLayer/WatchItemPolicy.h"
#include "Source/santad/DataLayer/WatchItems.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/EventProviders/EndpointSecurity/MockEndpointSecurityAPI.h"
#include "Source/santad/EventProviders/FAAPolicyProcessor.h"
#include "Source/santad/EventProviders/MockFAAPolicyProcessor.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityFileAccessAuthorizer.h"
#include "Source/santad/Logs/EndpointSecurity/MockLogger.h"
#include "Source/santad/SNTDecisionCache.h"

using santa::DataWatchItemPolicy;
using santa::Message;
using santa::MockFAAPolicyProcessor;
using santa::WatchItemProcess;

// Duplicate definition for test implementation
struct PathTarget {
  std::string path;
  bool isReadable;
  std::optional<std::pair<dev_t, ino_t>> devnoIno;
};

using PathTargetsPair = std::pair<std::optional<std::string>, std::optional<std::string>>;

void SetExpectationsForFileAccessAuthorizerInit(
    std::shared_ptr<MockEndpointSecurityAPI> mockESApi) {
  EXPECT_CALL(*mockESApi, InvertTargetPathMuting).WillOnce(testing::Return(true));
  EXPECT_CALL(*mockESApi, UnmuteAllTargetPaths).WillOnce(testing::Return(true));
}

@interface SNTEndpointSecurityFileAccessAuthorizer (Testing)
- (FileAccessPolicyDecision)specialCaseForPolicy:(std::shared_ptr<DataWatchItemPolicy>)policy
                                          target:(const PathTarget &)target
                                         message:(const Message &)msg;
- (FileAccessPolicyDecision)applyPolicy:
                                (std::optional<std::shared_ptr<DataWatchItemPolicy>>)optionalPolicy
                              forTarget:(const PathTarget &)target
                              toMessage:(const Message &)msg;
- (void)disable;

@property bool isSubscribed;
@end

@interface SNTEndpointSecurityFileAccessAuthorizerTest : XCTestCase
@property id mockConfigurator;
@property id cscMock;
@property id dcMock;
@end

@implementation SNTEndpointSecurityFileAccessAuthorizerTest

- (void)setUp {
  [super setUp];

  self.mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([self.mockConfigurator configurator]).andReturn(self.mockConfigurator);

  self.cscMock = OCMClassMock([MOLCodesignChecker class]);
  OCMStub([self.cscMock alloc]).andReturn(self.cscMock);

  self.dcMock = OCMStrictClassMock([SNTDecisionCache class]);
}

- (void)tearDown {
  [self.cscMock stopMocking];
  [self.dcMock stopMocking];

  [super tearDown];
}

- (void)testEnable {
  std::set<es_event_type_t> expectedEventSubs = {
      ES_EVENT_TYPE_AUTH_CLONE,        ES_EVENT_TYPE_AUTH_COPYFILE, ES_EVENT_TYPE_AUTH_CREATE,
      ES_EVENT_TYPE_AUTH_EXCHANGEDATA, ES_EVENT_TYPE_AUTH_LINK,     ES_EVENT_TYPE_AUTH_OPEN,
      ES_EVENT_TYPE_AUTH_RENAME,       ES_EVENT_TYPE_AUTH_TRUNCATE, ES_EVENT_TYPE_AUTH_UNLINK,
      ES_EVENT_TYPE_NOTIFY_EXIT,
  };

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  EXPECT_CALL(*mockESApi, ClearCache)
      .After(EXPECT_CALL(*mockESApi, Subscribe(testing::_, expectedEventSubs))
                 .WillOnce(testing::Return(true)))
      .WillOnce(testing::Return(true));

  id fileAccessClient = [[SNTEndpointSecurityFileAccessAuthorizer alloc]
      initWithESAPI:mockESApi
            metrics:nullptr
          processor:santa::Processor::kFileAccessAuthorizer];

  [fileAccessClient enable];

  for (const auto &event : expectedEventSubs) {
    XCTAssertNoThrow(santa::EventTypeToString(event));
  }

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

- (void)testDisable {
  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsESNewClient();
  SetExpectationsForFileAccessAuthorizerInit(mockESApi);

  SNTEndpointSecurityFileAccessAuthorizer *accessClient =
      [[SNTEndpointSecurityFileAccessAuthorizer alloc] initWithESAPI:mockESApi
                                                             metrics:nullptr
                                                              logger:nullptr
                                                          watchItems:nullptr
                                                            enricher:nullptr
                                                  faaPolicyProcessor:nil
                                                           ttyWriter:nullptr];

  EXPECT_CALL(*mockESApi, UnsubscribeAll);
  EXPECT_CALL(*mockESApi, UnmuteAllTargetPaths).WillOnce(testing::Return(true));

  accessClient.isSubscribed = true;
  [accessClient disable];

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

@end
