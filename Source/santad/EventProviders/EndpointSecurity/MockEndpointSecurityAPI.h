/// Copyright 2021 Google Inc. All rights reserved.
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

#ifndef SANTA__SANTAD__EVENTPROVIDERS_ENDPOINTSECURITY_MOCKENDPOINTSECURITYAPI_H
#define SANTA__SANTAD__EVENTPROVIDERS_ENDPOINTSECURITY_MOCKENDPOINTSECURITYAPI_H

#include <EndpointSecurity/EndpointSecurity.h>
#import <Foundation/Foundation.h>
#include <dispatch/dispatch.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <set>

#include "Source/santad/DataLayer/WatchItemPolicy.h"
#include "Source/santad/EventProviders/EndpointSecurity/Client.h"
#include "Source/santad/EventProviders/EndpointSecurity/EndpointSecurityAPI.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"

using santa::Client;

class MockEndpointSecurityAPI : public santa::EndpointSecurityAPI {
 public:
  MOCK_METHOD(santa::Client, NewClient, (void (^message_handler)(es_client_t *, santa::Message)));

  MOCK_METHOD(bool, Subscribe, (const santa::Client &, const std::set<es_event_type_t> &));
  MOCK_METHOD(bool, UnsubscribeAll, (const Client &client));

  MOCK_METHOD(bool, UnmuteAllPaths, (const Client &client));
  MOCK_METHOD(bool, UnmuteAllTargetPaths, (const Client &client));

  MOCK_METHOD(bool, IsTargetPathMutingInverted, (const Client &client));
  MOCK_METHOD(bool, InvertTargetPathMuting, (const Client &client));

  MOCK_METHOD(bool, IsProcessMutingInverted, (const Client &client));
  MOCK_METHOD(bool, InvertProcessMuting, (const Client &client));

  MOCK_METHOD(bool, MuteTargetPath,
              (const Client &client, std::string_view path, santa::WatchItemPathType path_type));
  MOCK_METHOD(bool, UnmuteTargetPath,
              (const Client &client, std::string_view path, santa::WatchItemPathType path_type));

  MOCK_METHOD(void, RetainMessage, (const es_message_t *msg));
  MOCK_METHOD(void, ReleaseMessage, (const es_message_t *msg));

  MOCK_METHOD(bool, RespondAuthResult,
              (const santa::Client &, const santa::Message &msg, es_auth_result_t result,
               bool cache));
  MOCK_METHOD(bool, RespondFlagsResult,
              (const santa::Client &client, const santa::Message &msg, uint32_t allowed_flags,
               bool cache));

  MOCK_METHOD(bool, MuteProcess, (const santa::Client &, const audit_token_t *tok));

  MOCK_METHOD(bool, ClearCache, (const santa::Client &));

  MOCK_METHOD(uint32_t, ExecArgCount, (const es_event_exec_t *event));
  MOCK_METHOD(es_string_token_t, ExecArg, (const es_event_exec_t *event, uint32_t index));

  MOCK_METHOD(uint32_t, ExecEnvCount, (const es_event_exec_t *event));
  MOCK_METHOD(es_string_token_t, ExecEnv, (const es_event_exec_t *event, uint32_t index));

  MOCK_METHOD(uint32_t, ExecFDCount, (const es_event_exec_t *event));
  MOCK_METHOD(const es_fd_t *, ExecFD, (const es_event_exec_t *event, uint32_t index));

  void SetExpectationsESNewClient() {
    EXPECT_CALL(*this, NewClient)
        .WillOnce(testing::Return(santa::Client(nullptr, ES_NEW_CLIENT_RESULT_SUCCESS)));
    EXPECT_CALL(*this, MuteProcess).WillOnce(testing::Return(true));
    EXPECT_CALL(*this, ClearCache).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(*this, Subscribe).WillRepeatedly(testing::Return(true));
  }

  void SetExpectationsRetainReleaseMessage() {
    EXPECT_CALL(*this, ReleaseMessage).Times(testing::AnyNumber());
    EXPECT_CALL(*this, RetainMessage).Times(testing::AnyNumber());
  }

  /// This method should be used for tests that must wait for retain counts to drop
  /// to 0 (e.g. due to async processing) in order to ensure tests don't exit early.
  void SetExpectationsRetainCountTracking(dispatch_semaphore_t sema) {
    __block int retainCount = 0;
    EXPECT_CALL(*this, ReleaseMessage).WillRepeatedly(^{
      if (retainCount == 0) {
        [NSException raise:@"Over Release" format:@"The ES message has been over-released."];
      }
      retainCount--;
      if (retainCount == 0) {
        dispatch_semaphore_signal(sema);
      }
    });
    EXPECT_CALL(*this, RetainMessage).WillRepeatedly(^{
      retainCount++;
    });
  }
};

#endif
