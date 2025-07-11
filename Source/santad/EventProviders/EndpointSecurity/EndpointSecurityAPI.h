/// Copyright 2022 Google Inc. All rights reserved.
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

#ifndef SANTA__SANTAD__EVENTPROVIDERS_ENDPOINTSECURITY_ENDPOINTSECURITYAPI_H
#define SANTA__SANTAD__EVENTPROVIDERS_ENDPOINTSECURITY_ENDPOINTSECURITYAPI_H

#include <EndpointSecurity/EndpointSecurity.h>
#import <Foundation/Foundation.h>

#include <set>
#include <string_view>

#include "Source/santad/DataLayer/WatchItemPolicy.h"
#include "Source/santad/EventProviders/EndpointSecurity/Client.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"

namespace santa {

class EndpointSecurityAPI : public std::enable_shared_from_this<EndpointSecurityAPI> {
 public:
  virtual ~EndpointSecurityAPI() = default;

  virtual Client NewClient(void (^message_handler)(es_client_t *, Message));

  virtual bool Subscribe(const Client &client, const std::set<es_event_type_t> &);
  virtual bool UnsubscribeAll(const Client &client);

  virtual bool UnmuteAllPaths(const Client &client);
  virtual bool UnmuteAllTargetPaths(const Client &client);

  virtual bool IsTargetPathMutingInverted(const Client &client);
  virtual bool InvertTargetPathMuting(const Client &client);

  virtual bool MuteTargetPath(const Client &client, std::string_view path,
                              santa::WatchItemPathType path_type);
  virtual bool UnmuteTargetPath(const Client &client, std::string_view path,
                                santa::WatchItemPathType path_type);

  virtual bool IsProcessMutingInverted(const Client &client);
  virtual bool InvertProcessMuting(const Client &client);
  virtual bool MuteProcess(const Client &client, const audit_token_t *tok);
  virtual bool UnmuteProcess(const Client &client, const audit_token_t *tok);

  virtual void RetainMessage(const es_message_t *msg);
  virtual void ReleaseMessage(const es_message_t *msg);

  virtual bool RespondAuthResult(const Client &client, const Message &msg, es_auth_result_t result,
                                 bool cache);
  virtual bool RespondFlagsResult(const Client &client, const Message &msg, uint32_t allowed_flags,
                                  bool cache);

  virtual bool ClearCache(const Client &client);

  virtual uint32_t ExecArgCount(const es_event_exec_t *event);
  virtual es_string_token_t ExecArg(const es_event_exec_t *event, uint32_t index);
  virtual std::vector<std::string> ExecArgs(const es_event_exec_t *event);

  virtual uint32_t ExecEnvCount(const es_event_exec_t *event);
  virtual es_string_token_t ExecEnv(const es_event_exec_t *event, uint32_t index);
  virtual std::map<std::string, std::string> ExecEnvs(const es_event_exec_t *event);

  virtual uint32_t ExecFDCount(const es_event_exec_t *event);
  virtual const es_fd_t *ExecFD(const es_event_exec_t *event, uint32_t index);
};

}  // namespace santa

#endif
