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

#ifndef SANTA__SANTAD__EVENTPROVIDERS_FAAWEBHOOKCLIENT_H
#define SANTA__SANTAD__EVENTPROVIDERS_FAAWEBHOOKCLIENT_H

#import <Foundation/Foundation.h>

#include <memory>
#include <string>

#import "Source/common/SNTStoredFileAccessEvent.h"
#include "Source/common/faa/WatchItemPolicy.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"

namespace santa {

class FAAWebhookClient {
 public:
  FAAWebhookClient();
  ~FAAWebhookClient();

  // Trigger a webhook request for a rule match
  // This is non-blocking and will dispatch the request asynchronously
  void TriggerWebhookForRuleMatch(const WatchItemPolicyBase &policy,
                                  const std::string &target_path,
                                  const Message &msg);

 private:
  dispatch_queue_t queue_;
  NSURLSession *url_session_;
};

}  // namespace santa

#endif  // SANTA__SANTAD__EVENTPROVIDERS_FAAWEBHOOKCLIENT_H

