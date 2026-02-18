/// Copyright 2023 Google LLC
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
#include "Source/santad/ProcessTree/SNTEndpointSecurityAdapter.h"

#include <EndpointSecurity/EndpointSecurity.h>
#import <Foundation/Foundation.h>
#include <Kernel/kern/cs_blobs.h>
#include <bsm/libbsm.h>

#include "Source/common/String.h"
#include "Source/santad/EventProviders/EndpointSecurity/EndpointSecurityAPI.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/ProcessTree/process_tree.h"
#include "Source/santad/ProcessTree/process_tree_macos.h"
#include "absl/status/statusor.h"

using santa::EndpointSecurityAPI;
using santa::Message;

namespace santa::santad::process_tree {

void InformFromESEvent(ProcessTree &tree, const Message &msg) {
  struct Pid event_pid = PidFromAuditToken(msg->process->audit_token);
  auto proc = tree.Get(event_pid);

  if (!proc) {
    return;
  }

  std::shared_ptr<EndpointSecurityAPI> esapi = msg.ESAPI();

  switch (msg->event_type) {
    case ES_EVENT_TYPE_AUTH_EXEC:
    case ES_EVENT_TYPE_NOTIFY_EXEC: {
      std::vector<std::string> args;
      args.reserve(esapi->ExecArgCount(&msg->event.exec));
      for (int i = 0; i < esapi->ExecArgCount(&msg->event.exec); i++) {
        es_string_token_t arg = esapi->ExecArg(&msg->event.exec, i);
        args.push_back(StringTokenToString(arg));
      }

      const es_process_t *target = msg->event.exec.target;
      es_string_token_t executable = target->executable->path;

      // Extract code signing info from the target process
      CodeSigningInfo cs_info{
          .cdhash = santa::BufToHexString(target->cdhash, sizeof(target->cdhash)),
          .is_platform_binary = target->is_platform_binary,
      };

      // Only add TeamID and SigningID if production-signed.
      if ((target->codesigning_flags & CS_ADHOC) == 0) {
        cs_info.team_id = StringTokenToString(target->team_id);
        cs_info.signing_id = StringTokenToString(target->signing_id);
      }

      tree.HandleExec(msg->mach_time, **proc, PidFromAuditToken(target->audit_token),
                      (struct Program){.executable = StringTokenToString(executable),
                                       .arguments = args,
                                       .code_signing = cs_info},
                      (struct Cred){
                          .uid = audit_token_to_euid(target->audit_token),
                          .gid = audit_token_to_egid(target->audit_token),
                      });

      break;
    }
    case ES_EVENT_TYPE_NOTIFY_FORK: {
      tree.HandleFork(msg->mach_time, **proc,
                      PidFromAuditToken(msg->event.fork.child->audit_token));
      break;
    }
    case ES_EVENT_TYPE_NOTIFY_EXIT: tree.HandleExit(msg->mach_time, **proc); break;
    default: return;
  }
}

}  // namespace santa::santad::process_tree
