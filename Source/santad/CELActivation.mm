/// Copyright 2026 North Pole Security, Inc.
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

#import "Source/santad/CELActivation.h"

#include <bsm/libbsm.h>
#include <sys/proc_info.h>

#include <map>
#include <memory>
#include <string>
#include <vector>

#import "Source/common/MOLCodesignChecker.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SigningIDHelpers.h"
#include "Source/common/String.h"
#include "Source/common/cel/Activation.h"
#include "Source/common/cel/CELProtoTraits.h"
#include "Source/common/es/EndpointSecurityAPI.h"
#include "Source/common/processtree/process_tree_macos.h"

namespace {

template <bool IsV2>
std::vector<typename santa::cel::CELProtoTraits<IsV2>::AncestorT> Ancestors(
    const std::shared_ptr<santa::santad::process_tree::ProcessTree>& processTree,
    const santa::Message& esMsg);

template <>
std::vector<santa::cel::CELProtoTraits<true>::AncestorT> Ancestors<true>(
    const std::shared_ptr<santa::santad::process_tree::ProcessTree>& processTree,
    const santa::Message& esMsg) {
  namespace pt = santa::santad::process_tree;

  // [CELANCESTRY] DEBUG-ONLY INSTRUMENTATION (revert before merge).
  // Identify the exec being evaluated so log lines can be correlated with a
  // specific probe. CEL activations are only built for AUTH_EXEC, so the exec
  // union is valid here.
  const char* targetPath = (esMsg->event.exec.target && esMsg->event.exec.target->executable)
                               ? esMsg->event.exec.target->executable->path.data
                               : "?";
  pid_t execingPid = pt::PidFromAuditToken(esMsg->process->audit_token).pid;

  if (!processTree) {
    LOGW(@"[CELANCESTRY] target=%s execing_pid=%d: EMPTY (processTree is null)", targetPath,
         execingPid);
    return {};
  }

  using Traits = santa::cel::CELProtoTraits<true>;
  using AncestorT = typename Traits::AncestorT;

  auto pid = pt::PidFromAuditToken(esMsg->process->parent_audit_token);
  auto proc = processTree->Get(pid);
  if (!proc) {
    // [CELANCESTRY] The parent could not be resolved. Distinguish "pid absent
    // entirely" from "pid present under a different pidversion" — the latter
    // would indict lookup/pidversion handling rather than a population gap.
    bool samePidOtherVer = false;
    uint64_t otherVer = 0;
    processTree->Iterate([&](std::shared_ptr<const pt::Process> p) {
      if (!samePidOtherVer && p->pid_.pid == pid.pid) {
        samePidOtherVer = true;
        otherVer = p->pid_.pidversion;
      }
    });
    LOGW(@"[CELANCESTRY] target=%s execing_pid=%d: EMPTY — parent pid=%d pidver=%llu NOT resolved "
         @"by Get(); same_pid_different_pidver=%d other_pidver=%llu",
         targetPath, execingPid, pid.pid, (unsigned long long)pid.pidversion, samePidOtherVer,
         (unsigned long long)otherVer);
    return {};
  }

  std::vector<santa::cel::CELProtoTraits<true>::AncestorT> ancestors;
  int skippedNullProgram = 0;
  for (const auto& p : processTree->RootSlice(*proc)) {
    if (!p->program_) {
      skippedNullProgram++;
      continue;
    }

    AncestorT ancestor;
    ancestor.set_path(p->program_->executable);
    for (const auto& arg : p->program_->arguments) {
      ancestor.add_args(arg);
    }

    if (p->program_->code_signing) {
      const auto& cs = *p->program_->code_signing;
      if (cs.is_platform_binary) {
        ancestor.set_signing_id("platform:" + cs.signing_id);
      } else {
        ancestor.set_signing_id(cs.team_id + ":" + cs.signing_id);
      }
      ancestor.set_team_id(cs.team_id);
      ancestor.set_cdhash(cs.cdhash);
    }

    ancestors.push_back(std::move(ancestor));
  }
  // [CELANCESTRY] Success path: report how the walk turned out.
  LOGW(@"[CELANCESTRY] target=%s execing_pid=%d: parent pid=%d pidver=%llu resolved; built %zu "
       @"ancestors (skipped %d null-program)",
       targetPath, execingPid, pid.pid, (unsigned long long)pid.pidversion, ancestors.size(),
       skippedNullProgram);
  return ancestors;
}

template <>
std::vector<santa::cel::CELProtoTraits<false>::AncestorT> Ancestors<false>(
    const std::shared_ptr<santa::santad::process_tree::ProcessTree>& processTree,
    const santa::Message& esMsg) {
  return {};
}

using FD = ::santa::cel::v2::FileDescriptor;

FD::FDType FDTypeFromES(uint32_t fdtype) {
  switch (fdtype) {
    case PROX_FDTYPE_VNODE: return FD::FD_TYPE_VNODE;
    case PROX_FDTYPE_SOCKET: return FD::FD_TYPE_SOCKET;
    case PROX_FDTYPE_PSHM: return FD::FD_TYPE_PSHM;
    case PROX_FDTYPE_PSEM: return FD::FD_TYPE_PSEM;
    case PROX_FDTYPE_KQUEUE: return FD::FD_TYPE_KQUEUE;
    case PROX_FDTYPE_PIPE: return FD::FD_TYPE_PIPE;
    case PROX_FDTYPE_FSEVENTS: return FD::FD_TYPE_FSEVENTS;
    case PROX_FDTYPE_ATALK: return FD::FD_TYPE_ATALK;
    case PROX_FDTYPE_NETPOLICY: return FD::FD_TYPE_NETPOLICY;
    case PROX_FDTYPE_CHANNEL: return FD::FD_TYPE_CHANNEL;
    case PROX_FDTYPE_NEXUS: return FD::FD_TYPE_NEXUS;
    default: return FD::FD_TYPE_UNKNOWN;
  }
}

}  // namespace

namespace santa {

ActivationCallbackBlock CreateCELActivationBlock(
    const Message& esMsg, NSString* signingID, NSString* teamID, BOOL isPlatformBinary,
    NSDate* signingTime, NSDate* secureSigningTime, NSDictionary* entitlementsDict,
    std::shared_ptr<santad::process_tree::ProcessTree> processTree) {
  std::shared_ptr<EndpointSecurityAPI> esApi = esMsg.ESAPI();
  NSString* formattedSigningID = FormatSigningID(signingID, teamID, isPlatformBinary);

  return ^std::unique_ptr<::google::api::expr::runtime::BaseActivation>(bool useV2) {
    auto makeActivation =
        [&]<bool IsV2>() -> std::unique_ptr<::google::api::expr::runtime::BaseActivation> {
      using Traits = santa::cel::CELProtoTraits<IsV2>;
      using ExecutableFileT = typename Traits::ExecutableFileT;
      using AncestorT = typename Traits::AncestorT;
      using FileDescriptorT = typename Traits::FileDescriptorT;

      auto f = std::make_unique<ExecutableFileT>();

      if (formattedSigningID) {
        f->set_signing_id(santa::NSStringToUTF8String(formattedSigningID));
      }

      if (signingTime) {
        f->mutable_signing_time()->set_seconds(signingTime.timeIntervalSince1970);
      }
      if (secureSigningTime) {
        f->mutable_secure_signing_time()->set_seconds(secureSigningTime.timeIntervalSince1970);
      }

      f->set_is_platform_binary(isPlatformBinary);
      if (teamID) {
        f->set_team_id(santa::NSStringToUTF8String(teamID));
      }

      if constexpr (IsV2) {
        if (entitlementsDict) {
          auto* entitlements = f->mutable_entitlements();
          [entitlementsDict
              enumerateKeysAndObjectsUsingBlock:^(NSString* key, id value, BOOL* stop) {
                NSError* err;
                NSData* jsonData;
                @try {
                  jsonData = [NSJSONSerialization dataWithJSONObject:value
                                                             options:NSJSONWritingFragmentsAllowed
                                                               error:&err];
                } @catch (NSException*) {
                }
                if (!jsonData) {
                  // Skip entitlements that can't be serialized to JSON.
                  return;
                }
                NSString* jsonStr = [[NSString alloc] initWithData:jsonData
                                                          encoding:NSUTF8StringEncoding];
                (*entitlements)[santa::NSStringToUTF8String(key)] =
                    santa::NSStringToUTF8String(jsonStr);
              }];
        }
      }

      return std::make_unique<santa::cel::Activation<IsV2>>(
          std::move(f),
          ^std::vector<std::string>() {
            return esApi->ExecArgs(&esMsg->event.exec);
          },
          ^std::map<std::string, std::string>() {
            return esApi->ExecEnvs(&esMsg->event.exec);
          },
          ^uid_t() {
            return audit_token_to_euid(esMsg->event.exec.target->audit_token);
          },
          ^std::string() {
            es_file_t* f = esMsg->event.exec.cwd;
            if (!f) return std::string();
            return std::string(f->path.data, f->path.length);
          },
          ^std::string() {
            es_file_t* f = esMsg->event.exec.target->executable;
            if (!f) return std::string();
            return std::string(f->path.data, f->path.length);
          },
          ^std::vector<AncestorT>() {
            return Ancestors<IsV2>(processTree, esMsg);
          },
          ^std::vector<FileDescriptorT>() {
            if constexpr (IsV2) {
              std::vector<FileDescriptorT> fds;
              uint32_t fdCount = esApi->ExecFDCount(&esMsg->event.exec);
              fds.reserve(fdCount);
              for (uint32_t i = 0; i < fdCount; i++) {
                const es_fd_t* esFD = esApi->ExecFD(&esMsg->event.exec, i);
                FileDescriptorT fd;
                fd.set_fd(esFD->fd);
                fd.set_type(FDTypeFromES(esFD->fdtype));
                fds.push_back(std::move(fd));
              }
              return fds;
            } else {
              return {};
            }
          });
    };

    if (useV2) {
      return makeActivation.operator()<true>();
    } else {
      return makeActivation.operator()<false>();
    }
  };
}

ActivationCallbackBlock CreateCELActivationBlock(
    const Message& esMsg, MOLCodesignChecker* csInfo,
    std::shared_ptr<santad::process_tree::ProcessTree> processTree) {
  return CreateCELActivationBlock(esMsg, csInfo.signingID, csInfo.teamID, csInfo.platformBinary,
                                  csInfo.signingTime, csInfo.secureSigningTime, csInfo.entitlements,
                                  std::move(processTree));
}

}  // namespace santa
