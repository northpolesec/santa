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

#import "Source/santasyncservice/SNTSantaCommandHandler+Kill.h"

#import "Source/common/SNTKillCommand.h"
#import "Source/common/SNTXPCControlInterface.h"
#include "Source/common/String.h"

namespace pbv1 = ::santa::commands::v1;
using santa::StringToNSString;

// Semi-arbitrary number of seconds to wait for santad to finish killing processes
static constexpr int64_t kKillResponseTimeoutSeconds = 90;

namespace {

void SetKillResponseError(SNTKillResponseError error, ::pbv1::KillResponse* pbResponse) {
  switch (error) {
    case SNTKillResponseErrorListPids:
      pbResponse->set_error(::pbv1::KillResponse::ERROR_LIST_PIDS);
      break;
    case SNTKillResponseErrorInvalidRequest:
      pbResponse->set_error(::pbv1::KillResponse::ERROR_INTERNAL);
      break;
    case SNTKillResponseErrorNone:
      // Do not set the error if there was none
      break;
    default: pbResponse->set_error(::pbv1::KillResponse::ERROR_INTERNAL); break;
  }
}

void SetKilledProcessError(SNTKilledProcessError error, ::pbv1::KillResponse::Process* pbProcess) {
  switch (error) {
    case SNTKilledProcessErrorUnknown:
      pbProcess->set_error(::pbv1::KillResponse::KILL_ERROR_INTERNAL);
      break;
    case SNTKilledProcessErrorInvalidTarget:
      pbProcess->set_error(::pbv1::KillResponse::KILL_ERROR_INVALID_TARGET);
      break;
    case SNTKilledProcessErrorNotPermitted:
      pbProcess->set_error(::pbv1::KillResponse::KILL_ERROR_OPERATION_NOT_PERMITTED);
      break;
    case SNTKilledProcessErrorNoSuchProcess:
      pbProcess->set_error(::pbv1::KillResponse::KILL_ERROR_NO_SUCH_PROCESS);
      break;
    case SNTKilledProcessErrorInvalidArgument:
      pbProcess->set_error(::pbv1::KillResponse::KILL_ERROR_INVALID_ARGUMENT);
      break;
    case SNTKilledProcessErrorBootSessionMismatch:
      pbProcess->set_error(::pbv1::KillResponse::KILL_ERROR_BOOT_SESSION_MISMATCH);
      break;
    case SNTKilledProcessErrorNone:
      // Do not set the error if there was none
      break;
    default: pbProcess->set_error(::pbv1::KillResponse::KILL_ERROR_INTERNAL); break;
  }
}

}  // namespace

// Forward declaration of private interface to access private properties
@interface SNTSantaCommandHandler ()
@property(weak) id<SNTPushNotificationsSyncDelegate> syncDelegate;
@end

@implementation SNTSantaCommandHandler (Kill)

- (::pbv1::KillResponse*)handleKillRequest:(const ::pbv1::KillRequest&)pbKillReq
                            withIdentifier:(NSString*)identifier
                                   onArena:(google::protobuf::Arena*)arena {
  auto pbKillResponse = google::protobuf::Arena::Create<::pbv1::KillResponse>(arena);
  SNTKillRequest* req;
  switch (pbKillReq.process_case()) {
    case ::pbv1::KillRequest::kRunningProcess:
      req = [[SNTKillRequestRunningProcess alloc]
             initWithUUID:identifier
                      pid:pbKillReq.running_process().pid()
               pidversion:pbKillReq.running_process().pidversion()
          bootSessionUUID:StringToNSString(pbKillReq.running_process().boot_session_uuid())];
      if (!req) {
        pbKillResponse->set_error(::pbv1::KillResponse::ERROR_INVALID_RUNNING_PROCESS);
      }
      break;
    case ::pbv1::KillRequest::kCdhash:
      req = [[SNTKillRequestCDHash alloc] initWithUUID:identifier
                                                cdHash:StringToNSString(pbKillReq.cdhash())];
      if (!req) {
        pbKillResponse->set_error(::pbv1::KillResponse::ERROR_INVALID_CDHASH);
      }
      break;
    case ::pbv1::KillRequest::kSigningId:
      req = [[SNTKillRequestSigningID alloc] initWithUUID:identifier
                                                signingID:StringToNSString(pbKillReq.signing_id())];
      if (!req) {
        pbKillResponse->set_error(::pbv1::KillResponse::ERROR_INVALID_SIGNING_ID);
      }
      break;
    case ::pbv1::KillRequest::kTeamId:
      req = [[SNTKillRequestTeamID alloc] initWithUUID:identifier
                                                teamID:StringToNSString(pbKillReq.team_id())];
      if (!req) {
        pbKillResponse->set_error(::pbv1::KillResponse::ERROR_INVALID_TEAM_ID);
      }
      break;
    default: pbKillResponse->set_error(::pbv1::KillResponse::ERROR_UNKNOWN_PROCESS_TYPE);
  }

  if (!req) {
    return pbKillResponse;
  }

  id<SNTPushNotificationsSyncDelegate> strongSyncDelegate = self.syncDelegate;
  if (!strongSyncDelegate) {
    pbKillResponse->set_error(::pbv1::KillResponse::ERROR_INTERNAL);
    return pbKillResponse;
  }

  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  __block SNTKillResponse* resp;
  [[[strongSyncDelegate daemonConnection] remoteObjectProxy]
      killProcesses:req
              reply:^(SNTKillResponse* killResponse) {
                resp = killResponse;
                dispatch_semaphore_signal(sema);
              }];

  if (dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, kKillResponseTimeoutSeconds *
                                                                         NSEC_PER_SEC)) != 0) {
    pbKillResponse->set_error(::pbv1::KillResponse::ERROR_TIMEOUT);
    return pbKillResponse;
  }

  SetKillResponseError(resp.error, pbKillResponse);

  for (SNTKilledProcess* killedProc in resp.killedProcesses) {
    auto pbProc = google::protobuf::Arena::Create<::pbv1::KillResponse::Process>(arena);

    pbProc->set_pid(killedProc.pid);
    pbProc->set_pidversion(killedProc.pidversion);
    SetKilledProcessError(killedProc.error, pbProc);

    pbKillResponse->mutable_processes()->UnsafeArenaAddAllocated(pbProc);
  }

  return pbKillResponse;
}

@end
