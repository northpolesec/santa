/// Copyright 2015 Google Inc. All rights reserved.
/// Copyright 2024 North Pole Security, Inc.
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

#import "Source/santasyncservice/SNTSyncEventUpload.h"

#include "Source/common/EncodeEntitlements.h"
#import "Source/common/MOLCertificate.h"
#import "Source/common/MOLXPCConnection.h"
#import "Source/common/NSData+Zlib.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTFileInfo.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTStoredEvent.h"
#import "Source/common/SNTStoredExecutionEvent.h"
#import "Source/common/SNTStoredFileAccessEvent.h"
#import "Source/common/SNTStoredNetworkMountEvent.h"
#include "Source/common/SNTStoredTemporaryMonitorModeAuditEvent.h"
#import "Source/common/SNTStoredUSBMountEvent.h"
#import "Source/common/SNTSyncConstants.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/common/String.h"
#include "Source/santasyncservice/ProtoTraits.h"
#import "Source/santasyncservice/SNTSyncLogging.h"
#import "Source/santasyncservice/SNTSyncState.h"
#include "google/protobuf/arena.h"

namespace pbv2 = ::santa::sync::v2;

using santa::NSStringToUTF8String;
using santa::NSStringToUTF8StringView;

namespace {

template <bool IsV2>
BOOL PerformRequest(SNTSyncEventUpload *self, google::protobuf::Message *req, int eventsInBatch);
template <bool IsV2>
typename santa::ProtoTraits<IsV2>::EventT *MessageForExecutionEvent(SNTStoredExecutionEvent *event,
                                                                    google::protobuf::Arena *arena);
template <bool IsV2>
typename santa::ProtoTraits<IsV2>::FileAccessEventT *MessageForFileAccessEvent(
    SNTStoredFileAccessEvent *event, google::protobuf::Arena *arena);
::pbv2::AuditEvent *MessageForTemporaryMonitorModeAuditEvent(
    SNTStoredTemporaryMonitorModeAuditEvent *event, google::protobuf::Arena *arena);
::pbv2::NetworkMountEvent *MessageForNetworkMountEvent(SNTStoredNetworkMountEvent *event,
                                                       google::protobuf::Arena *arena);
::pbv2::USBMountEvent *MessageForUSBMountEvent(SNTStoredUSBMountEvent *event,
                                               google::protobuf::Arena *arena);

template <bool IsV2>
BOOL PerformRequest(SNTSyncEventUpload *self, google::protobuf::Message *req, int eventsInBatch) {
  using Traits = santa::ProtoTraits<IsV2>;
  if (eventsInBatch == 0) {
    return YES;
  }

  if (self.syncState.syncType == SNTSyncTypeNormal ||
      [[SNTConfigurator configurator] enableCleanSyncEventUpload]) {
    typename Traits::EventUploadResponseT response;
    NSError *err = [self performRequest:[self requestWithMessage:req]
                            intoMessage:&response
                                timeout:30];
    if (err) {
      SLOGE(@"Failed to upload events: %@", err);
      return NO;
    }

    // A list of bundle hashes that require their related binary events to be uploaded.
    if (response.event_upload_bundle_binaries_size()) {
      self.syncState.bundleBinaryRequests =
          [NSMutableArray arrayWithCapacity:response.event_upload_bundle_binaries_size()];
      for (const std::string &bundle_binary : response.event_upload_bundle_binaries()) {
        [(NSMutableArray *)self.syncState.bundleBinaryRequests
            addObject:santa::StringToNSString(bundle_binary)];
      }
    }
    SLOGI(@"Uploaded %d events", eventsInBatch);
  }
  return YES;
}

template <bool IsV2>
BOOL EventUpload(SNTSyncEventUpload *self, NSArray<SNTStoredEvent *> *events) {
  using Traits = santa::ProtoTraits<IsV2>;
  google::protobuf::Arena arena;
  google::protobuf::Arena *pArena = &arena;
  NSMutableSet *eventIds = [NSMutableSet setWithCapacity:events.count];
  auto req = google::protobuf::Arena::Create<typename Traits::EventUploadRequestT>(&arena);
  req->set_machine_id(NSStringToUTF8String(self.syncState.machineID));
  google::protobuf::RepeatedPtrField<typename Traits::EventT> *uploadEvents = req->mutable_events();
  google::protobuf::RepeatedPtrField<typename Traits::FileAccessEventT> *uploadFAAEvents =
      req->mutable_file_access_events();
  google::protobuf::RepeatedPtrField<typename Traits::AuditEventT> *uploadAuditEvents =
      req->mutable_audit_events();
  google::protobuf::RepeatedPtrField<::pbv2::NetworkMountEvent> *uploadNetworkMountEvents;
  google::protobuf::RepeatedPtrField<::pbv2::USBMountEvent> *uploadUSBMountEvents;
  if constexpr (IsV2) {
    uploadNetworkMountEvents = req->mutable_network_mount_events();
    uploadUSBMountEvents = req->mutable_usb_mount_events();
  }
  __block BOOL success = YES;
  NSUInteger finalIdx = (events.count - 1);

  [events enumerateObjectsUsingBlock:^(SNTStoredEvent *event, NSUInteger idx, BOOL *stop) {
    // Track the idx as processed immediately so that it will always be removed
    // from the database, even if not uploaded.
    if (event.idx) [eventIds addObject:event.idx];

    if ([event isKindOfClass:[SNTStoredExecutionEvent class]]) {
      if (auto e = MessageForExecutionEvent<IsV2>((SNTStoredExecutionEvent *)event, pArena)) {
        uploadEvents->UnsafeArenaAddAllocated(e);
      }
    } else if ([event isKindOfClass:[SNTStoredFileAccessEvent class]]) {
      if (auto e = MessageForFileAccessEvent<IsV2>((SNTStoredFileAccessEvent *)event, pArena)) {
        uploadFAAEvents->UnsafeArenaAddAllocated(e);
      }
    } else if ([event isKindOfClass:[SNTStoredTemporaryMonitorModeAuditEvent class]]) {
      if constexpr (IsV2) {
        if (auto e = MessageForTemporaryMonitorModeAuditEvent(
                (SNTStoredTemporaryMonitorModeAuditEvent *)event, pArena)) {
          uploadAuditEvents->UnsafeArenaAddAllocated(e);
        }
      }
    } else if ([event isKindOfClass:[SNTStoredNetworkMountEvent class]]) {
      if constexpr (IsV2) {
        if (auto e = MessageForNetworkMountEvent((SNTStoredNetworkMountEvent *)event, pArena)) {
          uploadNetworkMountEvents->UnsafeArenaAddAllocated(e);
        }
      }
    } else if ([event isKindOfClass:[SNTStoredUSBMountEvent class]]) {
      if constexpr (IsV2) {
        if (auto e = MessageForUSBMountEvent((SNTStoredUSBMountEvent *)event, pArena)) {
          uploadUSBMountEvents->UnsafeArenaAddAllocated(e);
        }
      }

    } else {
      // This shouldn't be able to happen. But if it does, log a warning and continue. We still
      // want to continue on in case this is the last event being enumerated so that anything in
      // the batch still gets uploaded.
      LOGW(@"Unexpected event type in event upload: %@", [event class]);
    }

    int totalEventCount =
        uploadEvents->size() + uploadFAAEvents->size() + uploadAuditEvents->size();
    if constexpr (IsV2) {
      totalEventCount += uploadNetworkMountEvents->size();
      totalEventCount += uploadUSBMountEvents->size();
    }

    if (totalEventCount >= self.syncState.eventBatchSize || idx == finalIdx) {
      if (!PerformRequest<IsV2>(self, req, totalEventCount)) {
        success = NO;
        *stop = YES;
        return;
      }

      // Remove event IDs. For Bundle Events the ID is 0 so nothing happens.
      [[self.daemonConn remoteObjectProxy] databaseRemoveEventsWithIDs:[eventIds allObjects]];

      [eventIds removeAllObjects];
      uploadEvents->Clear();
      uploadFAAEvents->Clear();
      uploadAuditEvents->Clear();
      if constexpr (IsV2) {
        uploadNetworkMountEvents->Clear();
        uploadUSBMountEvents->Clear();
      }
    }
  }];

  // Handle the case where no events generated messages to send (e.g. all transitive)
  // Note: Check for success in case there are events in the set that failed to upload.
  if (success && eventIds.count > 0) {
    [[self.daemonConn remoteObjectProxy] databaseRemoveEventsWithIDs:[eventIds allObjects]];
  }

  return success;
}

template <bool IsV2>
typename santa::ProtoTraits<IsV2>::EventT *MessageForExecutionEvent(
    SNTStoredExecutionEvent *event, google::protobuf::Arena *arena) {
  using Traits = santa::ProtoTraits<IsV2>;
  auto e = google::protobuf::Arena::Create<typename Traits::EventT>(arena);

  e->set_file_sha256(NSStringToUTF8String(event.fileSHA256));
  e->set_file_path(NSStringToUTF8String([event.filePath stringByDeletingLastPathComponent]));
  e->set_file_name(NSStringToUTF8String([event.filePath lastPathComponent]));
  e->set_executing_user(NSStringToUTF8String(event.executingUser));
  e->set_execution_time([event.occurrenceDate timeIntervalSince1970]);

  for (NSString *user in event.loggedInUsers) {
    e->add_logged_in_users(NSStringToUTF8String(user));
  }
  for (NSString *session in event.currentSessions) {
    e->add_current_sessions(NSStringToUTF8String(session));
  }

  switch (event.decision) {
    case SNTEventStateAllowUnknown: e->set_decision(Traits::ALLOW_UNKNOWN); break;
    case SNTEventStateAllowBinary: e->set_decision(Traits::ALLOW_BINARY); break;
    case SNTEventStateAllowCompilerBinary: e->set_decision(Traits::ALLOW_BINARY); break;
    case SNTEventStateAllowCertificate: e->set_decision(Traits::ALLOW_CERTIFICATE); break;
    case SNTEventStateAllowScope: e->set_decision(Traits::ALLOW_SCOPE); break;
    case SNTEventStateAllowTeamID: e->set_decision(Traits::ALLOW_TEAMID); break;
    case SNTEventStateAllowSigningID: e->set_decision(Traits::ALLOW_SIGNINGID); break;
    case SNTEventStateAllowCompilerSigningID: e->set_decision(Traits::ALLOW_SIGNINGID); break;
    case SNTEventStateAllowCDHash: e->set_decision(Traits::ALLOW_CDHASH); break;
    case SNTEventStateAllowCompilerCDHash: e->set_decision(Traits::ALLOW_CDHASH); break;
    case SNTEventStateBlockUnknown: e->set_decision(Traits::BLOCK_UNKNOWN); break;
    case SNTEventStateBlockBinary: e->set_decision(Traits::BLOCK_BINARY); break;
    case SNTEventStateBlockCertificate: e->set_decision(Traits::BLOCK_CERTIFICATE); break;
    case SNTEventStateBlockScope: e->set_decision(Traits::BLOCK_SCOPE); break;
    case SNTEventStateBlockTeamID: e->set_decision(Traits::BLOCK_TEAMID); break;
    case SNTEventStateBlockSigningID: e->set_decision(Traits::BLOCK_SIGNINGID); break;
    case SNTEventStateBlockCDHash: e->set_decision(Traits::BLOCK_CDHASH); break;
    case SNTEventStateAllowTransitive: return nullptr;
    case SNTEventStateAllowLocalBinary: return nullptr;
    case SNTEventStateAllowLocalSigningID: return nullptr;
    case SNTEventStateAllowPendingTransitive: return nullptr;
    case SNTEventStateBlockLongPath: return nullptr;
    case SNTEventStateAllow: return nullptr;
    case SNTEventStateBlock: return nullptr;
    case SNTEventStateUnknown: return nullptr;
    case SNTEventStateBundleBinary:
      e->set_decision(Traits::BUNDLE_BINARY);
      e->clear_execution_time();
      break;
  }

  e->set_file_bundle_id(NSStringToUTF8String(event.fileBundleID));
  e->set_file_bundle_path(NSStringToUTF8String(event.fileBundlePath));
  e->set_file_bundle_executable_rel_path(NSStringToUTF8String(event.fileBundleExecutableRelPath));
  e->set_file_bundle_name(NSStringToUTF8String(event.fileBundleName));
  e->set_file_bundle_version(NSStringToUTF8String(event.fileBundleVersion));
  e->set_file_bundle_version_string(NSStringToUTF8String(event.fileBundleVersionString));
  e->set_file_bundle_hash(NSStringToUTF8String(event.fileBundleHash));
  e->set_file_bundle_hash_millis([event.fileBundleHashMilliseconds unsignedIntValue]);
  e->set_file_bundle_binary_count([event.fileBundleBinaryCount unsignedIntValue]);

  e->set_pid([event.pid unsignedIntValue]);
  e->set_ppid([event.ppid unsignedIntValue]);
  e->set_parent_name(NSStringToUTF8String(event.parentName));

  e->set_quarantine_data_url(NSStringToUTF8String(event.quarantineDataURL));
  e->set_quarantine_referer_url(NSStringToUTF8String(event.quarantineRefererURL));
  e->set_quarantine_timestamp([event.quarantineTimestamp timeIntervalSince1970]);
  e->set_quarantine_agent_bundle_id(NSStringToUTF8String(event.quarantineAgentBundleID));

  e->set_team_id(NSStringToUTF8String(event.teamID));
  e->set_signing_id(NSStringToUTF8String(event.signingID));
  e->set_cdhash(NSStringToUTF8String(event.cdhash));
  e->set_cs_flags(event.codesigningFlags);
  e->set_secure_signing_time([event.secureSigningTime timeIntervalSince1970]);
  e->set_signing_time([event.signingTime timeIntervalSince1970]);

  switch (event.signingStatus) {
    case SNTSigningStatusUnsigned: e->set_signing_status(Traits::SIGNING_STATUS_UNSIGNED); break;
    case SNTSigningStatusInvalid: e->set_signing_status(Traits::SIGNING_STATUS_INVALID); break;
    case SNTSigningStatusAdhoc: e->set_signing_status(Traits::SIGNING_STATUS_ADHOC); break;
    case SNTSigningStatusDevelopment:
      e->set_signing_status(Traits::SIGNING_STATUS_DEVELOPMENT);
      break;
    case SNTSigningStatusProduction:
      e->set_signing_status(Traits::SIGNING_STATUS_PRODUCTION);
      break;
    default: e->set_signing_status(Traits::SIGNING_STATUS_UNSPECIFIED); break;
  }

  for (MOLCertificate *cert in event.signingChain) {
    typename Traits::CertificateT *c = e->add_signing_chain();
    c->set_sha256(NSStringToUTF8String(cert.SHA256));
    c->set_cn(NSStringToUTF8String(cert.commonName));
    c->set_org(NSStringToUTF8String(cert.orgName));
    c->set_ou(NSStringToUTF8String(cert.orgUnit));
    c->set_valid_from([cert.validFrom timeIntervalSince1970]);
    c->set_valid_until([cert.validUntil timeIntervalSince1970]);
  }

  typename Traits::EntitlementInfoT *pb_entitlement_info = e->mutable_entitlement_info();

  santa::EncodeEntitlementsCommon(
      event.entitlements, event.entitlementsFiltered,
      ^(NSUInteger count, bool is_filtered) {
        pb_entitlement_info->set_entitlements_filtered(is_filtered);
        pb_entitlement_info->mutable_entitlements()->Reserve((int)count);
      },
      ^(NSString *entitlement, NSString *value) {
        typename Traits::EntitlementT *pb_entitlement = pb_entitlement_info->add_entitlements();
        pb_entitlement->set_key(NSStringToUTF8StringView(entitlement));
        pb_entitlement->set_value(NSStringToUTF8StringView(value));
      });

  // TODO: Add support the for Standalone Approval field so that a sync service
  // can be notified that a user self approved a binary.

  return e;
}

template <bool IsV2>
typename santa::ProtoTraits<IsV2>::FileAccessEventT *MessageForFileAccessEvent(
    SNTStoredFileAccessEvent *event, google::protobuf::Arena *arena) {
  using Traits = santa::ProtoTraits<IsV2>;
  auto e = google::protobuf::Arena::Create<typename Traits::FileAccessEventT>(arena);

  e->set_rule_version(NSStringToUTF8StringView(event.ruleVersion));
  e->set_rule_name(NSStringToUTF8StringView(event.ruleName));
  e->set_target(NSStringToUTF8StringView(event.accessedPath));
  e->set_access_time([event.occurrenceDate timeIntervalSince1970]);

  switch (event.decision) {
    case FileAccessPolicyDecision::kDenied:
      e->set_decision(Traits::FILE_ACCESS_DECISION_DENIED);
      break;
    case FileAccessPolicyDecision::kDeniedInvalidSignature:
      e->set_decision(Traits::FILE_ACCESS_DECISION_DENIED_INVALID_SIGNATURE);
      break;
    case FileAccessPolicyDecision::kAllowedAuditOnly:
      e->set_decision(Traits::FILE_ACCESS_DECISION_AUDIT_ONLY);
      break;
    case FileAccessPolicyDecision::kNoPolicy: return nullptr;
    case FileAccessPolicyDecision::kAllowed: return nullptr;
    case FileAccessPolicyDecision::kAllowedReadAccess: return nullptr;
    default: return nullptr;
  }

  SNTStoredFileAccessProcess *p = event.process;
  auto process_chain = e->mutable_process_chain();
  while (p) {
    typename Traits::ProcessT *proc = process_chain->Add();
    if (p.filePath) {
      proc->set_file_path(NSStringToUTF8StringView(p.filePath));
    }

    if (p.fileSHA256) {
      proc->set_file_sha256(NSStringToUTF8StringView(p.fileSHA256));
    }

    if (p.cdhash) {
      proc->set_cdhash(NSStringToUTF8StringView(p.cdhash));
    }

    if (p.signingID) {
      proc->set_signing_id(NSStringToUTF8StringView(p.signingID));
    }

    if (p.teamID) {
      proc->set_team_id(NSStringToUTF8StringView(p.teamID));
    }

    if (p.pid) {
      proc->set_pid([p.pid intValue]);
    }

    for (MOLCertificate *cert in p.signingChain) {
      typename Traits::CertificateT *c = proc->add_signing_chain();
      c->set_sha256(NSStringToUTF8String(cert.SHA256));
      c->set_cn(NSStringToUTF8String(cert.commonName));
      c->set_org(NSStringToUTF8String(cert.orgName));
      c->set_ou(NSStringToUTF8String(cert.orgUnit));
      c->set_valid_from([cert.validFrom timeIntervalSince1970]);
      c->set_valid_until([cert.validUntil timeIntervalSince1970]);
    }

    p = p.parent;
  }

  return e;
}

::pbv2::NetworkMountEvent *MessageForNetworkMountEvent(SNTStoredNetworkMountEvent *event,
                                                       google::protobuf::Arena *arena) {
  auto pbNetworkMountEvent =
      google::protobuf::Arena::Create<typename ::pbv2::NetworkMountEvent>(arena);

  pbNetworkMountEvent->set_uuid(NSStringToUTF8String(event.uuid));
  pbNetworkMountEvent->set_mount_from(
      NSStringToUTF8String([event sanitizedMountFromRemovingCredentials]));
  pbNetworkMountEvent->set_mount_on(NSStringToUTF8String(event.mountOnName));
  pbNetworkMountEvent->set_fs_type(NSStringToUTF8String(event.fsType));
  pbNetworkMountEvent->set_access_time([event.occurrenceDate timeIntervalSince1970]);

  return pbNetworkMountEvent;
}

::pbv2::USBMountEvent *MessageForUSBMountEvent(SNTStoredUSBMountEvent *event,
                                               google::protobuf::Arena *arena) {
  auto pbUSBMountEvent = google::protobuf::Arena::Create<typename ::pbv2::USBMountEvent>(arena);

  pbUSBMountEvent->set_uuid(NSStringToUTF8String(event.uuid));
  if (event.deviceModel.length > 0) {
    pbUSBMountEvent->set_device_model(NSStringToUTF8String(event.deviceModel));
  }
  if (event.deviceVendor.length > 0) {
    pbUSBMountEvent->set_device_vendor(NSStringToUTF8String(event.deviceVendor));
  }
  pbUSBMountEvent->set_mount_on(NSStringToUTF8String(event.mountOnName));
  pbUSBMountEvent->set_access_time([event.occurrenceDate timeIntervalSince1970]);
  

  return pbUSBMountEvent;
}

void MessageForTemporaryMonitorModeEnterAuditEvent(
    SNTStoredTemporaryMonitorModeEnterAuditEvent *event,
    ::pbv2::TemporaryMonitorModeEnter *pbEnter) {
  if (!pbEnter) {
    return;
  }

  pbEnter->set_seconds(event.seconds);

  switch (event.reason) {
    case SNTTemporaryMonitorModeEnterReasonOnDemand:
      pbEnter->set_reason(::pbv2::TemporaryMonitorModeEnter::REASON_ON_DEMAND);
      break;
    case SNTTemporaryMonitorModeEnterReasonOnDemandRefresh:
      pbEnter->set_reason(::pbv2::TemporaryMonitorModeEnter::REASON_ON_DEMAND_REFRESH);
      break;
    case SNTTemporaryMonitorModeEnterReasonRestart:
      pbEnter->set_reason(::pbv2::TemporaryMonitorModeEnter::REASON_RESTART);
      break;
    default: pbEnter->set_reason(::pbv2::TemporaryMonitorModeEnter::REASON_UNSPECIFIED); break;
  }
}

void MessageForTemporaryMonitorModeLeaveAuditEvent(
    SNTStoredTemporaryMonitorModeLeaveAuditEvent *event,
    ::pbv2::TemporaryMonitorModeLeave *pbLeave) {
  if (!pbLeave) {
    return;
  }

  switch (event.reason) {
    case SNTTemporaryMonitorModeLeaveReasonSessionExpired:
      pbLeave->set_reason(::pbv2::TemporaryMonitorModeLeave::REASON_EXPIRY);
      break;
    case SNTTemporaryMonitorModeLeaveReasonCancelled:
      pbLeave->set_reason(::pbv2::TemporaryMonitorModeLeave::REASON_CANCELLED);
      break;
    case SNTTemporaryMonitorModeLeaveReasonRevoked:
      pbLeave->set_reason(::pbv2::TemporaryMonitorModeLeave::REASON_REVOKED);
      break;
    case SNTTemporaryMonitorModeLeaveReasonSyncServerChanged:
      pbLeave->set_reason(::pbv2::TemporaryMonitorModeLeave::REASON_SYNC_SERVER_CHANGED);
      break;
    case SNTTemporaryMonitorModeLeaveReasonReboot:
      pbLeave->set_reason(::pbv2::TemporaryMonitorModeLeave::REASON_REBOOT);
      break;
    default: pbLeave->set_reason(::pbv2::TemporaryMonitorModeLeave::REASON_UNSPECIFIED); break;
  }
}

::pbv2::AuditEvent *MessageForTemporaryMonitorModeAuditEvent(
    SNTStoredTemporaryMonitorModeAuditEvent *event, google::protobuf::Arena *arena) {
  if (![event isKindOfClass:[SNTStoredTemporaryMonitorModeEnterAuditEvent class]] &&
      ![event isKindOfClass:[SNTStoredTemporaryMonitorModeLeaveAuditEvent class]]) {
    return nullptr;
  }

  auto pbAudit = google::protobuf::Arena::Create<typename ::pbv2::AuditEvent>(arena);
  pbAudit->set_timestamp([[event occurrenceDate] timeIntervalSince1970]);

  auto pbTmm = pbAudit->mutable_temporary_monitor_mode();
  pbTmm->set_session_id(NSStringToUTF8StringView(event.uuid));

  if ([event isKindOfClass:[SNTStoredTemporaryMonitorModeEnterAuditEvent class]]) {
    MessageForTemporaryMonitorModeEnterAuditEvent(
        (SNTStoredTemporaryMonitorModeEnterAuditEvent *)event, pbTmm->mutable_enter());
  } else if ([event isKindOfClass:[SNTStoredTemporaryMonitorModeLeaveAuditEvent class]]) {
    MessageForTemporaryMonitorModeLeaveAuditEvent(
        (SNTStoredTemporaryMonitorModeLeaveAuditEvent *)event, pbTmm->mutable_leave());
  }

  return pbAudit;
}

}  // namespace

@implementation SNTSyncEventUpload

- (NSURL *)stageURL {
  NSString *stageName = [@"eventupload" stringByAppendingFormat:@"/%@", self.syncState.machineID];
  return [NSURL URLWithString:stageName relativeToURL:self.syncState.syncBaseURL];
}

- (BOOL)sync {
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  [[self.daemonConn remoteObjectProxy] databaseEventsPending:^(NSArray *events) {
    if (events.count) {
      [self uploadEvents:events];
    }
    dispatch_semaphore_signal(sema);
  }];
  return (dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER) == 0);
}

- (BOOL)uploadEvents:(NSArray<SNTStoredEvent *> *)events {
  if (self.syncState.isSyncV2) {
    return EventUpload<true>(self, events);
  } else {
    return EventUpload<false>(self, events);
  }
}

@end
