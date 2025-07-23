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
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTFileInfo.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTStoredEvent.h"
#import "Source/common/SNTSyncConstants.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/common/String.h"
#import "Source/santasyncservice/NSData+Zlib.h"
#import "Source/santasyncservice/SNTSyncLogging.h"
#import "Source/santasyncservice/SNTSyncState.h"

#include <google/protobuf/arena.h>
#include "sync/v1.pb.h"
namespace pbv1 = ::santa::sync::v1;

using santa::NSStringToUTF8String;
using santa::NSStringToUTF8StringView;

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

- (BOOL)performRequest:(::pbv1::EventUploadRequest *)req {
  if (req->events_size() == 0) {
    return YES;
  }

  if (self.syncState.syncType == SNTSyncTypeNormal ||
      [[SNTConfigurator configurator] enableCleanSyncEventUpload]) {
    ::pbv1::EventUploadResponse response;
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
            addObject:santa::UTF8StringToNSString(bundle_binary)];
      }
    }
    SLOGI(@"Uploaded %d events", req->events_size());
  }
  return YES;
}

- (BOOL)uploadEvents:(NSArray<SNTStoredEvent *> *)events {
  google::protobuf::Arena arena;
  google::protobuf::Arena *pArena = &arena;
  NSMutableSet *eventIds = [NSMutableSet setWithCapacity:events.count];
  auto req = google::protobuf::Arena::Create<::pbv1::EventUploadRequest>(&arena);
  req->set_machine_id(NSStringToUTF8String(self.syncState.machineID));
  google::protobuf::RepeatedPtrField<::pbv1::Event> *uploadEvents = req->mutable_events();
  __block BOOL success = YES;
  NSUInteger finalIdx = (events.count - 1);

  [events enumerateObjectsUsingBlock:^(SNTStoredEvent *event, NSUInteger idx, BOOL *stop) {
    // Track the idx as processed immediately so that it will always be removed
    // from the database, even if not uploaded.
    if (event.idx) [eventIds addObject:event.idx];

    std::optional<::pbv1::Event> e = [self messageForEvent:event withArena:pArena];
    if (e.has_value()) uploadEvents->Add(*std::move(e));

    if (uploadEvents->size() >= self.syncState.eventBatchSize || idx == finalIdx) {
      if (![self performRequest:req]) {
        success = NO;
        *stop = YES;
        return;
      }

      // Remove event IDs. For Bundle Events the ID is 0 so nothing happens.
      [[self.daemonConn remoteObjectProxy] databaseRemoveEventsWithIDs:[eventIds allObjects]];

      [eventIds removeAllObjects];
      req->clear_events();
    }
  }];

  // Handle the case where no events generated messages to send (e.g. all transitive)
  // Note: Check for success in case there are events in the set that failed to upload.
  if (success && eventIds.count > 0) {
    [[self.daemonConn remoteObjectProxy] databaseRemoveEventsWithIDs:[eventIds allObjects]];
  }

  return success;
}

- (std::optional<::pbv1::Event>)messageForEvent:(SNTStoredEvent *)event
                                      withArena:(google::protobuf::Arena *)arena {
  auto e = google::protobuf::Arena::Create<::pbv1::Event>(arena);

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
    case SNTEventStateAllowUnknown: e->set_decision(::pbv1::ALLOW_UNKNOWN); break;
    case SNTEventStateAllowBinary: e->set_decision(::pbv1::ALLOW_BINARY); break;
    case SNTEventStateAllowCompilerBinary: e->set_decision(::pbv1::ALLOW_BINARY); break;
    case SNTEventStateAllowCertificate: e->set_decision(::pbv1::ALLOW_CERTIFICATE); break;
    case SNTEventStateAllowScope: e->set_decision(::pbv1::ALLOW_SCOPE); break;
    case SNTEventStateAllowTeamID: e->set_decision(::pbv1::ALLOW_TEAMID); break;
    case SNTEventStateAllowSigningID: e->set_decision(::pbv1::ALLOW_SIGNINGID); break;
    case SNTEventStateAllowCompilerSigningID: e->set_decision(::pbv1::ALLOW_SIGNINGID); break;
    case SNTEventStateAllowCDHash: e->set_decision(::pbv1::ALLOW_CDHASH); break;
    case SNTEventStateAllowCompilerCDHash: e->set_decision(::pbv1::ALLOW_CDHASH); break;
    case SNTEventStateBlockUnknown: e->set_decision(::pbv1::BLOCK_UNKNOWN); break;
    case SNTEventStateBlockBinary: e->set_decision(::pbv1::BLOCK_BINARY); break;
    case SNTEventStateBlockCertificate: e->set_decision(::pbv1::BLOCK_CERTIFICATE); break;
    case SNTEventStateBlockScope: e->set_decision(::pbv1::BLOCK_SCOPE); break;
    case SNTEventStateBlockTeamID: e->set_decision(::pbv1::BLOCK_TEAMID); break;
    case SNTEventStateBlockSigningID: e->set_decision(::pbv1::BLOCK_SIGNINGID); break;
    case SNTEventStateBlockCDHash: e->set_decision(::pbv1::BLOCK_CDHASH); break;
    case SNTEventStateAllowTransitive: return std::nullopt;
    case SNTEventStateAllowLocalBinary: return std::nullopt;
    case SNTEventStateAllowLocalSigningID: return std::nullopt;
    case SNTEventStateAllowPendingTransitive: return std::nullopt;
    case SNTEventStateBlockLongPath: return std::nullopt;
    case SNTEventStateAllow: return std::nullopt;
    case SNTEventStateBlock: return std::nullopt;
    case SNTEventStateUnknown: return std::nullopt;
    case SNTEventStateBundleBinary:
      e->set_decision(::pbv1::BUNDLE_BINARY);
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
    case SNTSigningStatusUnsigned: e->set_signing_status(::pbv1::SIGNING_STATUS_UNSIGNED); break;
    case SNTSigningStatusInvalid: e->set_signing_status(::pbv1::SIGNING_STATUS_INVALID); break;
    case SNTSigningStatusAdhoc: e->set_signing_status(::pbv1::SIGNING_STATUS_ADHOC); break;
    case SNTSigningStatusDevelopment:
      e->set_signing_status(::pbv1::SIGNING_STATUS_DEVELOPMENT);
      break;
    case SNTSigningStatusProduction:
      e->set_signing_status(::pbv1::SIGNING_STATUS_PRODUCTION);
      break;
    default: e->set_signing_status(::pbv1::SIGNING_STATUS_UNSPECIFIED); break;
  }

  for (MOLCertificate *cert in event.signingChain) {
    ::pbv1::Certificate *c = e->add_signing_chain();
    c->set_sha256(NSStringToUTF8String(cert.SHA256));
    c->set_cn(NSStringToUTF8String(cert.commonName));
    c->set_org(NSStringToUTF8String(cert.orgName));
    c->set_ou(NSStringToUTF8String(cert.orgUnit));
    c->set_valid_from([cert.validFrom timeIntervalSince1970]);
    c->set_valid_until([cert.validUntil timeIntervalSince1970]);
  }

  ::pbv1::EntitlementInfo *pb_entitlement_info = e->mutable_entitlement_info();

  santa::EncodeEntitlementsCommon(
      event.entitlements, event.entitlementsFiltered,
      ^(NSUInteger count, bool is_filtered) {
        pb_entitlement_info->set_entitlements_filtered(is_filtered);
        pb_entitlement_info->mutable_entitlements()->Reserve((int)count);
      },
      ^(NSString *entitlement, NSString *value) {
        ::pbv1::Entitlement *pb_entitlement = pb_entitlement_info->add_entitlements();
        pb_entitlement->set_key(NSStringToUTF8StringView(entitlement));
        pb_entitlement->set_value(NSStringToUTF8StringView(value));
      });

  // TODO: Add support the for Standalone Approval field so that a sync service
  // can be notified that a user self approved a binary.

  return std::make_optional(*e);
}

@end
