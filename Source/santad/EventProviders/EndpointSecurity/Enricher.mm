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

#include "Source/santad/EventProviders/EndpointSecurity/Enricher.h"

#include <EndpointSecurity/ESTypes.h>
#include <bsm/libbsm.h>
#include <grp.h>
#include <pwd.h>
#include <sys/types.h>

#include <memory>
#include <optional>

#include "Source/common/Platform.h"
#include "Source/common/SNTLogging.h"
#include "Source/common/String.h"
#include "Source/santad/EventProviders/EndpointSecurity/EnrichedTypes.h"
#include "Source/santad/ProcessTree/SNTEndpointSecurityAdapter.h"
#include "Source/santad/ProcessTree/process_tree.h"
#include "Source/santad/ProcessTree/process_tree_macos.h"

namespace santa {

Enricher::Enricher(std::shared_ptr<::santa::santad::process_tree::ProcessTree> pt)
    : username_cache_(256), groupname_cache_(256), process_tree_(std::move(pt)) {}

std::unique_ptr<EnrichedMessage> Enricher::Enrich(Message &&es_msg) {
  // TODO(mlw): Consider potential design patterns that could help reduce memory usage under load
  // (such as maybe the flyweight pattern)
  switch (es_msg->event_type) {
    case ES_EVENT_TYPE_NOTIFY_CLOSE:
      return std::make_unique<EnrichedMessage>(EnrichedClose(
          std::move(es_msg), Enrich(*es_msg->process), Enrich(*es_msg->event.close.target)));
    case ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA:
      return std::make_unique<EnrichedMessage>(EnrichedExchange(
          std::move(es_msg), Enrich(*es_msg->process), Enrich(*es_msg->event.exchangedata.file1),
          Enrich(*es_msg->event.exchangedata.file2)));
    case ES_EVENT_TYPE_NOTIFY_EXEC:
      return std::make_unique<EnrichedMessage>(EnrichedExec(
          std::move(es_msg), Enrich(*es_msg->process), Enrich(*es_msg->event.exec.target),
          (es_msg->version >= 2 && es_msg->event.exec.script)
              ? std::make_optional(Enrich(*es_msg->event.exec.script))
              : std::nullopt,
          (es_msg->version >= 3 && es_msg->event.exec.cwd)
              ? std::make_optional(Enrich(*es_msg->event.exec.cwd))
              : std::nullopt));
    case ES_EVENT_TYPE_NOTIFY_FORK:
      return std::make_unique<EnrichedMessage>(EnrichedFork(
          std::move(es_msg), Enrich(*es_msg->process), Enrich(*es_msg->event.fork.child)));
    case ES_EVENT_TYPE_NOTIFY_EXIT:
      return std::make_unique<EnrichedMessage>(
          EnrichedExit(std::move(es_msg), Enrich(*es_msg->process)));
    case ES_EVENT_TYPE_NOTIFY_LINK:
      return std::make_unique<EnrichedMessage>(
          EnrichedLink(std::move(es_msg), Enrich(*es_msg->process),
                       Enrich(*es_msg->event.link.source), Enrich(*es_msg->event.link.target_dir)));
    case ES_EVENT_TYPE_NOTIFY_RENAME: {
      if (es_msg->event.rename.destination_type == ES_DESTINATION_TYPE_NEW_PATH) {
        return std::make_unique<EnrichedMessage>(EnrichedRename(
            std::move(es_msg), Enrich(*es_msg->process), Enrich(*es_msg->event.rename.source),
            std::nullopt, Enrich(*es_msg->event.rename.destination.new_path.dir)));
      } else {
        return std::make_unique<EnrichedMessage>(EnrichedRename(
            std::move(es_msg), Enrich(*es_msg->process), Enrich(*es_msg->event.rename.source),
            Enrich(*es_msg->event.rename.destination.existing_file), std::nullopt));
      }
    }
    case ES_EVENT_TYPE_NOTIFY_UNLINK:
      return std::make_unique<EnrichedMessage>(EnrichedUnlink(
          std::move(es_msg), Enrich(*es_msg->process), Enrich(*es_msg->event.unlink.target)));
    case ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED:
      return std::make_unique<EnrichedMessage>(
          EnrichedCSInvalidated(std::move(es_msg), Enrich(*es_msg->process)));
    case ES_EVENT_TYPE_NOTIFY_CLONE:
      return std::make_unique<EnrichedMessage>(EnrichedClone(
          std::move(es_msg), Enrich(*es_msg->process), Enrich(*es_msg->event.clone.source)));
    case ES_EVENT_TYPE_NOTIFY_COPYFILE:
      return std::make_unique<EnrichedMessage>(EnrichedCopyfile(
          std::move(es_msg), Enrich(*es_msg->process), Enrich(*es_msg->event.copyfile.source)));
    case ES_EVENT_TYPE_NOTIFY_AUTHENTICATION:
      switch (es_msg->event.authentication->type) {
        case ES_AUTHENTICATION_TYPE_OD:
          return std::make_unique<EnrichedMessage>(
              EnrichedAuthenticationOD(std::move(es_msg), Enrich(*es_msg->process),
                                       Enrich(es_msg->event.authentication->data.od->instigator)));
        case ES_AUTHENTICATION_TYPE_TOUCHID:
          return std::make_unique<EnrichedMessage>(EnrichedAuthenticationTouchID(
              std::move(es_msg), Enrich(*es_msg->process),
              Enrich(es_msg->event.authentication->data.touchid->instigator),
              es_msg->event.authentication->data.touchid->has_uid
                  ? UsernameForUID(es_msg->event.authentication->data.touchid->uid.uid)
                  : std::nullopt));
        case ES_AUTHENTICATION_TYPE_TOKEN:
          return std::make_unique<EnrichedMessage>(EnrichedAuthenticationToken(
              std::move(es_msg), Enrich(*es_msg->process),
              Enrich(es_msg->event.authentication->data.token->instigator)));
        case ES_AUTHENTICATION_TYPE_AUTO_UNLOCK:
          return std::make_unique<EnrichedMessage>(EnrichedAuthenticationAutoUnlock(
              std::move(es_msg), Enrich(*es_msg->process),
              UIDForUsername(StringTokenToStringView(
                  es_msg->event.authentication->data.auto_unlock->username))));

        // Note: There is a case here where future OS versions could add new authentication types
        // that did not exist in the SDK used to build the current running version of Santa. Return
        // nullptr here to signal to the caller that event processing should not continue. Santa
        // would have to be updated and rebuilt with the new SDK in order to properly handle the new
        // types.
        default: return nullptr;
      }
    case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN:
      return std::make_unique<EnrichedMessage>(EnrichedLoginWindowSessionLogin(
          std::move(es_msg), Enrich(*es_msg->process),
          UIDForUsername(StringTokenToStringView(es_msg->event.lw_session_login->username))));
    case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT:
      return std::make_unique<EnrichedMessage>(EnrichedLoginWindowSessionLogout(
          std::move(es_msg), Enrich(*es_msg->process),
          UIDForUsername(StringTokenToStringView(es_msg->event.lw_session_logout->username))));
    case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK:
      return std::make_unique<EnrichedMessage>(EnrichedLoginWindowSessionLock(
          std::move(es_msg), Enrich(*es_msg->process),
          UIDForUsername(StringTokenToStringView(es_msg->event.lw_session_lock->username))));
    case ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK:
      return std::make_unique<EnrichedMessage>(EnrichedLoginWindowSessionUnlock(
          std::move(es_msg), Enrich(*es_msg->process),
          UIDForUsername(StringTokenToStringView(es_msg->event.lw_session_unlock->username))));
    case ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH:
      return std::make_unique<EnrichedMessage>(
          EnrichedScreenSharingAttach(std::move(es_msg), Enrich(*es_msg->process)));
    case ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH:
      return std::make_unique<EnrichedMessage>(
          EnrichedScreenSharingDetach(std::move(es_msg), Enrich(*es_msg->process)));
    case ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN:
      return std::make_unique<EnrichedMessage>(
          EnrichedOpenSSHLogin(std::move(es_msg), Enrich(*es_msg->process)));
    case ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT:
      return std::make_unique<EnrichedMessage>(
          EnrichedOpenSSHLogout(std::move(es_msg), Enrich(*es_msg->process)));
    case ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN:
      return std::make_unique<EnrichedMessage>(
          EnrichedLoginLogin(std::move(es_msg), Enrich(*es_msg->process)));
    case ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT:
      return std::make_unique<EnrichedMessage>(
          EnrichedLoginLogout(std::move(es_msg), Enrich(*es_msg->process)));
    case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD:
      return std::make_unique<EnrichedMessage>(
          EnrichedLaunchItem(std::move(es_msg), Enrich(*es_msg->process),
                             Enrich(es_msg->event.btm_launch_item_add->instigator),
                             Enrich(es_msg->event.btm_launch_item_add->app),
                             UsernameForUID(es_msg->event.btm_launch_item_add->item->uid)));
    case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE:
      return std::make_unique<EnrichedMessage>(
          EnrichedLaunchItem(std::move(es_msg), Enrich(*es_msg->process),
                             Enrich(es_msg->event.btm_launch_item_remove->instigator),
                             Enrich(es_msg->event.btm_launch_item_remove->app),
                             UsernameForUID(es_msg->event.btm_launch_item_remove->item->uid)));
    case ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED:
      return std::make_unique<EnrichedMessage>(
          EnrichedXProtectDetected(std::move(es_msg), Enrich(*es_msg->process)));
    case ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED:
      return std::make_unique<EnrichedMessage>(
          EnrichedXProtectRemediated(std::move(es_msg), Enrich(*es_msg->process)));
#if HAVE_MACOS_15
    case ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE:
      return std::make_unique<EnrichedMessage>(EnrichedGatekeeperOverride(
          std::move(es_msg), Enrich(*es_msg->process),
          es_msg->event.gatekeeper_user_override->file_type ==
                  ES_GATEKEEPER_USER_OVERRIDE_FILE_TYPE_FILE
              ? std::make_optional(Enrich(*es_msg->event.gatekeeper_user_override->file.file))
              : std::nullopt));
#endif  // HAVE_MACOS_15
#if HAVE_MACOS_15_4
    case ES_EVENT_TYPE_NOTIFY_TCC_MODIFY:
      return std::make_unique<EnrichedMessage>(EnrichedTCCModification(
          std::move(es_msg), Enrich(*es_msg->process), Enrich(es_msg->event.tcc_modify->instigator),
          Enrich(es_msg->event.tcc_modify->responsible)));
#endif  // HAVE_MACOS_15_4
    default:
      // This is a programming error
      LOGE(@"Attempting to enrich an unhandled event type: %d", es_msg->event_type);
      exit(EXIT_FAILURE);
  }
}

std::optional<EnrichedProcess> Enricher::Enrich(const es_process_t *es_proc,
                                                EnrichOptions options) {
  return es_proc ? std::make_optional<EnrichedProcess>(Enrich(*es_proc, options)) : std::nullopt;
}

EnrichedProcess Enricher::Enrich(const es_process_t &es_proc, EnrichOptions options) {
  return EnrichedProcess(
      UsernameForUID(audit_token_to_euid(es_proc.audit_token), options),
      UsernameForGID(audit_token_to_egid(es_proc.audit_token), options),
      UsernameForUID(audit_token_to_ruid(es_proc.audit_token), options),
      UsernameForGID(audit_token_to_rgid(es_proc.audit_token), options),
      Enrich(*es_proc.executable, options),
      process_tree_ ? process_tree_->ExportAnnotations(
                          santa::santad::process_tree::PidFromAuditToken(es_proc.audit_token))
                    : std::nullopt);
}

EnrichedFile Enricher::Enrich(const es_file_t &es_file, EnrichOptions options) {
  // TODO(mlw): Consider having the enricher perform file hashing. This will
  // make more sense if we start including hashes in more event types.
  return EnrichedFile(UsernameForUID(es_file.stat.st_uid, options),
                      UsernameForGID(es_file.stat.st_gid, options), std::nullopt);
}

std::optional<std::shared_ptr<std::string>> Enricher::UsernameForUID(uid_t uid,
                                                                     EnrichOptions options) {
  std::optional<std::shared_ptr<std::string>> username = username_cache_.get(uid);

  if (username.has_value()) {
    return username;
  } else if (options == EnrichOptions::kLocalOnly) {
    // If `kLocalOnly` option is set, do not attempt a lookup
    return std::nullopt;
  } else {
    struct passwd *pw = getpwuid(uid);
    if (pw) {
      username = std::make_shared<std::string>(pw->pw_name);
    } else {
      username = std::nullopt;
    }

    username_cache_.set(uid, username);

    return username;
  }
}

std::optional<std::shared_ptr<std::string>> Enricher::UsernameForGID(gid_t gid,
                                                                     EnrichOptions options) {
  std::optional<std::shared_ptr<std::string>> groupname = groupname_cache_.get(gid);

  if (groupname.has_value()) {
    return groupname;
  } else if (options == EnrichOptions::kLocalOnly) {
    // If `kLocalOnly` option is set, do not attempt a lookup
    return std::nullopt;
  } else {
    struct group *gr = getgrgid(gid);
    if (gr) {
      groupname = std::make_shared<std::string>(gr->gr_name);
    } else {
      groupname = std::nullopt;
    }

    groupname_cache_.set(gid, groupname);

    return groupname;
  }
}

std::optional<uid_t> Enricher::UIDForUsername(std::string_view username, EnrichOptions options) {
  if (options == EnrichOptions::kLocalOnly) {
    // If `kLocalOnly` option is set, do not attempt a lookup
    return std::nullopt;
  }

  struct passwd *pw = getpwnam(username.data());
  return pw ? std::make_optional(pw->pw_uid) : std::nullopt;
}

}  // namespace santa
