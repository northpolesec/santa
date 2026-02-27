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

#include "Source/santad/Logs/EndpointSecurity/Serializers/BasicString.h"

#include <DiskArbitration/DiskArbitration.h>
#include <EndpointSecurity/EndpointSecurity.h>
#import <Security/Security.h>
#include <bsm/libbsm.h>
#include <libgen.h>
#include <mach/message.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/kauth.h>
#include <sys/param.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <optional>
#include <string>

#include "Source/common/AuditUtilities.h"
#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTStoredExecutionEvent.h"
#import "Source/common/String.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/SanitizableString.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/Utilities.h"
#import "Source/santad/SNTDecisionCache.h"
#include "src/santanetd/SNDNetworkFlowsSerializer.h"

namespace santa {

static inline SanitizableString FilePath(const es_file_t *file) {
  return SanitizableString(file);
}

static NSDateFormatter *GetDateFormatter() {
  static dispatch_once_t onceToken;
  static NSDateFormatter *dateFormatter;

  dispatch_once(&onceToken, ^{
    dateFormatter = [[NSDateFormatter alloc] init];
    dateFormatter.dateFormat = @"yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";
    dateFormatter.calendar = [NSCalendar calendarWithIdentifier:NSCalendarIdentifierISO8601];
    dateFormatter.timeZone = [NSTimeZone timeZoneWithName:@"UTC"];
  });

  return dateFormatter;
}

std::string GetDecisionString(SNTEventState event_state) {
  if (event_state & SNTEventStateAllowCompilerBinary ||
      event_state & SNTEventStateAllowCompilerCDHash ||
      event_state & SNTEventStateAllowCompilerSigningID) {
    return "ALLOW_COMPILER";
  } else if (event_state & SNTEventStateAllow) {
    return "ALLOW";
  } else if (event_state & SNTEventStateBlock) {
    return "DENY";
  } else {
    return "UNKNOWN";
  }
}

std::string GetReasonString(SNTEventState event_state) {
  switch (event_state) {
    case SNTEventStateAllowBinary: return "BINARY";
    case SNTEventStateAllowLocalBinary: return "BINARY";
    case SNTEventStateAllowCompilerBinary: return "BINARY";
    case SNTEventStateAllowTransitive: return "TRANSITIVE";
    case SNTEventStateAllowPendingTransitive: return "PENDING_TRANSITIVE";
    case SNTEventStateAllowCertificate: return "CERT";
    case SNTEventStateAllowScope: return "SCOPE";
    case SNTEventStateAllowTeamID: return "TEAMID";
    case SNTEventStateAllowLocalSigningID: return "SIGNINGID";
    case SNTEventStateAllowSigningID: return "SIGNINGID";
    case SNTEventStateAllowCompilerSigningID: return "SIGNINGID";
    case SNTEventStateAllowCDHash: return "CDHASH";
    case SNTEventStateAllowCompilerCDHash: return "CDHASH";
    case SNTEventStateAllowUnknown: return "UNKNOWN";
    case SNTEventStateBlockBinary: return "BINARY";
    case SNTEventStateBlockCertificate: return "CERT";
    case SNTEventStateBlockScope: return "SCOPE";
    case SNTEventStateBlockTeamID: return "TEAMID";
    case SNTEventStateBlockSigningID: return "SIGNINGID";
    case SNTEventStateBlockCDHash: return "CDHASH";
    case SNTEventStateBlockLongPath: return "LONG_PATH";
    case SNTEventStateBlockUnknown: return "UNKNOWN";
    case SNTEventStateUnknown: return "UNKNOWN";
    case SNTEventStateAllow: return "UNKNOWN";
    case SNTEventStateBlock: return "UNKNOWN";
    case SNTEventStateBundleBinary: return "UNKNOWN";
  }

  return "UNKNOWN";
}

std::string GetModeString(SNTClientMode mode) {
  switch (mode) {
    case SNTClientModeMonitor: return "M";
    case SNTClientModeLockdown: return "L";
    case SNTClientModeStandalone: return "S";
    default: return "U";
  }
}

std::string GetAccessTypeString(es_event_type_t event_type) {
  switch (event_type) {
    case ES_EVENT_TYPE_AUTH_CLONE: return "CLONE";
    case ES_EVENT_TYPE_AUTH_COPYFILE: return "COPYFILE";
    case ES_EVENT_TYPE_AUTH_CREATE: return "CREATE";
    case ES_EVENT_TYPE_AUTH_EXCHANGEDATA: return "EXCHANGEDATA";
    case ES_EVENT_TYPE_AUTH_LINK: return "LINK";
    case ES_EVENT_TYPE_AUTH_OPEN: return "OPEN";
    case ES_EVENT_TYPE_AUTH_RENAME: return "RENAME";
    case ES_EVENT_TYPE_AUTH_TRUNCATE: return "TRUNCATE";
    case ES_EVENT_TYPE_AUTH_UNLINK: return "UNLINK";
    default: return "UNKNOWN_TYPE_" + std::to_string(event_type);
  }
}

static inline std::string GetBoolString(bool val) {
  return (val ? "true" : "false");
}

std::string GetFileAccessPolicyDecisionString(FileAccessPolicyDecision decision) {
  switch (decision) {
    case FileAccessPolicyDecision::kNoPolicy: return "NO_POLICY";
    case FileAccessPolicyDecision::kDenied: return "DENIED";
    case FileAccessPolicyDecision::kDeniedInvalidSignature: return "DENIED_INVALID_SIGNATURE";
    case FileAccessPolicyDecision::kAllowed: return "ALLOWED";
    case FileAccessPolicyDecision::kAllowedReadAccess: return "ALLOWED_READ_ACCESS";
    case FileAccessPolicyDecision::kAllowedAuditOnly: return "AUDIT_ONLY";
    default: return "UNKNOWN_DECISION_" + std::to_string((int)decision);
  }
}

static inline void AppendProcess(std::string &str, const es_process_t *es_proc,
                                 const std::string prefix = "") {
  char bname[MAXPATHLEN];
  str.append("|" + prefix + "pid=");
  str.append(std::to_string(Pid(es_proc->audit_token)));
  str.append("|" + prefix + "ppid=");
  str.append(std::to_string(es_proc->original_ppid));
  str.append("|" + prefix + "process=");
  str.append(basename_r(FilePath(es_proc->executable).Sanitized().data(), bname) ?: "");
  str.append("|" + prefix + "processpath=");
  str.append(FilePath(es_proc->executable).Sanitized());
}

static inline void AppendUserGroup(std::string &str, const audit_token_t &tok,
                                   const std::optional<std::shared_ptr<std::string>> &user,
                                   const std::optional<std::shared_ptr<std::string>> &group,
                                   const std::string prefix = "") {
  str.append("|" + prefix + "uid=");
  str.append(std::to_string((int)RealUser(tok)));
  str.append("|" + prefix + "user=");
  str.append(user.has_value() ? user->get()->c_str() : "(null)");
  str.append("|" + prefix + "gid=");
  str.append(std::to_string((int)RealGroup(tok)));
  str.append("|" + prefix + "group=");
  str.append(group.has_value() ? group->get()->c_str() : "(null)");
}

static inline void AppendEventUser(std::string &str, const es_string_token_t &user,
                                   std::optional<uid_t> uid, const std::string prefix = "event_") {
  if (user.length > 0) {
    str.append("|" + prefix + "user=");
    str.append(user.data);
  }

  if (uid.has_value()) {
    str.append("|" + prefix + "uid=");
    str.append(std::to_string((int)uid.value()));
  }
}

static inline void AppendInstigator(std::string &str, const es_process_t *es_proc,
                                    const EnrichedProcess &enriched_proc,
                                    const std::string prefix = "") {
  AppendProcess(str, es_proc, prefix);
  AppendUserGroup(str, es_proc->audit_token, enriched_proc.real_user(), enriched_proc.real_group(),
                  prefix);
}

static inline void AppendInstigator(std::string &str, const EnrichedEventType &event,
                                    const std::string prefix = "") {
  AppendInstigator(str, event->process, event.instigator(), prefix);
}

static inline void AppendEventUser(std::string &str,
                                   const std::optional<std::shared_ptr<std::string>> &user,
                                   uid_t uid, const std::string prefix = "event_") {
  es_string_token_t user_token = {.length = user.has_value() ? user.value()->length() : 0,
                                  .data = user.has_value() ? user.value()->c_str() : NULL};

  AppendEventUser(str, user_token, std::make_optional<uid_t>(uid), prefix);
}

static inline void AppendGraphicalSession(std::string &str, es_graphical_session_id_t session_id) {
  str.append("|graphical_session_id=");
  str.append(std::to_string(session_id));
}

static inline void AppendSocketAddress(std::string &str, es_address_type_t type,
                                       es_string_token_t addr) {
  str.append("|address_type=");
  switch (type) {
    case ES_ADDRESS_TYPE_NONE: str.append("none"); break;
    case ES_ADDRESS_TYPE_IPV4: str.append("ipv4"); break;
    case ES_ADDRESS_TYPE_IPV6: str.append("ipv6"); break;
    case ES_ADDRESS_TYPE_NAMED_SOCKET: str.append("named_socket"); break;
    default: str.append("unknown"); break;
  }

  if (addr.length > 0) {
    str.append("|address=");
    str.append(SanitizableString(addr).Sanitized());
  }
}

static inline std::string GetOpenSSHLoginResult(std::string &str,
                                                es_openssh_login_result_type_t result) {
  switch (result) {
    case ES_OPENSSH_LOGIN_EXCEED_MAXTRIES: return "LOGIN_EXCEED_MAXTRIES";
    case ES_OPENSSH_LOGIN_ROOT_DENIED: return "LOGIN_ROOT_DENIED";
    case ES_OPENSSH_AUTH_SUCCESS: return "AUTH_SUCCESS";
    case ES_OPENSSH_AUTH_FAIL_NONE: return "AUTH_FAIL_NONE";
    case ES_OPENSSH_AUTH_FAIL_PASSWD: return "AUTH_FAIL_PASSWD";
    case ES_OPENSSH_AUTH_FAIL_KBDINT: return "AUTH_FAIL_KBDINT";
    case ES_OPENSSH_AUTH_FAIL_PUBKEY: return "AUTH_FAIL_PUBKEY";
    case ES_OPENSSH_AUTH_FAIL_HOSTBASED: return "AUTH_FAIL_HOSTBASED";
    case ES_OPENSSH_AUTH_FAIL_GSSAPI: return "AUTH_FAIL_GSSAPI";
    case ES_OPENSSH_INVALID_USER: return "INVALID_USER";
    default: return "UNKNOWN";
  }
}

static char *FormattedDateString(char *buf, size_t len) {
  struct timeval tv;
  struct tm tm;

  gettimeofday(&tv, NULL);
  gmtime_r(&tv.tv_sec, &tm);

  strftime(buf, len, "%Y-%m-%dT%H:%M:%S", &tm);
  snprintf(buf, len, "%s.%03dZ", buf, tv.tv_usec / 1000);

  return buf;
}

std::shared_ptr<BasicString> BasicString::Create(std::shared_ptr<EndpointSecurityAPI> esapi,
                                                 SNTDecisionCache *decision_cache,
                                                 bool prefix_time_name) {
  return std::make_shared<BasicString>(esapi, decision_cache, prefix_time_name);
}

BasicString::BasicString(std::shared_ptr<EndpointSecurityAPI> esapi,
                         SNTDecisionCache *decision_cache, bool prefix_time_name)
    : Serializer(std::move(decision_cache)), esapi_(esapi), prefix_time_name_(prefix_time_name) {}

std::string BasicString::CreateDefaultString(size_t reserved_size) {
  std::string str;
  str.reserve(1024);

  if (prefix_time_name_) {
    char buf[32];

    str.append("[");
    str.append(FormattedDateString(buf, sizeof(buf)));
    str.append("] I santad: ");
  }

  return str;
}

std::vector<uint8_t> BasicString::FinalizeString(std::string &str) {
  if (EnableMachineIDDecoration()) {
    str.append("|machineid=");
    str.append(*MachineID());
  }
  str.append("\n");

  std::vector<uint8_t> vec(str.length());
  std::copy(str.begin(), str.end(), vec.begin());
  return vec;
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedClose &msg) {
  std::string str = CreateDefaultString();

  str.append("action=WRITE|path=");
  str.append(FilePath(msg->event.close.target).Sanitized());

  AppendInstigator(str, msg);

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedExchange &msg) {
  std::string str = CreateDefaultString();

  str.append("action=EXCHANGE|path=");
  str.append(FilePath(msg->event.exchangedata.file1).Sanitized());
  str.append("|newpath=");
  str.append(FilePath(msg->event.exchangedata.file2).Sanitized());

  AppendInstigator(str, msg);

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedExec &msg, SNTCachedDecision *cd) {
  std::string str = CreateDefaultString(1024);  // EXECs tend to be bigger, reserve more space.

  str.append("action=EXEC|decision=");
  str.append(GetDecisionString(cd.decision));
  str.append("|reason=");
  str.append(GetReasonString(cd.decision));

  if (cd.decisionExtra) {
    str.append("|explain=");
    str.append([cd.decisionExtra UTF8String]);
  }

  if (cd.sha256) {
    str.append("|sha256=");
    str.append([cd.sha256 UTF8String]);
  }

  if (cd.certSHA256) {
    str.append("|cert_sha256=");
    str.append([cd.certSHA256 UTF8String]);
    str.append("|cert_cn=");
    str.append(SanitizableString(cd.certCommonName).Sanitized());
  }

  if (cd.teamID.length) {
    str.append("|teamid=");
    str.append([NonNull(cd.teamID) UTF8String]);
  }

  if (cd.quarantineURL) {
    str.append("|quarantine_url=");
    str.append(SanitizableString(cd.quarantineURL).Sanitized());
  }

  str.append("|pid=");
  str.append(std::to_string(Pid(msg->event.exec.target->audit_token)));
  str.append("|pidversion=");
  str.append(std::to_string(Pidversion(msg->event.exec.target->audit_token)));
  str.append("|ppid=");
  str.append(std::to_string(msg->event.exec.target->original_ppid));

  AppendUserGroup(str, msg->event.exec.target->audit_token, msg.instigator().real_user(),
                  msg.instigator().real_group());

  str.append("|mode=");
  str.append(GetModeString(cd.decisionClientMode));
  str.append("|path=");
  str.append(FilePath(msg->event.exec.target->executable).Sanitized());

  NSString *origPath = santa::OriginalPathForTranslocation(msg->event.exec.target);
  if (origPath) {
    str.append("|origpath=");
    str.append(SanitizableString(origPath).Sanitized());
  }

  uint32_t argCount = esapi_->ExecArgCount(&msg->event.exec);
  if (argCount > 0) {
    str.append("|args=");
    for (uint32_t i = 0; i < argCount; i++) {
      if (i != 0) {
        str.append(" ");
      }

      str.append(SanitizableString(esapi_->ExecArg(&msg->event.exec, i)).Sanitized());
    }
  }

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedExit &msg) {
  std::string str = CreateDefaultString();

  str.append("action=EXIT|pid=");
  str.append(std::to_string(Pid(msg->process->audit_token)));
  str.append("|pidversion=");
  str.append(std::to_string(Pidversion(msg->process->audit_token)));
  str.append("|ppid=");
  str.append(std::to_string(msg->process->original_ppid));
  str.append("|uid=");
  str.append(std::to_string((int)RealUser(msg->process->audit_token)));
  str.append("|gid=");
  str.append(std::to_string((int)RealGroup(msg->process->audit_token)));

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedFork &msg) {
  std::string str = CreateDefaultString();

  str.append("action=FORK|pid=");
  str.append(std::to_string(Pid(msg->event.fork.child->audit_token)));
  str.append("|pidversion=");
  str.append(std::to_string(Pidversion(msg->event.fork.child->audit_token)));
  str.append("|ppid=");
  str.append(std::to_string(msg->event.fork.child->original_ppid));
  str.append("|uid=");
  str.append(std::to_string((int)RealUser(msg->event.fork.child->audit_token)));
  str.append("|gid=");
  str.append(std::to_string((int)RealGroup(msg->event.fork.child->audit_token)));

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedLink &msg) {
  std::string str = CreateDefaultString();

  str.append("action=LINK|path=");
  str.append(FilePath(msg->event.link.source).Sanitized());
  str.append("|newpath=");
  str.append(FilePath(msg->event.link.target_dir).Sanitized());
  str.append("/");
  str.append(SanitizableString(msg->event.link.target_filename).Sanitized());

  AppendInstigator(str, msg);

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedRename &msg) {
  std::string str = CreateDefaultString();

  str.append("action=RENAME|path=");
  str.append(FilePath(msg->event.rename.source).Sanitized());
  str.append("|newpath=");

  switch (msg->event.rename.destination_type) {
    case ES_DESTINATION_TYPE_EXISTING_FILE:
      str.append(FilePath(msg->event.rename.destination.existing_file).Sanitized());
      break;
    case ES_DESTINATION_TYPE_NEW_PATH:
      str.append(FilePath(msg->event.rename.destination.new_path.dir).Sanitized());
      str.append("/");
      str.append(SanitizableString(msg->event.rename.destination.new_path.filename).Sanitized());
      break;
    default: str.append("(null)"); break;
  }

  AppendInstigator(str, msg);

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedUnlink &msg) {
  std::string str = CreateDefaultString();

  str.append("action=DELETE|path=");
  str.append(FilePath(msg->event.unlink.target).Sanitized());

  AppendInstigator(str, msg);

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedCSInvalidated &msg) {
  std::string str = CreateDefaultString();

  str.append("action=CODESIGNING_INVALIDATED");
  AppendInstigator(str, msg);
  str.append("|codesigning_flags=");
  str.append([NSString stringWithFormat:@"0x%08x", msg->process->codesigning_flags].UTF8String);
  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedClone &msg) {
  std::string str = CreateDefaultString();

  str.append("action=CLONE|source=");
  str.append(FilePath(msg->event.clone.source).Sanitized());
  str.append("|target=");
  str.append(FilePath(msg->event.clone.target_dir).Sanitized());
  str.append("/");
  str.append(SanitizableString(msg->event.clone.target_name).Sanitized());
  AppendInstigator(str, msg);

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedCopyfile &msg) {
  std::string str = CreateDefaultString();

  str.append("action=COPYFILE|source=");
  str.append(FilePath(msg->event.copyfile.source).Sanitized());
  str.append("|target=");
  str.append(FilePath(msg->event.copyfile.target_dir).Sanitized());
  str.append("/");
  str.append(SanitizableString(msg->event.copyfile.target_name).Sanitized());
  AppendInstigator(str, msg);

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedLoginWindowSessionLogin &msg) {
  std::string str = CreateDefaultString();

  str.append("action=LOGIN_WINDOW_SESSION_LOGIN");
  AppendInstigator(str, msg);
  AppendEventUser(str, msg->event.lw_session_login->username, msg.UID());
  AppendGraphicalSession(str, msg->event.lw_session_login->graphical_session_id);

  return FinalizeString(str);
};

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedLoginWindowSessionLogout &msg) {
  std::string str = CreateDefaultString();

  str.append("action=LOGIN_WINDOW_SESSION_LOGOUT");
  AppendInstigator(str, msg);
  AppendEventUser(str, msg->event.lw_session_logout->username, msg.UID());
  AppendGraphicalSession(str, msg->event.lw_session_logout->graphical_session_id);

  return FinalizeString(str);
};

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedLoginWindowSessionLock &msg) {
  std::string str = CreateDefaultString();

  str.append("action=LOGIN_WINDOW_SESSION_LOCK");
  AppendInstigator(str, msg);
  AppendEventUser(str, msg->event.lw_session_lock->username, msg.UID());
  AppendGraphicalSession(str, msg->event.lw_session_lock->graphical_session_id);

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedLoginWindowSessionUnlock &msg) {
  std::string str = CreateDefaultString();

  str.append("action=LOGIN_WINDOW_SESSION_UNLOCK");
  AppendInstigator(str, msg);
  AppendEventUser(str, msg->event.lw_session_unlock->username, msg.UID());
  AppendGraphicalSession(str, msg->event.lw_session_unlock->graphical_session_id);

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedScreenSharingAttach &msg) {
  std::string str = CreateDefaultString();

  str.append("action=SCREEN_SHARING_ATTACH|success=");
  str.append(msg->event.screensharing_attach->success ? "true" : "false");

  AppendSocketAddress(str, msg->event.screensharing_attach->source_address_type,
                      msg->event.screensharing_attach->source_address);

  if (msg->event.screensharing_attach->viewer_appleid.length > 0) {
    str.append("|viewer=");
    str.append(SanitizableString(msg->event.screensharing_attach->viewer_appleid).Sanitized());
  }

  if (msg->event.screensharing_attach->authentication_type.length > 0) {
    str.append("|auth_type=");
    str.append(SanitizableString(msg->event.screensharing_attach->authentication_type).Sanitized());
  }

  if (msg->event.screensharing_attach->authentication_username.length > 0) {
    str.append("|auth_user=");
    str.append(
        SanitizableString(msg->event.screensharing_attach->authentication_username).Sanitized());
  }

  if (msg->event.screensharing_attach->session_username.length > 0) {
    str.append("|session_user=");
    str.append(SanitizableString(msg->event.screensharing_attach->session_username).Sanitized());
  }

  str.append("|existing_session=");
  str.append(msg->event.screensharing_attach->existing_session ? "true" : "false");

  AppendInstigator(str, msg);
  AppendGraphicalSession(str, msg->event.screensharing_attach->graphical_session_id);

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedScreenSharingDetach &msg) {
  std::string str = CreateDefaultString();

  str.append("action=SCREEN_SHARING_DETACH");

  AppendSocketAddress(str, msg->event.screensharing_detach->source_address_type,
                      msg->event.screensharing_detach->source_address);

  if (msg->event.screensharing_detach->viewer_appleid.length > 0) {
    str.append("|viewer=");
    str.append(SanitizableString(msg->event.screensharing_detach->viewer_appleid).Sanitized());
  }

  AppendInstigator(str, msg);
  AppendGraphicalSession(str, msg->event.screensharing_detach->graphical_session_id);

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedOpenSSHLogin &msg) {
  std::string str = CreateDefaultString();

  str.append("action=OPENSSH_LOGIN|success=");
  str.append(msg->event.openssh_login->success ? "true" : "false");
  str.append("|result_type=");
  str.append(GetOpenSSHLoginResult(str, msg->event.openssh_login->result_type));

  AppendSocketAddress(str, msg->event.openssh_login->source_address_type,
                      msg->event.openssh_login->source_address);
  AppendInstigator(str, msg);
  AppendEventUser(str, msg->event.openssh_login->username,
                  msg->event.openssh_login->has_uid
                      ? std::make_optional<uid_t>(msg->event.openssh_login->uid.uid)
                      : std::nullopt);

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedOpenSSHLogout &msg) {
  std::string str = CreateDefaultString();

  str.append("action=OPENSSH_LOGOUT");

  AppendSocketAddress(str, msg->event.openssh_logout->source_address_type,
                      msg->event.openssh_logout->source_address);
  AppendInstigator(str, msg);
  AppendEventUser(str, msg->event.openssh_logout->username,
                  std::make_optional<uid_t>(msg->event.openssh_logout->uid));

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedLoginLogin &msg) {
  std::string str = CreateDefaultString();

  str.append("action=LOGIN|success=");
  str.append(msg->event.login_login->success ? "true" : "false");
  if (!msg->event.login_login->success) {
    str.append("|failure=");
    str.append(SanitizableString(msg->event.login_login->failure_message).Sanitized());
  }

  AppendInstigator(str, msg);
  AppendEventUser(str, msg->event.login_login->username,
                  msg->event.login_login->has_uid
                      ? std::make_optional<uid_t>(msg->event.login_login->uid.uid)
                      : std::nullopt);

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedLoginLogout &msg) {
  std::string str = CreateDefaultString();

  str.append("action=LOGOUT");

  AppendInstigator(str, msg);
  AppendEventUser(str, msg->event.login_logout->username,
                  std::make_optional<uid_t>(msg->event.login_logout->uid));

  return FinalizeString(str);
}

static void AppendEventInstigatorOrFallback(std::string &str,
                                            const EnrichedEventWithInstigator &event,
                                            std::string prefix = "auth_") {
  if (event.EventInstigator() && event.EnrichedEventInstigator().has_value()) {
    AppendInstigator(str, event.EventInstigator(), event.EnrichedEventInstigator().value(), prefix);
  } else if (event->version >= 8) {
    if (event.EventInstigatorToken().has_value()) {
      str.append("|" + prefix + "pid=");
      str.append(std::to_string(Pid(event.EventInstigatorToken().value())));
    }
    if (event.EventInstigatorToken().has_value()) {
      str.append("|" + prefix + "pidver=");
      str.append(std::to_string(Pidversion(event.EventInstigatorToken().value())));
    }
  }
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedAuthenticationOD &msg) {
  std::string str = CreateDefaultString();

  str.append("action=AUTHENTICATION_OD");
  str.append("|success=");
  str.append(msg->event.authentication->success ? "true" : "false");

  AppendInstigator(str, msg);
  AppendEventInstigatorOrFallback(str, msg);

  str.append("|record_type=");
  str.append(msg->event.authentication->data.od->record_type.data);
  str.append("|record_name=");
  str.append(msg->event.authentication->data.od->record_name.data);
  str.append("|node_name=");
  str.append(msg->event.authentication->data.od->node_name.data);

  // db_path is optional
  if (msg->event.authentication->data.od->db_path.length > 0) {
    str.append("|db_path=");
    str.append(msg->event.authentication->data.od->db_path.data);
  }

  return FinalizeString(str);
}

std::string GetAuthenticationTouchIDModeString(es_touchid_mode_t mode) {
  switch (mode) {
    case ES_TOUCHID_MODE_VERIFICATION: return "VERIFICATION";
    case ES_TOUCHID_MODE_IDENTIFICATION: return "IDENTIFICATION";
    default: return "UNKNOWN";
  }
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedAuthenticationTouchID &msg) {
  std::string str = CreateDefaultString();

  str.append("action=AUTHENTICATION_TOUCHID");
  str.append("|success=");
  str.append(msg->event.authentication->success ? "true" : "false");

  AppendInstigator(str, msg);
  AppendEventInstigatorOrFallback(str, msg);

  str.append("|touchid_mode=");
  str.append(
      GetAuthenticationTouchIDModeString(msg->event.authentication->data.touchid->touchid_mode));

  if (msg->event.authentication->data.touchid->has_uid) {
    AppendEventUser(str, msg.Username(), msg->event.authentication->data.touchid->uid.uid);
  }

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedAuthenticationToken &msg) {
  std::string str = CreateDefaultString();

  str.append("action=AUTHENTICATION_TOKEN");
  str.append("|success=");
  str.append(msg->event.authentication->success ? "true" : "false");

  AppendInstigator(str, msg);
  AppendEventInstigatorOrFallback(str, msg);

  str.append("|pubkey_hash=");
  str.append(msg->event.authentication->data.token->pubkey_hash.data);
  str.append("|token_id=");
  str.append(msg->event.authentication->data.token->token_id.data);

  // kerberos_principal is optional
  if (msg->event.authentication->data.token->kerberos_principal.length > 0) {
    str.append("|kerberos_principal=");
    str.append(msg->event.authentication->data.token->kerberos_principal.data);
  }

  return FinalizeString(str);
}

std::string GetAuthenticationAutoUnlockTypeString(es_auto_unlock_type_t type) {
  switch (type) {
    case ES_AUTO_UNLOCK_MACHINE_UNLOCK: return "MACHINE_UNLOCK";
    case ES_AUTO_UNLOCK_AUTH_PROMPT: return "AUTH_PROMPT";
    default: return "UNKNOWN";
  }
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedAuthenticationAutoUnlock &msg) {
  std::string str = CreateDefaultString();

  str.append("action=AUTHENTICATION_AUTO_UNLOCK");
  str.append("|success=");
  str.append(msg->event.authentication->success ? "true" : "false");

  AppendInstigator(str, msg);
  AppendEventUser(str, msg->event.authentication->data.auto_unlock->username, msg.UID());

  str.append("|type=");
  str.append(
      GetAuthenticationAutoUnlockTypeString(msg->event.authentication->data.auto_unlock->type));

  return FinalizeString(str);
}

std::string GetBTMLaunchItemTypeString(es_btm_item_type_t item_type) {
  switch (item_type) {
    case ES_BTM_ITEM_TYPE_USER_ITEM: return "USER_ITEM";
    case ES_BTM_ITEM_TYPE_APP: return "APP";
    case ES_BTM_ITEM_TYPE_LOGIN_ITEM: return "LOGIN_ITEM";
    case ES_BTM_ITEM_TYPE_AGENT: return "AGENT";
    case ES_BTM_ITEM_TYPE_DAEMON: return "DAEMON";
    default: return "UNKNOWN";
  }
}

std::vector<uint8_t> BasicString::SerializeMessageLaunchItemAdd(const EnrichedLaunchItem &msg) {
  assert(msg->event_type == ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD);
  const es_event_btm_launch_item_add_t *btm = msg->event.btm_launch_item_add;

  std::string str = CreateDefaultString();

  str.append("action=LAUNCH_ITEM_ADD|item_type=");
  str.append(GetBTMLaunchItemTypeString(btm->item->item_type));
  str.append("|legacy=");
  str.append(GetBoolString(btm->item->legacy));
  str.append("|managed=");
  str.append(GetBoolString(btm->item->managed));
  AppendEventUser(str, msg.Username(), btm->item->uid, "item_");

  NSString *path = ConcatPrefixIfRelativePath(btm->executable_path, btm->item->app_url);
  if (path) {
    str.append("|exec_path=");
    str.append(NSStringToUTF8StringView(path));
  }

  path = ConcatPrefixIfRelativePath(btm->item->item_url, btm->item->app_url);
  if (path) {
    str.append("|item_path=");
    str.append(NSStringToUTF8StringView(path));
  }

  if (btm->item->app_url.length > 0) {
    str.append("|app_path=");
    str.append(NSStringToUTF8StringView(NormalizePath(btm->item->app_url)));
  }

  // Note: The string for this event is already very long. Choosing for now to not
  // serialize potential app info. If desired, users should use the proto log type.
  AppendEventInstigatorOrFallback(str, msg, "event_");
  AppendInstigator(str, msg);

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeMessageLaunchItemRemove(const EnrichedLaunchItem &msg) {
  assert(msg->event_type == ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE);
  const es_event_btm_launch_item_remove_t *btm = msg->event.btm_launch_item_remove;

  std::string str = CreateDefaultString();

  str.append("action=LAUNCH_ITEM_REMOVE|item_type=");
  str.append(GetBTMLaunchItemTypeString(btm->item->item_type));
  str.append("|legacy=");
  str.append(GetBoolString(btm->item->legacy));
  str.append("|managed=");
  str.append(GetBoolString(btm->item->managed));
  AppendEventUser(str, msg.Username(), btm->item->uid, "item_");

  NSString *path = ConcatPrefixIfRelativePath(btm->item->item_url, btm->item->app_url);
  if (path) {
    str.append("|item_path=");
    str.append(NSStringToUTF8StringView(path));
  }

  if (btm->item->app_url.length > 0) {
    str.append("|app_path=");
    str.append(NSStringToUTF8StringView(NormalizePath(btm->item->app_url)));
  }

  // Note: The string for this event is already very long. Choosing for now to not
  // serialize potential app info. If desired, users should use the proto log type.
  AppendEventInstigatorOrFallback(str, msg, "event_");
  AppendInstigator(str, msg);

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedLaunchItem &msg) {
  if (msg->event_type == ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD) {
    return SerializeMessageLaunchItemAdd(msg);
  } else if (msg->event_type == ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE) {
    return SerializeMessageLaunchItemRemove(msg);
  } else {
    LOGE(@"Unexpected event type for EnrichedLaunchItem: %d", msg->event_type);
    std::abort();
  }
}

static inline void AppendStringToken(std::string &str, std::string key, es_string_token_t val) {
  if (val.length > 0) {
    str.append(key);
    str.append(val.data);
  }
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedXProtectDetected &msg) {
  const es_event_xp_malware_detected_t *xp = msg->event.xp_malware_detected;
  std::string str = CreateDefaultString();

  str.append("action=XPROTECT_DETECTED");

  AppendStringToken(str, "|signature_version=", xp->signature_version);
  AppendStringToken(str, "|malware_identifier=", xp->malware_identifier);
  AppendStringToken(str, "|incident_identifier=", xp->incident_identifier);
  AppendStringToken(str, "|detected_path=", xp->detected_path);

  AppendInstigator(str, msg);

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedXProtectRemediated &msg) {
  const es_event_xp_malware_remediated_t *xp = msg->event.xp_malware_remediated;
  std::string str = CreateDefaultString();

  str.append("action=XPROTECT_REMEDIATED");

  AppendStringToken(str, "|signature_version=", xp->signature_version);
  AppendStringToken(str, "|malware_identifier=", xp->malware_identifier);
  AppendStringToken(str, "|incident_identifier=", xp->incident_identifier);
  AppendStringToken(str, "|action_type=", xp->action_type);
  str.append("|success=");
  str.append(GetBoolString(xp->success));
  AppendStringToken(str, "|result_description=", xp->result_description);
  AppendStringToken(str, "|remediated_path=", xp->remediated_path);
  if (xp->remediated_process_audit_token) {
    str.append("|remediated_pid=");
    str.append(std::to_string(Pid(*xp->remediated_process_audit_token)));
  }

  return FinalizeString(str);
}

#if HAVE_MACOS_15

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedGatekeeperOverride &msg) {
  std::string str = CreateDefaultString();
  es_event_gatekeeper_user_override_t *gk = msg->event.gatekeeper_user_override;

  str.append("action=GATEKEEPER_OVERRIDE|target=");
  switch (gk->file_type) {
    case ES_GATEKEEPER_USER_OVERRIDE_FILE_TYPE_PATH:
      str.append(SanitizableString(gk->file.file_path).Sanitized());
      break;
    case ES_GATEKEEPER_USER_OVERRIDE_FILE_TYPE_FILE:
      str.append(FilePath(gk->file.file).Sanitized());
      break;
    default: break;
  }

  if (gk->sha256) {
    str.append("|hash=");
    str.append(BufToHexString(*gk->sha256, sizeof(*gk->sha256)));
  }

  if (gk->signing_info) {
    if (gk->signing_info->team_id.length > 0) {
      str.append("|team_id=");
      str.append(gk->signing_info->team_id.data);
    }
    if (gk->signing_info->signing_id.length > 0) {
      str.append("|signing_id=");
      str.append(SanitizableString(gk->signing_info->signing_id).Sanitized());
    }
    str.append("|cdhash=");
    str.append(BufToHexString(gk->signing_info->cdhash, sizeof(gk->signing_info->cdhash)));
  }

  AppendInstigator(str, msg);

  return FinalizeString(str);
}

#endif  // HAVE_MACOS_15

#if HAVE_MACOS_15_4

std::string GetTCCIdentityTypeString(es_tcc_identity_type_t id_type) {
  switch (id_type) {
    case ES_TCC_IDENTITY_TYPE_BUNDLE_ID: return "BUNDLE_ID";
    case ES_TCC_IDENTITY_TYPE_EXECUTABLE_PATH: return "EXECUTABLE_PATH";
    case ES_TCC_IDENTITY_TYPE_POLICY_ID: return "POLICY_ID";
    case ES_TCC_IDENTITY_TYPE_FILE_PROVIDER_DOMAIN_ID: return "FILE_PROVIDER_DOMAIN_ID";
    default: return "UNKNOWN";
  }
}

std::string GetTCCEventTypeString(es_tcc_event_type_t event_type) {
  switch (event_type) {
    case ES_TCC_EVENT_TYPE_CREATE: return "CREATE";
    case ES_TCC_EVENT_TYPE_MODIFY: return "MODIFY";
    case ES_TCC_EVENT_TYPE_DELETE: return "DELETE";
    default: return "UNKNOWN";
  }
}

std::string GetTCCAuthorizationRightString(es_tcc_authorization_right_t auth_right) {
  switch (auth_right) {
    case ES_TCC_AUTHORIZATION_RIGHT_DENIED: return "DENIED";
    case ES_TCC_AUTHORIZATION_RIGHT_UNKNOWN: return "UNKNOWN";
    case ES_TCC_AUTHORIZATION_RIGHT_ALLOWED: return "ALLOWED";
    case ES_TCC_AUTHORIZATION_RIGHT_LIMITED: return "LIMITED";
    case ES_TCC_AUTHORIZATION_RIGHT_ADD_MODIFY_ADDED: return "ADD_MODIFY_ADDED";
    case ES_TCC_AUTHORIZATION_RIGHT_SESSION_PID: return "SESSION_PID";
    case ES_TCC_AUTHORIZATION_RIGHT_LEARN_MORE: return "LEARN_MORE";
    default: return "UNKNOWN";
  }
}

std::string GetTCCAuthorizationReasonString(es_tcc_authorization_reason_t auth_reason) {
  switch (auth_reason) {
    case ES_TCC_AUTHORIZATION_REASON_NONE: return "NONE";
    case ES_TCC_AUTHORIZATION_REASON_ERROR: return "ERROR";
    case ES_TCC_AUTHORIZATION_REASON_USER_CONSENT: return "USER_CONSENT";
    case ES_TCC_AUTHORIZATION_REASON_USER_SET: return "USER_SET";
    case ES_TCC_AUTHORIZATION_REASON_SYSTEM_SET: return "SYSTEM_SET";
    case ES_TCC_AUTHORIZATION_REASON_SERVICE_POLICY: return "SERVICE_POLICY";
    case ES_TCC_AUTHORIZATION_REASON_MDM_POLICY: return "MDM_POLICY";
    case ES_TCC_AUTHORIZATION_REASON_SERVICE_OVERRIDE_POLICY: return "SERVICE_OVERRIDE_POLICY";
    case ES_TCC_AUTHORIZATION_REASON_MISSING_USAGE_STRING: return "MISSING_USAGE_STRING";
    case ES_TCC_AUTHORIZATION_REASON_PROMPT_TIMEOUT: return "PROMPT_TIMEOUT";
    case ES_TCC_AUTHORIZATION_REASON_PREFLIGHT_UNKNOWN: return "PREFLIGHT_UNKNOWN";
    case ES_TCC_AUTHORIZATION_REASON_ENTITLED: return "ENTITLED";
    case ES_TCC_AUTHORIZATION_REASON_APP_TYPE_POLICY: return "APP_TYPE_POLICY";
    case ES_TCC_AUTHORIZATION_REASON_PROMPT_CANCEL: return "PROMPT_CANCEL";
    default: return "UNKNOWN";
  }
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedTCCModification &msg) {
  std::string str = CreateDefaultString();

  str.append("action=TCC_MODIFICATION");

  str.append("|event_type=");
  str.append(GetTCCEventTypeString(msg->event.tcc_modify->update_type));

  str.append("|service=");
  str.append(msg->event.tcc_modify->service.data);
  str.append("|identity=");
  str.append(SanitizableString(msg->event.tcc_modify->identity).Sanitized());
  str.append("|identity_type=");
  str.append(GetTCCIdentityTypeString(msg->event.tcc_modify->identity_type));
  str.append("|auth_right=");
  str.append(GetTCCAuthorizationRightString(msg->event.tcc_modify->right));
  str.append("|auth_reason=");
  str.append(GetTCCAuthorizationReasonString(msg->event.tcc_modify->reason));

  // Note: The string for this event is already very long. Choosing for now to
  // not serialize potential responsible proc info. If desired, users should
  // use the proto log type.
  AppendEventInstigatorOrFallback(str, msg, "event_");
  AppendInstigator(str, msg);

  return FinalizeString(str);
}

#endif  // HAVE_MACOS_15_4

std::vector<uint8_t> BasicString::SerializeNetworkFlows(SNDProcessFlows *processFlows,
                                                        struct timespec window_start,
                                                        struct timespec window_end,
                                                        SNTCachedDecision *cd) {
  std::string line = CreateDefaultString();
  line += santanetd::FormatNetworkFlowsBasicString(processFlows, cd);
  return FinalizeString(line);
}

std::vector<uint8_t> BasicString::SerializeFileAccess(
    const std::string &policy_version, const std::string &policy_name, const Message &msg,
    const EnrichedProcess &enriched_process, size_t target_index,
    std::optional<santa::EnrichedFile> enriched_event_target, FileAccessPolicyDecision decision,
    std::string_view operation_id) {
  std::string str = CreateDefaultString();

  str.append("action=FILE_ACCESS|policy_version=");
  str.append(policy_version);
  str.append("|policy_name=");
  str.append(policy_name);
  str.append("|path=");
  if (msg.HasPathTarget(target_index)) {
    str.append(msg.PathTargetAtIndex(target_index).path);
  } else {
    // This shouldn't be possible with real data
    str.append("(error)");
  }
  str.append("|access_type=");
  str.append(GetAccessTypeString(msg->event_type));
  str.append("|decision=");
  str.append(GetFileAccessPolicyDecisionString(decision));
  str.append("|operation_id=");
  str.append(operation_id);

  AppendProcess(str, msg->process);
  AppendUserGroup(str, msg->process->audit_token, enriched_process.real_user(),
                  enriched_process.real_group());

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeAllowlist(const Message &msg,
                                                     const std::string_view hash) {
  std::string str = CreateDefaultString();

  str.append("action=ALLOWLIST|pid=");
  str.append(std::to_string(Pid(msg->process->audit_token)));
  str.append("|pidversion=");
  str.append(std::to_string(Pidversion(msg->process->audit_token)));
  str.append("|path=");
  str.append(FilePath(santa::GetAllowListTargetFile(msg)).Sanitized());
  str.append("|sha256=");
  str.append(hash);

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeBundleHashingEvent(SNTStoredExecutionEvent *event) {
  std::string str = CreateDefaultString();

  str.append("action=BUNDLE|sha256=");
  str.append([NonNull(event.fileSHA256) UTF8String]);
  str.append("|bundlehash=");
  str.append([NonNull(event.fileBundleHash) UTF8String]);
  str.append("|bundlename=");
  str.append([NonNull(event.fileBundleName) UTF8String]);
  str.append("|bundleid=");
  str.append([NonNull(event.fileBundleID) UTF8String]);
  str.append("|bundlepath=");
  str.append([NonNull(event.fileBundlePath) UTF8String]);
  str.append("|path=");
  str.append([NonNull(event.filePath) UTF8String]);

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeDiskAppeared(NSDictionary *props, bool allowed) {
  NSString *dmg_path = nil;
  NSString *serial = nil;
  if ([props[@"DADeviceModel"] isEqual:@"Disk Image"]) {
    dmg_path = santa::DiskImageForDevice(props[@"DADevicePath"]);
  } else {
    serial = santa::SerialForDevice(props[@"DADevicePath"]);
  }

  NSString *model = [NSString stringWithFormat:@"%@ %@", NonNull(props[@"DADeviceVendor"]),
                                               NonNull(props[@"DADeviceModel"])];
  model = [model stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];

  NSString *appearanceDateString = [GetDateFormatter()
      stringFromDate:[NSDate dateWithTimeIntervalSinceReferenceDate:[props[@"DAAppearanceTime"]
                                                                        doubleValue]]];

  std::string str = CreateDefaultString();
  if (allowed) {
    str.append("action=DISKAPPEAR");
  } else {
    str.append("action=DISK_BLOCKED");
  }
  str.append("|mount=");
  str.append([NonNull([props[@"DAVolumePath"] path]) UTF8String]);
  str.append("|volume=");
  str.append([NonNull(props[@"DAVolumeName"]) UTF8String]);
  str.append("|bsdname=");
  str.append([NonNull(props[@"DAMediaBSDName"]) UTF8String]);
  str.append("|fs=");
  str.append([NonNull(props[@"DAVolumeKind"]) UTF8String]);
  str.append("|model=");
  str.append([NonNull(model) UTF8String]);
  str.append("|serial=");
  str.append([NonNull(serial) UTF8String]);
  str.append("|bus=");
  str.append([NonNull(props[@"DADeviceProtocol"]) UTF8String]);
  str.append("|dmgpath=");
  str.append([NonNull(dmg_path) UTF8String]);
  str.append("|appearance=");
  str.append([NonNull(appearanceDateString) UTF8String]);
  str.append("|mountfrom=");
  if (allowed) {
    str.append([NonNull(MountFromName([props[@"DAVolumePath"] path])) UTF8String]);
  } else {
    str.append([NonNull(props[santa::kMountFromNameKey]) UTF8String]);
  }

  NSNumber *encrypted = props[(__bridge NSString *)kDADiskDescriptionMediaEncryptedKey];
  if (encrypted != nil) {
    str.append("|encrypted=");
    str.append([encrypted boolValue] ? "true" : "false");
  }

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeDiskDisappeared(NSDictionary *props) {
  std::string str = CreateDefaultString();

  str.append("action=DISKDISAPPEAR");
  str.append("|mount=");
  str.append([NonNull([props[@"DAVolumePath"] path]) UTF8String]);
  str.append("|volume=");
  str.append([NonNull(props[@"DAVolumeName"]) UTF8String]);
  str.append("|bsdname=");
  str.append([NonNull(props[@"DAMediaBSDName"]) UTF8String]);

  return FinalizeString(str);
}

}  // namespace santa
