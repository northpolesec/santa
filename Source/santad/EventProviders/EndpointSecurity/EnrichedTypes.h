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

/// This file groups all of the enriched message types - that is the
/// objects that are constructed to hold all enriched event data prior
/// to being logged.

#ifndef SANTA__SANTAD__EVENTPROVIDERS_ENDPOINTSECURITY_ENRICHEDTYPES_H
#define SANTA__SANTAD__EVENTPROVIDERS_ENDPOINTSECURITY_ENRICHEDTYPES_H

#include <EndpointSecurity/EndpointSecurity.h>
#include <time.h>

#include <optional>
#include <string>
#include <variant>

#include "Source/common/Platform.h"
#include "Source/common/TelemetryEventMap.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/ProcessTree/process_tree.pb.h"

namespace santa {

class EnrichedFile {
 public:
  EnrichedFile()
      : user_(std::nullopt), group_(std::nullopt), hash_(std::nullopt) {}

  EnrichedFile(std::optional<std::shared_ptr<std::string>> &&user,
               std::optional<std::shared_ptr<std::string>> &&group,
               std::optional<std::shared_ptr<std::string>> &&hash)
      : user_(std::move(user)),
        group_(std::move(group)),
        hash_(std::move(hash)) {}

  EnrichedFile(EnrichedFile &&other)
      : user_(std::move(other.user_)),
        group_(std::move(other.group_)),
        hash_(std::move(other.hash_)) {}

  // Note: Move assignment could be safely implemented but not currently needed
  EnrichedFile &operator=(EnrichedFile &&other) = delete;

  EnrichedFile(const EnrichedFile &other) = delete;
  EnrichedFile &operator=(const EnrichedFile &other) = delete;

  const std::optional<std::shared_ptr<std::string>> &user() const {
    return user_;
  }
  const std::optional<std::shared_ptr<std::string>> &group() const {
    return group_;
  }

 private:
  std::optional<std::shared_ptr<std::string>> user_;
  std::optional<std::shared_ptr<std::string>> group_;
  std::optional<std::shared_ptr<std::string>> hash_;
};

class EnrichedProcess {
 public:
  EnrichedProcess()
      : effective_user_(std::nullopt),
        effective_group_(std::nullopt),
        real_user_(std::nullopt),
        real_group_(std::nullopt),
        annotations_(std::nullopt) {}

  EnrichedProcess(
      std::optional<std::shared_ptr<std::string>> &&effective_user,
      std::optional<std::shared_ptr<std::string>> &&effective_group,
      std::optional<std::shared_ptr<std::string>> &&real_user,
      std::optional<std::shared_ptr<std::string>> &&real_group,
      EnrichedFile &&executable,
      std::optional<santa::pb::v1::process_tree::Annotations> &&annotations)
      : effective_user_(std::move(effective_user)),
        effective_group_(std::move(effective_group)),
        real_user_(std::move(real_user)),
        real_group_(std::move(real_group)),
        executable_(std::move(executable)),
        annotations_(std::move(annotations)) {}

  EnrichedProcess(EnrichedProcess &&other)
      : effective_user_(std::move(other.effective_user_)),
        effective_group_(std::move(other.effective_group_)),
        real_user_(std::move(other.real_user_)),
        real_group_(std::move(other.real_group_)),
        executable_(std::move(other.executable_)),
        annotations_(std::move(other.annotations_)) {}

  // Note: Move assignment could be safely implemented but not currently needed
  EnrichedProcess &operator=(EnrichedProcess &&other) = delete;

  EnrichedProcess(const EnrichedProcess &other) = delete;
  EnrichedProcess &operator=(const EnrichedProcess &other) = delete;

  const std::optional<std::shared_ptr<std::string>> &effective_user() const {
    return effective_user_;
  }
  const std::optional<std::shared_ptr<std::string>> &effective_group() const {
    return effective_group_;
  }
  const std::optional<std::shared_ptr<std::string>> &real_user() const {
    return real_user_;
  }
  const std::optional<std::shared_ptr<std::string>> &real_group() const {
    return real_group_;
  }
  const EnrichedFile &executable() const { return executable_; }
  const std::optional<santa::pb::v1::process_tree::Annotations> &annotations()
      const {
    return annotations_;
  }

 private:
  std::optional<std::shared_ptr<std::string>> effective_user_;
  std::optional<std::shared_ptr<std::string>> effective_group_;
  std::optional<std::shared_ptr<std::string>> real_user_;
  std::optional<std::shared_ptr<std::string>> real_group_;
  EnrichedFile executable_;
  std::optional<santa::pb::v1::process_tree::Annotations> annotations_;
};

class EnrichedEventType {
 public:
  EnrichedEventType(Message &&es_msg, EnrichedProcess &&instigator)
      : es_msg_(std::move(es_msg)), instigator_(std::move(instigator)) {
    clock_gettime(CLOCK_REALTIME, &enrichment_time_);
  }

  EnrichedEventType(EnrichedEventType &&other)
      : es_msg_(std::move(other.es_msg_)),
        instigator_(std::move(other.instigator_)),
        enrichment_time_(std::move(other.enrichment_time_)) {}

  // Note: Move assignment could be safely implemented but not currently needed
  // so no sense in implementing across all child classes.
  EnrichedEventType &operator=(EnrichedEventType &&other) = delete;

  EnrichedEventType(const EnrichedEventType &other) = delete;
  EnrichedEventType &operator=(const EnrichedEventType &other) = delete;

  virtual ~EnrichedEventType() = default;

  inline const es_message_t *operator->() const { return es_msg_.operator->(); }

  const EnrichedProcess &instigator() const { return instigator_; }
  struct timespec enrichment_time() const { return enrichment_time_; }

 protected:
  Message es_msg_;

 private:
  EnrichedProcess instigator_;
  struct timespec enrichment_time_;
};

class EnrichedClose : public EnrichedEventType {
 public:
  EnrichedClose(Message &&es_msg, EnrichedProcess &&instigator,
                EnrichedFile &&target)
      : EnrichedEventType(std::move(es_msg), std::move(instigator)),
        target_(std::move(target)) {}

  EnrichedClose(EnrichedClose &&other)
      : EnrichedEventType(std::move(other)),
        target_(std::move(other.target_)) {}

  EnrichedClose(const EnrichedClose &other) = delete;

  const EnrichedFile &target() const { return target_; }

 private:
  EnrichedFile target_;
};

class EnrichedExchange : public EnrichedEventType {
 public:
  EnrichedExchange(Message &&es_msg, EnrichedProcess &&instigator,
                   EnrichedFile &&file1, EnrichedFile &&file2)
      : EnrichedEventType(std::move(es_msg), std::move(instigator)),
        file1_(std::move(file1)),
        file2_(std::move(file2)) {}

  EnrichedExchange(EnrichedExchange &&other)
      : EnrichedEventType(std::move(other)),
        file1_(std::move(other.file1_)),
        file2_(std::move(other.file2_)) {}

  EnrichedExchange(const EnrichedExchange &other) = delete;

  const EnrichedFile &file1() const { return file1_; }
  const EnrichedFile &file2() const { return file2_; }

 private:
  EnrichedFile file1_;
  EnrichedFile file2_;
};

class EnrichedExec : public EnrichedEventType {
 public:
  EnrichedExec(Message &&es_msg, EnrichedProcess &&instigator,
               EnrichedProcess &&target, std::optional<EnrichedFile> &&script,
               std::optional<EnrichedFile> working_dir)
      : EnrichedEventType(std::move(es_msg), std::move(instigator)),
        target_(std::move(target)),
        script_(std::move(script)),
        working_dir_(std::move(working_dir)) {}

  EnrichedExec(EnrichedExec &&other)
      : EnrichedEventType(std::move(other)),
        target_(std::move(other.target_)),
        script_(std::move(other.script_)),
        working_dir_(std::move(other.working_dir_)) {}

  EnrichedExec(const EnrichedExec &other) = delete;

  const EnrichedProcess &target() const { return target_; }
  const std::optional<EnrichedFile> &script() const { return script_; }
  const std::optional<EnrichedFile> &working_dir() const {
    return working_dir_;
  }

 private:
  EnrichedProcess target_;
  std::optional<EnrichedFile> script_;
  std::optional<EnrichedFile> working_dir_;
};

class EnrichedExit : public EnrichedEventType {
 public:
  EnrichedExit(Message &&es_msg, EnrichedProcess &&instigator)
      : EnrichedEventType(std::move(es_msg), std::move(instigator)) {}

  EnrichedExit(EnrichedExit &&other) : EnrichedEventType(std::move(other)) {}

  EnrichedExit(const EnrichedExit &other) = delete;
};

class EnrichedFork : public EnrichedEventType {
 public:
  EnrichedFork(Message &&es_msg, EnrichedProcess &&instigator,
               EnrichedProcess &&child)
      : EnrichedEventType(std::move(es_msg), std::move(instigator)),
        child_(std::move(child)) {}

  EnrichedFork(EnrichedFork &&other)
      : EnrichedEventType(std::move(other)), child_(std::move(other.child_)) {}

  EnrichedFork(const EnrichedFork &other) = delete;

  const EnrichedProcess &child() const { return child_; }

 private:
  EnrichedProcess child_;
};

class EnrichedLink : public EnrichedEventType {
 public:
  EnrichedLink(Message &&es_msg, EnrichedProcess &&instigator,
               EnrichedFile &&source, EnrichedFile &&target_dir)
      : EnrichedEventType(std::move(es_msg), std::move(instigator)),
        source_(std::move(source)),
        target_dir_(std::move(target_dir)) {}

  EnrichedLink(EnrichedLink &&other)
      : EnrichedEventType(std::move(other)),
        source_(std::move(other.source_)),
        target_dir_(std::move(other.target_dir_)) {}

  EnrichedLink(const EnrichedLink &other) = delete;

  const EnrichedFile &source() const { return source_; }

 private:
  EnrichedFile source_;
  EnrichedFile target_dir_;
};

class EnrichedRename : public EnrichedEventType {
 public:
  EnrichedRename(Message &&es_msg, EnrichedProcess &&instigator,
                 EnrichedFile &&source, std::optional<EnrichedFile> &&target,
                 std::optional<EnrichedFile> &&target_dir)
      : EnrichedEventType(std::move(es_msg), std::move(instigator)),
        source_(std::move(source)),
        target_(std::move(target)),
        target_dir_(std::move(target_dir)) {}

  EnrichedRename(EnrichedRename &&other)
      : EnrichedEventType(std::move(other)),
        source_(std::move(other.source_)),
        target_(std::move(other.target_)),
        target_dir_(std::move(other.target_dir_)) {}

  EnrichedRename(const EnrichedRename &other) = delete;

  const EnrichedFile &source() const { return source_; }

 private:
  EnrichedFile source_;
  std::optional<EnrichedFile> target_;
  std::optional<EnrichedFile> target_dir_;
};

class EnrichedUnlink : public EnrichedEventType {
 public:
  EnrichedUnlink(Message &&es_msg, EnrichedProcess &&instigator,
                 EnrichedFile &&target)
      : EnrichedEventType(std::move(es_msg), std::move(instigator)),
        target_(std::move(target)) {}

  EnrichedUnlink(EnrichedUnlink &&other)
      : EnrichedEventType(std::move(other)),
        target_(std::move(other.target_)) {}

  EnrichedUnlink(const EnrichedUnlink &other) = delete;

  const EnrichedFile &target() const { return target_; }

 private:
  EnrichedFile target_;
};

class EnrichedCSInvalidated : public EnrichedEventType {
 public:
  EnrichedCSInvalidated(Message &&es_msg, EnrichedProcess &&instigator)
      : EnrichedEventType(std::move(es_msg), std::move(instigator)) {}
  EnrichedCSInvalidated(EnrichedCSInvalidated &&other)
      : EnrichedEventType(std::move(other)) {}
  EnrichedCSInvalidated(const EnrichedCSInvalidated &other) = delete;
};

// Note: All EnrichedLoginWindowSession* classes currently have the same
// data and implementation. To improve maintainability but still provide
// individual types, an internal EnrichedLoginWindowSession base class is
// defined that is derived by each desired types.
// EnrichedLoginWindowSession is wrapped in an `internal` namespace as it
// shouldn't be directly used outside of this file.
namespace internal {

class EnrichedLoginWindowSession : public EnrichedEventType {
 public:
  EnrichedLoginWindowSession(Message &&es_msg, EnrichedProcess instigator,
                             std::optional<uid_t> uid)
      : EnrichedEventType(std::move(es_msg), std::move(instigator)),
        uid_(std::move(uid)) {}

  EnrichedLoginWindowSession(EnrichedLoginWindowSession &&) = default;

  virtual ~EnrichedLoginWindowSession() = default;
  inline std::optional<uid_t> UID() const { return uid_; }

 private:
  std::optional<uid_t> uid_;
};

}  // namespace internal

class EnrichedLoginWindowSessionLogin
    : public internal::EnrichedLoginWindowSession {
  using EnrichedLoginWindowSession::EnrichedLoginWindowSession;
};

class EnrichedLoginWindowSessionLogout
    : public internal::EnrichedLoginWindowSession {
  using EnrichedLoginWindowSession::EnrichedLoginWindowSession;
};

class EnrichedLoginWindowSessionLock
    : public internal::EnrichedLoginWindowSession {
  using EnrichedLoginWindowSession::EnrichedLoginWindowSession;
};

class EnrichedLoginWindowSessionUnlock
    : public internal::EnrichedLoginWindowSession {
  using EnrichedLoginWindowSession::EnrichedLoginWindowSession;
};

class EnrichedScreenSharingAttach : public EnrichedEventType {
 public:
  EnrichedScreenSharingAttach(Message &&es_msg, EnrichedProcess instigator)
      : EnrichedEventType(std::move(es_msg), std::move(instigator)) {}

  EnrichedScreenSharingAttach(EnrichedScreenSharingAttach &&) = default;
};

class EnrichedScreenSharingDetach : public EnrichedEventType {
 public:
  EnrichedScreenSharingDetach(Message &&es_msg, EnrichedProcess instigator)
      : EnrichedEventType(std::move(es_msg), std::move(instigator)) {}

  EnrichedScreenSharingDetach(EnrichedScreenSharingDetach &&) = default;
};

class EnrichedOpenSSHLogin : public EnrichedEventType {
 public:
  EnrichedOpenSSHLogin(Message &&es_msg, EnrichedProcess instigator)
      : EnrichedEventType(std::move(es_msg), std::move(instigator)) {}

  EnrichedOpenSSHLogin(EnrichedOpenSSHLogin &&) = default;
};

class EnrichedOpenSSHLogout : public EnrichedEventType {
 public:
  EnrichedOpenSSHLogout(Message &&es_msg, EnrichedProcess instigator)
      : EnrichedEventType(std::move(es_msg), std::move(instigator)) {}

  EnrichedOpenSSHLogout(EnrichedOpenSSHLogout &&) = default;
};

class EnrichedLoginLogin : public EnrichedEventType {
 public:
  EnrichedLoginLogin(Message &&es_msg, EnrichedProcess instigator)
      : EnrichedEventType(std::move(es_msg), std::move(instigator)) {}

  EnrichedLoginLogin(EnrichedLoginLogin &&) = default;
};

class EnrichedLoginLogout : public EnrichedEventType {
 public:
  EnrichedLoginLogout(Message &&es_msg, EnrichedProcess instigator)
      : EnrichedEventType(std::move(es_msg), std::move(instigator)) {}

  EnrichedLoginLogout(EnrichedLoginLogout &&) = default;
};

// Base class for event types that contain instigator information. Note that
// beginning in macOS 15 instigator information is optional. If complete
// process info is missing, the audit token of the instigator is still made
// available.
class EnrichedEventWithInstigator : public EnrichedEventType {
 public:
  EnrichedEventWithInstigator(
      Message &&es_msg, EnrichedProcess instigator,
      std::optional<EnrichedProcess> enriched_event_instigator)
      : EnrichedEventType(std::move(es_msg), std::move(instigator)),
        enriched_event_instigator_(std::move(enriched_event_instigator)) {}

  virtual ~EnrichedEventWithInstigator() = default;

  EnrichedEventWithInstigator(EnrichedEventWithInstigator &&) = default;

  virtual const es_process_t *EventInstigator() const = 0;
  virtual std::optional<audit_token_t> EventInstigatorToken() const = 0;

  const std::optional<EnrichedProcess> &EnrichedEventInstigator() const {
    return enriched_event_instigator_;
  }

 private:
  std::optional<EnrichedProcess> enriched_event_instigator_;
};

class EnrichedAuthenticationOD : public EnrichedEventWithInstigator {
 public:
  using EnrichedEventWithInstigator::EnrichedEventWithInstigator;

  EnrichedAuthenticationOD(EnrichedAuthenticationOD &&) = default;

  const es_process_t *EventInstigator() const override {
#if HAVE_MACOS_13
    return es_msg_->event.authentication->data.od->instigator;
#else
    return nullptr;
#endif
  }

  std::optional<audit_token_t> EventInstigatorToken() const override {
#if HAVE_MACOS_15
    return es_msg_->version >= 8
               ? std::make_optional<audit_token_t>(
                     es_msg_->event.authentication->data.od->instigator_token)
               : std::nullopt;
#else
    return std::nullopt;
#endif
  }
};

class EnrichedAuthenticationTouchID : public EnrichedEventWithInstigator {
 public:
  EnrichedAuthenticationTouchID(
      Message &&es_msg, EnrichedProcess instigator,
      std::optional<EnrichedProcess> auth_instigator,
      std::optional<std::shared_ptr<std::string>> username)
      : EnrichedEventWithInstigator(std::move(es_msg), std::move(instigator),
                                    std::move(auth_instigator)),
        username_(std::move(username)) {}

  EnrichedAuthenticationTouchID(EnrichedAuthenticationTouchID &&) = default;

  const es_process_t *EventInstigator() const override {
#if HAVE_MACOS_13
    return es_msg_->event.authentication->data.touchid->instigator;
#else
    return nullptr;
#endif
  }

  std::optional<audit_token_t> EventInstigatorToken() const override {
#if HAVE_MACOS_15
    return es_msg_->version >= 8 ? std::make_optional<audit_token_t>(
                                       es_msg_->event.authentication->data
                                           .touchid->instigator_token)
                                 : std::nullopt;
#else
    return std::nullopt;
#endif
  }

  const std::optional<std::shared_ptr<std::string>> &Username() const {
    return username_;
  }

 private:
  std::optional<std::shared_ptr<std::string>> username_;
};

class EnrichedAuthenticationToken : public EnrichedEventWithInstigator {
 public:
  using EnrichedEventWithInstigator::EnrichedEventWithInstigator;

  EnrichedAuthenticationToken(EnrichedAuthenticationToken &&) = default;

  const es_process_t *EventInstigator() const override {
#if HAVE_MACOS_13
    return es_msg_->event.authentication->data.token->instigator;
#else
    return nullptr;
#endif
  }

  std::optional<audit_token_t> EventInstigatorToken() const override {
#if HAVE_MACOS_15
    return es_msg_->version >= 8 ? std::make_optional<audit_token_t>(
                                       es_msg_->event.authentication->data
                                           .token->instigator_token)
                                 : std::nullopt;
#else
    return std::nullopt;
#endif
  }
};

class EnrichedAuthenticationAutoUnlock : public EnrichedEventType {
 public:
  EnrichedAuthenticationAutoUnlock(Message &&es_msg, EnrichedProcess instigator,
                                   std::optional<uid_t> uid)
      : EnrichedEventType(std::move(es_msg), std::move(instigator)),
        uid_(std::move(uid)) {}

  EnrichedAuthenticationAutoUnlock(EnrichedAuthenticationAutoUnlock &&) =
      default;

  inline std::optional<uid_t> UID() const { return uid_; }

 private:
  std::optional<uid_t> uid_;
};

class EnrichedLaunchItem : public EnrichedEventWithInstigator {
 public:
  EnrichedLaunchItem(Message &&es_msg, EnrichedProcess instigator,
                     std::optional<EnrichedProcess> enriched_btm_instigator,
                     std::optional<EnrichedProcess> enriched_app_registrant,
                     std::optional<std::shared_ptr<std::string>> username)
      : EnrichedEventWithInstigator(std::move(es_msg), std::move(instigator),
                                    std::move(enriched_btm_instigator)),
        enriched_app_registrant_(std::move(enriched_app_registrant)),
        username_(std::move(username)) {
    assert(es_msg_->event_type == ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD ||
           es_msg_->event_type == ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE);
  }

  EnrichedLaunchItem(EnrichedLaunchItem &&) = default;

  const es_process_t *EventInstigator() const override {
#if HAVE_MACOS_13
    if (es_msg_->event_type == ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD) {
      return es_msg_->event.btm_launch_item_add->instigator;
    } else {
      return es_msg_->event.btm_launch_item_remove->instigator;
    }
#else
    return nullptr;
#endif
  }

  std::optional<audit_token_t> EventInstigatorToken() const override {
#if HAVE_MACOS_15
    if (es_msg_->version < 8) {
      return std::nullopt;
    }

    if (es_msg_->event_type == ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD &&
        es_msg_->event.btm_launch_item_add->instigator_token) {
      return std::make_optional<audit_token_t>(
          *es_msg_->event.btm_launch_item_add->instigator_token);
    } else if (es_msg_->event_type ==
                   ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE &&
               es_msg_->event.btm_launch_item_remove->instigator_token) {
      return std::make_optional<audit_token_t>(
          *es_msg_->event.btm_launch_item_remove->instigator_token);
    } else {
      return std::nullopt;
    }
#else
    return std::nullopt;
#endif
  }

  const es_process_t *AppRegistrant() const {
#if HAVE_MACOS_13
    if (es_msg_->event_type == ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD) {
      return es_msg_->event.btm_launch_item_add->app;
    } else {
      return es_msg_->event.btm_launch_item_remove->app;
    }
#else
    return nullptr;
#endif
  }

  std::optional<audit_token_t> AppRegistrantToken() const {
#if HAVE_MACOS_15
    if (es_msg_->version < 8) {
      return std::nullopt;
    }

    if (es_msg_->event_type == ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD &&
        es_msg_->event.btm_launch_item_add->app_token) {
      return std::make_optional<audit_token_t>(
          *es_msg_->event.btm_launch_item_add->app_token);
    } else if (es_msg_->event_type ==
                   ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE &&
               es_msg_->event.btm_launch_item_remove->app_token) {
      return std::make_optional<audit_token_t>(
          *es_msg_->event.btm_launch_item_remove->app_token);
    } else {
      return std::nullopt;
    }
#else
    return std::nullopt;
#endif
  }

  const std::optional<EnrichedProcess> &EnrichedAppRegistrant() const {
    return enriched_app_registrant_;
  }

  const std::optional<std::shared_ptr<std::string>> &Username() const {
    return username_;
  }

 private:
  std::optional<EnrichedProcess> enriched_app_registrant_;
  std::optional<std::shared_ptr<std::string>> username_;
};

class EnrichedClone : public EnrichedEventType {
 public:
  EnrichedClone(Message &&es_msg, EnrichedProcess &&instigator,
                EnrichedFile &&source)
      : EnrichedEventType(std::move(es_msg), std::move(instigator)),
        source_(std::move(source)) {}

  EnrichedClone(EnrichedClone &&) = default;

  const EnrichedFile &source() const { return source_; }

 private:
  EnrichedFile source_;
};

class EnrichedCopyfile : public EnrichedEventType {
 public:
  EnrichedCopyfile(Message &&es_msg, EnrichedProcess &&instigator,
                   EnrichedFile &&source)
      : EnrichedEventType(std::move(es_msg), std::move(instigator)),
        source_(std::move(source)) {}

  EnrichedCopyfile(EnrichedCopyfile &&) = default;

  const EnrichedFile &source() const { return source_; }

 private:
  EnrichedFile source_;
};

class EnrichedGatekeeperOverride : public EnrichedEventType {
 public:
  EnrichedGatekeeperOverride(Message &&es_msg, EnrichedProcess &&instigator,
                             std::optional<EnrichedFile> target)
      : EnrichedEventType(std::move(es_msg), std::move(instigator)),
        target_(std::move(target)) {}

  const std::optional<EnrichedFile> &Target() const { return target_; }

 private:
  std::optional<EnrichedFile> target_;
};

class EnrichedTCCModification : public EnrichedEventWithInstigator {
 public:
  EnrichedTCCModification(
      Message &&es_msg, EnrichedProcess instigator,
      std::optional<EnrichedProcess> enriched_tcc_instigator,
      std::optional<EnrichedProcess> enriched_responsible_process)
      : EnrichedEventWithInstigator(std::move(es_msg), std::move(instigator),
                                    std::move(enriched_tcc_instigator)),
        enriched_responsible_proc_(std::move(enriched_responsible_process)) {}

  ~EnrichedTCCModification() override = default;
  EnrichedTCCModification(EnrichedTCCModification &&) = default;

  const es_process_t *EventInstigator() const override {
#if HAVE_MACOS_15_4
    return es_msg_->event.tcc_modify->instigator;
#else
    return nullptr;
#endif
  }

  std::optional<audit_token_t> EventInstigatorToken() const override {
#if HAVE_MACOS_15_4
    return std::make_optional<audit_token_t>(
        es_msg_->event.tcc_modify->instigator_token);

#else
    return std::nullopt;
#endif
  }

  const es_process_t *ResponsibleProcess() const {
#if HAVE_MACOS_15_4
    return es_msg_->event.tcc_modify->responsible;
#else
    return nullptr;
#endif
  }

  std::optional<audit_token_t> ResponsibleProcessToken() const {
#if HAVE_MACOS_15_4
    if (es_msg_->event.tcc_modify->responsible_token) {
      return std::make_optional<audit_token_t>(
          *es_msg_->event.tcc_modify->responsible_token);
    } else {
      return std::nullopt;
    }
#else
    return std::nullopt;
#endif
  }

  const std::optional<EnrichedProcess> &EnrichedResponsibleProcess() const {
    return enriched_responsible_proc_;
  }

 private:
  std::optional<EnrichedProcess> enriched_responsible_proc_;
};

using EnrichedType =
    std::variant<EnrichedClose, EnrichedExchange, EnrichedExec, EnrichedExit,
                 EnrichedFork, EnrichedLink, EnrichedRename, EnrichedUnlink,
                 EnrichedCSInvalidated, EnrichedLoginWindowSessionLogin,
                 EnrichedLoginWindowSessionLogout,
                 EnrichedLoginWindowSessionLock,
                 EnrichedLoginWindowSessionUnlock, EnrichedScreenSharingAttach,
                 EnrichedScreenSharingDetach, EnrichedOpenSSHLogin,
                 EnrichedOpenSSHLogout, EnrichedLoginLogin, EnrichedLoginLogout,
                 EnrichedAuthenticationOD, EnrichedAuthenticationTouchID,
                 EnrichedAuthenticationToken, EnrichedAuthenticationAutoUnlock,
                 EnrichedClone, EnrichedCopyfile, EnrichedLaunchItem
#if HAVE_MACOS_15
                 ,
                 EnrichedGatekeeperOverride
#endif  // HAVE_MACOS_15
#if HAVE_MACOS_15_4
                 ,
                 EnrichedTCCModification
#endif  // HAVE_MACOS_15_4
                 >;

class EnrichedMessage {
 public:
  // Note: For now, all EnrichedType variants have a base class of
  // EnrichedEventType. If this changes in the future, we'll need a more
  // comprehensive solution for grabbing the TelemetryEvent type of T.
  template <typename T>
  EnrichedMessage(T &&event)
      : telemetry_event_(ESEventToTelemetryEvent(event->event_type)),
        msg_(std::move(event)) {}

  const EnrichedType &GetEnrichedMessage() { return msg_; }

  inline TelemetryEvent GetTelemetryEvent() { return telemetry_event_; }

 private:
  // Because the constructor requires moving the given argument into msg_,
  // telemetry_event_ should be declared first to ensure the argument isn't
  // in an unspecified state.
  TelemetryEvent telemetry_event_;
  EnrichedType msg_;
};

}  // namespace santa

#endif
