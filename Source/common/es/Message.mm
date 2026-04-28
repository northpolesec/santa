/// Copyright 2022 Google Inc. All rights reserved.
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

#include "Source/common/es/Message.h"

#include <bsm/libbsm.h>
#include <libproc.h>
#include <sys/param.h>
#include <sys/stat.h>

#include "Source/common/es/EndpointSecurityAPI.h"

namespace santa {

// Simple path: string_view directly into the retained es_message_t data.
static inline void PushBackPathTarget(std::vector<Message::PathTarget>& vec,
                                      const es_file_t* esFile, bool isReadable = false) {
  vec.push_back({std::string_view(esFile->path.data, esFile->path.length), isReadable, esFile,
                 esFile->path_truncated});
}

// Compound path (dir + "/" + filename): must materialize a std::string.
static inline void PushBackPathTarget(std::vector<Message::PathTarget>& vec, const es_file_t* dir,
                                      const es_string_token_t& name) {
  std::string full_path;
  full_path.reserve(dir->path.length + 1 + name.length);
  full_path.append(dir->path.data, dir->path.length);
  full_path += '/';
  full_path.append(name.data, name.length);
  vec.push_back({std::move(full_path), false, nullptr, dir->path_truncated});
}

Message::Message(std::shared_ptr<EndpointSecurityAPI> esapi, const es_message_t* es_msg)
    : esapi_(std::move(esapi)), es_msg_(es_msg), process_token_(std::nullopt) {
  esapi_->RetainMessage(es_msg);
}

Message::~Message() {
  if (es_msg_) {
    esapi_->ReleaseMessage(es_msg_);
  }
}

Message::Message(Message&& other) {
  esapi_ = std::move(other.esapi_);
  es_msg_ = other.es_msg_;
  path_targets_ = std::move(other.path_targets_);
  other.es_msg_ = nullptr;
  process_token_ = std::move(other.process_token_);
  other.process_token_ = std::nullopt;
}

Message::Message(const Message& other) {
  esapi_ = other.esapi_;
  es_msg_ = other.es_msg_;
  esapi_->RetainMessage(es_msg_);
  path_targets_ = other.path_targets_;
  process_token_ = other.process_token_;
}

void Message::SetProcessToken(santa::santad::process_tree::ProcessToken tok) {
  process_token_ = std::move(tok);
}

std::string Message::ParentProcessName() const {
  return GetProcessName(es_msg_->process->ppid);
}

std::string Message::ParentProcessPath() const {
  return GetProcessPath(&es_msg_->process->parent_audit_token);
}

std::string Message::GetProcessName(pid_t pid) const {
  // Note: proc_name() accesses the `pbi_name` field of `struct proc_bsdinfo`. The size of `pname`
  // here is meant to match the size of `pbi_name`, and one extra byte ensure zero-terminated.
  char pname[MAXCOMLEN * 2 + 1] = {};
  if (proc_name(pid, pname, sizeof(pname)) > 0) {
    return std::string(pname);
  } else {
    return std::string("");
  }
}

std::string Message::GetProcessPath(audit_token_t* tok) const {
  char path_buf[MAXPATHLEN] = {};
  if (proc_pidpath_audittoken(tok, path_buf, sizeof(path_buf)) > 0) {
    return std::string(path_buf);
  } else {
    return std::string("");
  }
}

const std::vector<Message::PathTarget> Message::PathTargets() {
  if (path_targets_.size() == 0) {
    PopulatePathTargets();
  }

  return path_targets_;
}

void Message::PopulatePathTargets() {
  std::vector<Message::PathTarget> targets;
  targets.reserve(2);

  switch (es_msg_->event_type) {
    case ES_EVENT_TYPE_AUTH_CLONE:
      PushBackPathTarget(targets, es_msg_->event.clone.source, true);
      PushBackPathTarget(targets, es_msg_->event.clone.target_dir,
                         es_msg_->event.clone.target_name);
      break;

    case ES_EVENT_TYPE_AUTH_CREATE:
      // AUTH CREATE events should always be ES_DESTINATION_TYPE_NEW_PATH
      if (es_msg_->event.create.destination_type == ES_DESTINATION_TYPE_NEW_PATH) {
        PushBackPathTarget(targets, es_msg_->event.create.destination.new_path.dir,
                           es_msg_->event.create.destination.new_path.filename);
      } else {
        LOGW(@"Unexpected destination type for create event: %d. Ignoring target.",
             es_msg_->event.create.destination_type);
      }
      break;

    case ES_EVENT_TYPE_AUTH_COPYFILE:
      PushBackPathTarget(targets, es_msg_->event.copyfile.source, true);
      if (es_msg_->event.copyfile.target_file) {
        PushBackPathTarget(targets, es_msg_->event.copyfile.target_file);
      } else {
        PushBackPathTarget(targets, es_msg_->event.copyfile.target_dir,
                           es_msg_->event.copyfile.target_name);
      }
      break;

    case ES_EVENT_TYPE_AUTH_EXCHANGEDATA:
      PushBackPathTarget(targets, es_msg_->event.exchangedata.file1);
      PushBackPathTarget(targets, es_msg_->event.exchangedata.file2);
      break;

    case ES_EVENT_TYPE_AUTH_LINK:
      PushBackPathTarget(targets, es_msg_->event.link.source);
      PushBackPathTarget(targets, es_msg_->event.link.target_dir,
                         es_msg_->event.link.target_filename);
      break;

    case ES_EVENT_TYPE_AUTH_OPEN:
      PushBackPathTarget(targets, es_msg_->event.open.file, true);
      break;

    case ES_EVENT_TYPE_AUTH_RENAME:
      PushBackPathTarget(targets, es_msg_->event.rename.source);
      if (es_msg_->event.rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE) {
        PushBackPathTarget(targets, es_msg_->event.rename.destination.existing_file);
      } else if (es_msg_->event.rename.destination_type == ES_DESTINATION_TYPE_NEW_PATH) {
        PushBackPathTarget(targets, es_msg_->event.rename.destination.new_path.dir,
                           es_msg_->event.rename.destination.new_path.filename);
      } else {
        LOGW(@"Unexpected destination type for rename event: %d. Ignoring destination.",
             es_msg_->event.rename.destination_type);
      }
      break;

    case ES_EVENT_TYPE_AUTH_TRUNCATE:
      PushBackPathTarget(targets, es_msg_->event.truncate.target);
      break;

    case ES_EVENT_TYPE_AUTH_UNLINK:
      PushBackPathTarget(targets, es_msg_->event.unlink.target);
      break;

    default: break;
  }

  path_targets_.swap(targets);
}

}  // namespace santa
