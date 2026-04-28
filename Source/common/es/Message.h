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

#ifndef SANTA_COMMON_ES_MESSAGE_H
#define SANTA_COMMON_ES_MESSAGE_H

#include <EndpointSecurity/EndpointSecurity.h>

#include <memory>
#include <string>
#include <string_view>
#include <variant>

#include "Source/common/processtree/process_tree.h"

namespace santa {

class EndpointSecurityAPI;

class Message {
 public:
  // Small structure to hold event target information.
  struct PathTarget {
    // Simple paths hold a string_view into the retained es_message_t (zero
    // copy). Compound paths (dir + "/" + filename) hold a materialized string.
    // Both variants are null-terminated.
    std::variant<std::string_view, std::string> path;
    bool is_readable;
    // This is a pointer into an es_message_t. The message must be valid for
    // this pointer to be valid. The interfaces in the Message class will vend
    // pointers that are valid, and callers must not store or otherwise
    // reference the pointer to ensure no valid access is made.
    const es_file_t* unsafe_file;
    // True if any es_file_t contributing to this entry had path_truncated set.
    // The path string is whatever EndpointSecurity captured (up to PATH_MAX);
    // it is partial and unreliable for security decisions.
    bool truncated;

    // Returns a view of the path, regardless of which variant is held.
    std::string_view Path() const {
      return std::visit([](const auto& p) -> std::string_view { return p; },
                        path);
    }
  };

  Message(std::shared_ptr<EndpointSecurityAPI> esapi,
          const es_message_t* es_msg);
  ~Message();

  Message(Message&& other);
  // Note: Safe to implement this, just not currently needed so left deleted.
  Message& operator=(Message&& rhs) = delete;

  Message(const Message& other);
  Message& operator=(const Message& other) = delete;

  void SetProcessToken(santa::santad::process_tree::ProcessToken tok);

  // Operators to access underlying es_message_t
  inline const es_message_t* operator->() const { return es_msg_; }
  inline const es_message_t& operator*() const { return *es_msg_; }

  // Helper to get the API associated with this message.
  // Used for things like es_exec_arg_count.
  // We should ideally rework this to somehow present these functions as methods
  // on the Message, however this would be a bit of a bigger lift.
  std::shared_ptr<EndpointSecurityAPI> ESAPI() const { return esapi_; }

  std::string ParentProcessName() const;
  std::string ParentProcessPath() const;

  // This method is not thread safe until after the first completed call.
  const std::vector<Message::PathTarget> PathTargets();

  inline bool HasPathTarget(size_t index) const {
    return index < path_targets_.size();
  }

  inline const Message::PathTarget& PathTargetAtIndex(size_t index) const {
    return path_targets_.at(index);
  }

 private:
  std::string GetProcessName(pid_t pid) const;
  std::string GetProcessPath(audit_token_t* tok) const;
  void PopulatePathTargets();

  std::shared_ptr<EndpointSecurityAPI> esapi_;
  const es_message_t* es_msg_;
  std::optional<santa::santad::process_tree::ProcessToken> process_token_;
  std::vector<PathTarget> path_targets_;
};

}  // namespace santa

#endif  // SANTA_COMMON_ES_MESSAGE_H
