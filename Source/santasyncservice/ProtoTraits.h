/// Copyright 2025 North Pole Security, Inc.
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

#ifndef SANTA__SANTASYNCSERVICE__PROTOTRAITS_H
#define SANTA__SANTASYNCSERVICE__PROTOTRAITS_H

#include <type_traits>

#include "sync/v1.pb.h"
#include "syncv2/v2.pb.h"

namespace santa {

template <typename T>
struct ProtoTraits;

// Disabling clang format because this is more readable with longer lines
// clang-format off
template <>
struct ProtoTraits<std::bool_constant<false>> {
  // Sync Phase Types
  using PreflightRequestT = ::santa::sync::v1::PreflightRequest;
  using PreflightResponseT = ::santa::sync::v1::PreflightResponse;
  using EventUploadRequestT = ::santa::sync::v1::EventUploadRequest;
  using EventUploadResponseT = ::santa::sync::v1::EventUploadResponse;
  using RuleDownloadRequestT = ::santa::sync::v1::RuleDownloadRequest;
  using RuleDownloadResponseT = ::santa::sync::v1::RuleDownloadResponse;
  using PostflightRequestT = ::santa::sync::v1::PostflightRequest;
  using PostflightResponseT = ::santa::sync::v1::PostflightResponse;

  // General Types
  using CertificateT = ::santa::sync::v1::Certificate;
  using EntitlementInfoT = ::santa::sync::v1::EntitlementInfo;
  using EntitlementT = ::santa::sync::v1::Entitlement;
  using EventT = ::santa::sync::v1::Event;
  using FileAccessEventT = ::santa::sync::v1::FileAccessEvent;
  using ProcessT = ::santa::sync::v1::Process;
  using RuleT = ::santa::sync::v1::Rule;

  // Enum aliases
  using ClientMode = ::santa::sync::v1::ClientMode;
  static constexpr ClientMode UNKNOWN_CLIENT_MODE = ::santa::sync::v1::UNKNOWN_CLIENT_MODE;
  static constexpr ClientMode MONITOR = ::santa::sync::v1::MONITOR;
  static constexpr ClientMode LOCKDOWN = ::santa::sync::v1::LOCKDOWN;
  static constexpr ClientMode STANDALONE = ::santa::sync::v1::STANDALONE;

  using Decision = ::santa::sync::v1::Decision;
  static constexpr Decision DECISION_UNKNOWN = ::santa::sync::v1::DECISION_UNKNOWN;
  static constexpr Decision ALLOW_UNKNOWN = ::santa::sync::v1::ALLOW_UNKNOWN;
  static constexpr Decision ALLOW_BINARY = ::santa::sync::v1::ALLOW_BINARY;
  static constexpr Decision ALLOW_CERTIFICATE = ::santa::sync::v1::ALLOW_CERTIFICATE;
  static constexpr Decision ALLOW_SCOPE = ::santa::sync::v1::ALLOW_SCOPE;
  static constexpr Decision ALLOW_TEAMID = ::santa::sync::v1::ALLOW_TEAMID;
  static constexpr Decision ALLOW_SIGNINGID = ::santa::sync::v1::ALLOW_SIGNINGID;
  static constexpr Decision ALLOW_CDHASH = ::santa::sync::v1::ALLOW_CDHASH;
  static constexpr Decision BLOCK_UNKNOWN = ::santa::sync::v1::BLOCK_UNKNOWN;
  static constexpr Decision BLOCK_BINARY = ::santa::sync::v1::BLOCK_BINARY;
  static constexpr Decision BLOCK_CERTIFICATE = ::santa::sync::v1::BLOCK_CERTIFICATE;
  static constexpr Decision BLOCK_SCOPE = ::santa::sync::v1::BLOCK_SCOPE;
  static constexpr Decision BLOCK_TEAMID = ::santa::sync::v1::BLOCK_TEAMID;
  static constexpr Decision BLOCK_SIGNINGID = ::santa::sync::v1::BLOCK_SIGNINGID;
  static constexpr Decision BLOCK_CDHASH = ::santa::sync::v1::BLOCK_CDHASH;
  static constexpr Decision BUNDLE_BINARY = ::santa::sync::v1::BUNDLE_BINARY;

  using FileAccessAction = ::santa::sync::v1::FileAccessAction;
  static constexpr FileAccessAction FILE_ACCESS_ACTION_UNSPECIFIED = ::santa::sync::v1::FILE_ACCESS_ACTION_UNSPECIFIED;
  static constexpr FileAccessAction NONE = ::santa::sync::v1::NONE;
  static constexpr FileAccessAction AUDIT_ONLY = ::santa::sync::v1::AUDIT_ONLY;
  static constexpr FileAccessAction DISABLE = ::santa::sync::v1::DISABLE;

  using FileAccessDecision = ::santa::sync::v1::FileAccessDecision;
  static constexpr FileAccessDecision FILE_ACCESS_DECISION_UNKNOWN = ::santa::sync::v1::FILE_ACCESS_DECISION_UNKNOWN;
  static constexpr FileAccessDecision FILE_ACCESS_DECISION_DENIED = ::santa::sync::v1::FILE_ACCESS_DECISION_DENIED;
  static constexpr FileAccessDecision FILE_ACCESS_DECISION_DENIED_INVALID_SIGNATURE = ::santa::sync::v1::FILE_ACCESS_DECISION_DENIED_INVALID_SIGNATURE;
  static constexpr FileAccessDecision FILE_ACCESS_DECISION_AUDIT_ONLY = ::santa::sync::v1::FILE_ACCESS_DECISION_AUDIT_ONLY;

  using Policy = ::santa::sync::v1::Policy;
  static constexpr Policy POLICY_UNKNOWN = ::santa::sync::v1::POLICY_UNKNOWN;
  static constexpr Policy ALLOWLIST = ::santa::sync::v1::ALLOWLIST;
  static constexpr Policy ALLOWLIST_COMPILER = ::santa::sync::v1::ALLOWLIST_COMPILER;
  static constexpr Policy BLOCKLIST = ::santa::sync::v1::BLOCKLIST;
  static constexpr Policy SILENT_BLOCKLIST = ::santa::sync::v1::SILENT_BLOCKLIST;
  static constexpr Policy REMOVE = ::santa::sync::v1::REMOVE;
  static constexpr Policy CEL = ::santa::sync::v1::CEL;

  using RuleType = ::santa::sync::v1::RuleType;
  static constexpr RuleType RULETYPE_UNKNOWN = ::santa::sync::v1::RULETYPE_UNKNOWN;
  static constexpr RuleType BINARY = ::santa::sync::v1::BINARY;
  static constexpr RuleType CERTIFICATE = ::santa::sync::v1::CERTIFICATE;
  static constexpr RuleType TEAMID = ::santa::sync::v1::TEAMID;
  static constexpr RuleType SIGNINGID = ::santa::sync::v1::SIGNINGID;
  static constexpr RuleType CDHASH = ::santa::sync::v1::CDHASH;

  using SigningStatus = ::santa::sync::v1::SigningStatus;
  static constexpr SigningStatus SIGNING_STATUS_UNSPECIFIED = ::santa::sync::v1::SIGNING_STATUS_UNSPECIFIED;
  static constexpr SigningStatus SIGNING_STATUS_UNSIGNED = ::santa::sync::v1::SIGNING_STATUS_UNSIGNED;
  static constexpr SigningStatus SIGNING_STATUS_INVALID = ::santa::sync::v1::SIGNING_STATUS_INVALID;
  static constexpr SigningStatus SIGNING_STATUS_ADHOC = ::santa::sync::v1::SIGNING_STATUS_ADHOC;
  static constexpr SigningStatus SIGNING_STATUS_DEVELOPMENT = ::santa::sync::v1::SIGNING_STATUS_DEVELOPMENT;
  static constexpr SigningStatus SIGNING_STATUS_PRODUCTION = ::santa::sync::v1::SIGNING_STATUS_PRODUCTION;

  using SyncType = ::santa::sync::v1::SyncType;
  static constexpr SyncType SYNC_TYPE_UNSPECIFIED = ::santa::sync::v1::SYNC_TYPE_UNSPECIFIED;
  static constexpr SyncType NORMAL = ::santa::sync::v1::NORMAL;
  static constexpr SyncType CLEAN = ::santa::sync::v1::CLEAN;
  static constexpr SyncType CLEAN_ALL = ::santa::sync::v1::CLEAN_ALL;
  static constexpr SyncType CLEAN_STANDALONE = ::santa::sync::v1::CLEAN_STANDALONE;
  static constexpr SyncType CLEAN_RULES = ::santa::sync::v1::CLEAN_RULES;
  static constexpr SyncType CLEAN_FILE_ACCESS_RULES = ::santa::sync::v1::CLEAN_FILE_ACCESS_RULES;
};

template <>
struct ProtoTraits<std::bool_constant<true>> {
  // Sync Phase Types
  using PreflightRequestT = ::santa::sync::v2::PreflightRequest;
  using PreflightResponseT = ::santa::sync::v2::PreflightResponse;
  using EventUploadRequestT = ::santa::sync::v2::EventUploadRequest;
  using EventUploadResponseT = ::santa::sync::v2::EventUploadResponse;
  using RuleDownloadRequestT = ::santa::sync::v2::RuleDownloadRequest;
  using RuleDownloadResponseT = ::santa::sync::v2::RuleDownloadResponse;
  using PostflightRequestT = ::santa::sync::v2::PostflightRequest;
  using PostflightResponseT = ::santa::sync::v2::PostflightResponse;

  // General Types
  using CertificateT = ::santa::sync::v2::Certificate;
  using EntitlementT = ::santa::sync::v2::Entitlement;
  using EntitlementInfoT = ::santa::sync::v2::EntitlementInfo;
  using EventT = ::santa::sync::v2::Event;
  using FileAccessEventT = ::santa::sync::v2::FileAccessEvent;
  using FileAccessRuleT = ::santa::sync::v2::FileAccessRule;
  using ProcessT = ::santa::sync::v2::Process;
  using RuleT = ::santa::sync::v2::Rule;

  // Enum Aliases
  using ClientMode = ::santa::sync::v2::ClientMode;
  static constexpr ClientMode UNKNOWN_CLIENT_MODE = ::santa::sync::v2::UNKNOWN_CLIENT_MODE;
  static constexpr ClientMode MONITOR = ::santa::sync::v2::MONITOR;
  static constexpr ClientMode LOCKDOWN = ::santa::sync::v2::LOCKDOWN;
  static constexpr ClientMode STANDALONE = ::santa::sync::v2::STANDALONE;

  using Decision = ::santa::sync::v2::Decision;
  static constexpr Decision DECISION_UNKNOWN = ::santa::sync::v2::DECISION_UNKNOWN;
  static constexpr Decision ALLOW_UNKNOWN = ::santa::sync::v2::ALLOW_UNKNOWN;
  static constexpr Decision ALLOW_BINARY = ::santa::sync::v2::ALLOW_BINARY;
  static constexpr Decision ALLOW_CERTIFICATE = ::santa::sync::v2::ALLOW_CERTIFICATE;
  static constexpr Decision ALLOW_SCOPE = ::santa::sync::v2::ALLOW_SCOPE;
  static constexpr Decision ALLOW_TEAMID = ::santa::sync::v2::ALLOW_TEAMID;
  static constexpr Decision ALLOW_SIGNINGID = ::santa::sync::v2::ALLOW_SIGNINGID;
  static constexpr Decision ALLOW_CDHASH = ::santa::sync::v2::ALLOW_CDHASH;
  static constexpr Decision BLOCK_UNKNOWN = ::santa::sync::v2::BLOCK_UNKNOWN;
  static constexpr Decision BLOCK_BINARY = ::santa::sync::v2::BLOCK_BINARY;
  static constexpr Decision BLOCK_CERTIFICATE = ::santa::sync::v2::BLOCK_CERTIFICATE;
  static constexpr Decision BLOCK_SCOPE = ::santa::sync::v2::BLOCK_SCOPE;
  static constexpr Decision BLOCK_TEAMID = ::santa::sync::v2::BLOCK_TEAMID;
  static constexpr Decision BLOCK_SIGNINGID = ::santa::sync::v2::BLOCK_SIGNINGID;
  static constexpr Decision BLOCK_CDHASH = ::santa::sync::v2::BLOCK_CDHASH;
  static constexpr Decision BUNDLE_BINARY = ::santa::sync::v2::BUNDLE_BINARY;

  using FileAccessAction = ::santa::sync::v2::FileAccessAction;
  static constexpr FileAccessAction FILE_ACCESS_ACTION_UNSPECIFIED = ::santa::sync::v2::FILE_ACCESS_ACTION_UNSPECIFIED;
  static constexpr FileAccessAction NONE = ::santa::sync::v2::NONE;
  static constexpr FileAccessAction AUDIT_ONLY = ::santa::sync::v2::AUDIT_ONLY;
  static constexpr FileAccessAction DISABLE = ::santa::sync::v2::DISABLE;

  using FileAccessDecision = ::santa::sync::v2::FileAccessDecision;
  static constexpr FileAccessDecision FILE_ACCESS_DECISION_UNKNOWN = ::santa::sync::v2::FILE_ACCESS_DECISION_UNKNOWN;
  static constexpr FileAccessDecision FILE_ACCESS_DECISION_DENIED = ::santa::sync::v2::FILE_ACCESS_DECISION_DENIED;
  static constexpr FileAccessDecision FILE_ACCESS_DECISION_DENIED_INVALID_SIGNATURE = ::santa::sync::v2::FILE_ACCESS_DECISION_DENIED_INVALID_SIGNATURE;
  static constexpr FileAccessDecision FILE_ACCESS_DECISION_AUDIT_ONLY = ::santa::sync::v2::FILE_ACCESS_DECISION_AUDIT_ONLY;

  using Policy = ::santa::sync::v2::Policy;
  static constexpr Policy POLICY_UNKNOWN = ::santa::sync::v2::POLICY_UNKNOWN;
  static constexpr Policy ALLOWLIST = ::santa::sync::v2::ALLOWLIST;
  static constexpr Policy ALLOWLIST_COMPILER = ::santa::sync::v2::ALLOWLIST_COMPILER;
  static constexpr Policy BLOCKLIST = ::santa::sync::v2::BLOCKLIST;
  static constexpr Policy SILENT_BLOCKLIST = ::santa::sync::v2::SILENT_BLOCKLIST;
  static constexpr Policy REMOVE = ::santa::sync::v2::REMOVE;
  static constexpr Policy CEL = ::santa::sync::v2::CEL;

  using RuleType = ::santa::sync::v2::RuleType;
  static constexpr RuleType RULETYPE_UNKNOWN = ::santa::sync::v2::RULETYPE_UNKNOWN;
  static constexpr RuleType BINARY = ::santa::sync::v2::BINARY;
  static constexpr RuleType CERTIFICATE = ::santa::sync::v2::CERTIFICATE;
  static constexpr RuleType TEAMID = ::santa::sync::v2::TEAMID;
  static constexpr RuleType SIGNINGID = ::santa::sync::v2::SIGNINGID;
  static constexpr RuleType CDHASH = ::santa::sync::v2::CDHASH;

  using SigningStatus = ::santa::sync::v2::SigningStatus;
  static constexpr SigningStatus SIGNING_STATUS_UNSPECIFIED = ::santa::sync::v2::SIGNING_STATUS_UNSPECIFIED;
  static constexpr SigningStatus SIGNING_STATUS_UNSIGNED = ::santa::sync::v2::SIGNING_STATUS_UNSIGNED;
  static constexpr SigningStatus SIGNING_STATUS_INVALID = ::santa::sync::v2::SIGNING_STATUS_INVALID;
  static constexpr SigningStatus SIGNING_STATUS_ADHOC = ::santa::sync::v2::SIGNING_STATUS_ADHOC;
  static constexpr SigningStatus SIGNING_STATUS_DEVELOPMENT = ::santa::sync::v2::SIGNING_STATUS_DEVELOPMENT;
  static constexpr SigningStatus SIGNING_STATUS_PRODUCTION = ::santa::sync::v2::SIGNING_STATUS_PRODUCTION;

  using SyncType = ::santa::sync::v2::SyncType;
  static constexpr SyncType SYNC_TYPE_UNSPECIFIED = ::santa::sync::v2::SYNC_TYPE_UNSPECIFIED;
  static constexpr SyncType NORMAL = ::santa::sync::v2::NORMAL;
  static constexpr SyncType CLEAN = ::santa::sync::v2::CLEAN;
  static constexpr SyncType CLEAN_ALL = ::santa::sync::v2::CLEAN_ALL;
  static constexpr SyncType CLEAN_STANDALONE = ::santa::sync::v2::CLEAN_STANDALONE;
  static constexpr SyncType CLEAN_RULES = ::santa::sync::v2::CLEAN_RULES;
  static constexpr SyncType CLEAN_FILE_ACCESS_RULES = ::santa::sync::v2::CLEAN_FILE_ACCESS_RULES;
};

// clang-format on

}  // namespace santa

#endif  // SANTA__SANTASYNCSERVICE__PROTOTRAITS_H
