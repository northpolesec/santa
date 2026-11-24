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

#import "Source/santad/EventProviders/SNTEndpointSecurityRecorder.h"
#include <os/base.h>

#import "Source/santad/SNTLoginWindowSessionHandlerProtocol.h"

#include <EndpointSecurity/EndpointSecurity.h>
#include <unicode/uregex.h>
#include <unicode/utext.h>

#include <memory>
#include <string_view>
#include <vector>

#include "Source/common/Platform.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTKVOManager.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTStrengthify.h"
#include "Source/common/String.h"
#include "Source/common/TelemetryEventMap.h"
#include "Source/common/es/ESMetricsObserver.h"
#include "Source/common/es/EnrichedTypes.h"
#include "Source/common/es/Message.h"
#include "Source/common/processtree/process_tree.h"
#import "Source/santad/SNTDecisionCache.h"
#include "absl/synchronization/mutex.h"

using santa::EndpointSecurityAPI;
using santa::EnrichedMessage;
using santa::Enricher;
using santa::EventDisposition;
using santa::Logger;
using santa::Message;
using santa::PrefixTree;
using santa::Unit;
using santa::santad::process_tree::ProcessTree;

namespace {

// ICU form of FileChangesRegex, matched directly against UTF-8 path bytes.
// ICU reads bytes that are not valid UTF-8 as U+FFFD, so such paths are still
// evaluated. ICU keeps match state in the regex object, so callers must not
// match from two threads at once.
class FileChangesMatcher {
 public:
  // Returns nullptr if the ICU regex cannot be set up.
  static std::unique_ptr<FileChangesMatcher> Create(NSRegularExpression* re);
  ~FileChangesMatcher();
  FileChangesMatcher(const FileChangesMatcher&) = delete;
  FileChangesMatcher& operator=(const FileChangesMatcher&) = delete;

  bool Matches(std::string_view path);

 private:
  explicit FileChangesMatcher(URegularExpression* re) : re_(re) {}

  URegularExpression* re_;
  // Reused for every path, so matching does not allocate.
  UText text_ = UTEXT_INITIALIZER;
  // Open on "". re_ and text_ refer to it between matches.
  UText empty_ = UTEXT_INITIALIZER;
};

std::unique_ptr<FileChangesMatcher> FileChangesMatcher::Create(NSRegularExpression* re) {
  NSString* pattern = re.pattern;
  std::vector<UChar> chars(pattern.length);
  [pattern getCharacters:reinterpret_cast<unichar*>(chars.data())
                   range:NSMakeRange(0, pattern.length)];

  UErrorCode status = U_ZERO_ERROR;
  // re.options is not read. Flags 0 match the options:0 that SNTConfigurator
  // compiles FileChangesRegex with (expressionForPattern:). If those options
  // change, the flags here must change to match.
  URegularExpression* uregex =
      uregex_open(chars.data(), static_cast<int32_t>(chars.size()), 0, nullptr, &status);
  if (U_FAILURE(status)) {
    if (uregex) uregex_close(uregex);
    return nullptr;
  }

  // The destructor releases whatever was opened.
  std::unique_ptr<FileChangesMatcher> matcher(new FileChangesMatcher(uregex));
  utext_openUTF8(&matcher->empty_, "", 0, &status);
  utext_openUTF8(&matcher->text_, "", 0, &status);
  uregex_setUText(uregex, &matcher->empty_, &status);
  if (U_FAILURE(status)) {
    return nullptr;
  }
  return matcher;
}

FileChangesMatcher::~FileChangesMatcher() {
  uregex_close(re_);
  utext_close(&text_);
  utext_close(&empty_);
}

bool FileChangesMatcher::Matches(std::string_view path) {
  UErrorCode status = U_ZERO_ERROR;
  utext_openUTF8(&text_, path.data(), static_cast<int64_t>(path.size()), &status);
  uregex_setUText(re_, &text_, &status);
  bool found = U_SUCCESS(status) && uregex_find(re_, 0, &status) && U_SUCCESS(status);

  // The regex keeps a reference to the path bytes, which belong to the
  // message. Point it back at "" so nothing refers to them after this returns.
  // ICU calls do nothing when the status already holds an error, so use a
  // fresh one.
  UErrorCode reset = U_ZERO_ERROR;
  uregex_setUText(re_, &empty_, &reset);
  utext_openUTF8(&text_, "", 0, &reset);
  return found;
}

}  // namespace

@interface SNTEndpointSecurityRecorder ()
@property SNTCompilerController* compilerController;
@property(nonatomic, strong) id<SNTLoginWindowSessionHandler> loginWindowSessionHandler;
@property SNTConfigurator* configurator;
@end

@implementation SNTEndpointSecurityRecorder {
  std::shared_ptr<Enricher> _enricher;
  std::shared_ptr<Logger> _logger;
  std::shared_ptr<PrefixTree<Unit>> _prefixTree;

  SNTKVOManager* _fileChangesRegexKVO;
  absl::Mutex _fileChangesMu;
  // Guarded by _fileChangesMu. Null when no FileChangesRegex is configured.
  std::unique_ptr<FileChangesMatcher> _fileChangesMatcher;
}

- (instancetype)initWithESAPI:(std::shared_ptr<EndpointSecurityAPI>)esApi
                      metrics:(std::shared_ptr<santa::ESMetricsObserver>)metrics
                       logger:(std::shared_ptr<Logger>)logger
                     enricher:(std::shared_ptr<Enricher>)enricher
           compilerController:(SNTCompilerController*)compilerController
    loginWindowSessionHandler:(id<SNTLoginWindowSessionHandler>)loginWindowSessionHandler
                   prefixTree:(std::shared_ptr<PrefixTree<Unit>>)prefixTree
                  processTree:(std::shared_ptr<ProcessTree>)processTree {
  self = [super initWithESAPI:std::move(esApi)
                      metrics:std::move(metrics)
                    processor:santa::Processor::kRecorder
                  processTree:std::move(processTree)];
  if (self) {
    _enricher = enricher;
    _logger = logger;
    _compilerController = compilerController;
    _loginWindowSessionHandler = loginWindowSessionHandler;
    _prefixTree = prefixTree;
    _configurator = [SNTConfigurator configurator];

    // Watch before reading so a change in between is not missed.
    WEAKIFY(self);
    _fileChangesRegexKVO = [[SNTKVOManager alloc]
        initWithObject:_configurator
              selector:@selector(fileChangesRegex)
                  type:[NSRegularExpression class]
              callback:^(NSRegularExpression* oldValue, NSRegularExpression* newValue) {
                // Every config reload builds a new NSRegularExpression, so
                // compare patterns to skip recompiling an unchanged one.
                if (oldValue == newValue || [oldValue.pattern isEqualToString:newValue.pattern]) {
                  return;
                }
                STRONGIFY(self);
                [self setFileChangesRegex:newValue];
              }];
    [self setFileChangesRegex:_configurator.fileChangesRegex];

    [self establishClientOrDie];
  }
  return self;
}

- (NSString*)description {
  return @"Recorder";
}

- (void)setFileChangesRegex:(NSRegularExpression*)re {
  std::unique_ptr<FileChangesMatcher> matcher = re ? FileChangesMatcher::Create(re) : nullptr;
  if (re && !matcher) {
    LOGE(@"Failed to compile FileChangesRegex \"%@\" with ICU. File changes will not be logged.",
         re.pattern);
  }

  absl::MutexLock lock(_fileChangesMu);
  _fileChangesMatcher = std::move(matcher);
}

- (void)handleMessage:(Message&&)esMsg
    recordEventMetrics:(void (^)(EventDisposition))recordEventMetrics {
  // Pre-enrichment processing
  switch (esMsg->event_type) {
    case ES_EVENT_TYPE_NOTIFY_CLOSE: {
      // If something was mmaped writable it was probably written to. Often
      // developer tools do this to avoid lots of write syscalls, e.g. go's
      // tool chain. We log this so the compiler controller can take that into
      // account.
      if (!esMsg->event.close.modified && !esMsg->event.close.was_mapped_writable) {
        // Ignore unmodified files
        // Note: Do not record metrics in this case. These are not considered "drops"
        // because this is not a failure case. Ideally we would tell ES to not send
        // these events in the first place but no such mechanism currently exists.
        return;
      }

      break;
    }

    default: break;
  }

  bool recordDrop = false;
  bool willLog = [self willLogMessage:esMsg recordDrop:&recordDrop];
  if (willLog) {
    // The compiler controller can spend a while hashing, so the token must
    // exist before it runs.
    [self attachProcessToken:esMsg];
  }

  [self.compilerController handleEvent:esMsg withLogger:self->_logger];

  // Taken before any of the Recorder's drop returns, so a mark outlives its
  // hold only if its NOTIFY_EXEC never reaches this handler.
  bool heldExecution =
      esMsg->event_type == ES_EVENT_TYPE_NOTIFY_EXEC &&
      [[SNTDecisionCache sharedCache] takeHeldExecution:esMsg->event.exec.target->audit_token];

  switch (esMsg->event_type) {
    case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK:
      [self.loginWindowSessionHandler
          handleLoginWindowSessionEvent:esMsg->event_type
                               username:santa::StringToNSString(santa::StringTokenToStringView(
                                            esMsg->event.lw_session_lock->username))];
      break;
    case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT:
      [self.loginWindowSessionHandler
          handleLoginWindowSessionEvent:esMsg->event_type
                               username:santa::StringToNSString(santa::StringTokenToStringView(
                                            esMsg->event.lw_session_logout->username))];
      break;
    default: break;
  }

  if (!willLog) {
    if (recordDrop) {
      recordEventMetrics(EventDisposition::kDropped);
    }
    return;
  }

  // For NOTIFY_EXEC of a held execution (pending authorization, or held for a
  // transitive rule), skip logging here. The execution controller logs the
  // event with its final decision once the hold resolves.
  if (esMsg->event_type == ES_EVENT_TYPE_NOTIFY_EXEC) {
    if (heldExecution) {
      return;
    }
    SNTCachedDecision* cd = [[SNTDecisionCache sharedCache]
        cachedDecisionForFile:esMsg->event.exec.target->executable->stat];
    if (cd.holdAndAsk) {
      return;
    }
  }

  // Enrich the message inline with the ES handler block to capture enrichment
  // data as close to the source event as possible.
  std::unique_ptr<EnrichedMessage> enrichedMessage = _enricher->Enrich(std::move(esMsg));

  if (!enrichedMessage) {
    recordEventMetrics(EventDisposition::kDropped);
    return;
  }

  // Asynchronously log the message
  [self processEnrichedMessage:std::move(enrichedMessage)
                       handler:^(std::unique_ptr<EnrichedMessage> msg) {
                         self->_logger->Log(std::move(msg));
                         recordEventMetrics(EventDisposition::kProcessed);
                       }];
}

// The Enricher is the Recorder's only tree reader, so the Recorder builds its
// token in handleMessage: once it knows the message will be logged.
- (bool)attachesProcessTokenEagerly {
  return false;
}

// Whether handleMessage: will log the message, before the exec hold checks.
// Has no side effects, so it can run before the compiler controller. Sets
// *recordDrop when the drop counts toward metrics.
// ponytail: recordDrop is an out-param, not a recordEventMetrics call, because
// recording the drop here would stop the processing-time metric before the
// compiler controller runs.
- (bool)willLogMessage:(Message&)esMsg recordDrop:(bool*)recordDrop {
  // The logger will take care of this, but we check early so we
  // don't do any unnecessary work
  if (!_logger->ShouldLog(santa::ESEventToTelemetryEvent(esMsg->event_type))) {
    *recordDrop = true;
    return false;
  }

  switch (esMsg->event_type) {
    case ES_EVENT_TYPE_NOTIFY_CLONE: OS_FALLTHROUGH;
    case ES_EVENT_TYPE_NOTIFY_CLOSE: OS_FALLTHROUGH;
    case ES_EVENT_TYPE_NOTIFY_COPYFILE: OS_FALLTHROUGH;
    case ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA: OS_FALLTHROUGH;
    case ES_EVENT_TYPE_NOTIFY_LINK: OS_FALLTHROUGH;
    case ES_EVENT_TYPE_NOTIFY_RENAME: OS_FALLTHROUGH;
    case ES_EVENT_TYPE_NOTIFY_UNLINK: {
      // Only log file changes that match the given regex. When no regex is
      // configured, or it failed to compile, these events are never logged, so
      // bail before inspecting any targets.
      absl::MutexLock lock(self->_fileChangesMu);
      if (!self->_fileChangesMatcher) {
        // Note: Do not record metrics in this case. These are not considered "drops"
        // because this is not a failure case.
        // TODO(mlw): Consider changes to configuration that would allow muting paths
        // to filter on the kernel side rather than in user space.
        return false;
      }

      // Events like rename, clone, copyfile, exchangedata, and link have more than
      // one target. Log the event if any target is outside FileChangesPrefixFilters
      // and matches FileChangesRegex, so e.g. a rename from a filtered path into a
      // watched path is still logged.
      bool shouldLog = false;
      bool prefixFiltered = false;
      for (const Message::PathTarget& target : esMsg.PathTargets()) {
        std::string_view path = target.Path();
        // Path() is always null-terminated
        if (self->_prefixTree->HasPrefix(path.data())) {
          prefixFiltered = true;
          continue;
        }

        if (self->_fileChangesMatcher->Matches(path)) {
          shouldLog = true;
          break;
        }
      }

      if (!shouldLog) {
        // Note: Only prefix filtered events are recorded as drops. Regex misses are
        // not considered a failure case.
        *recordDrop = prefixFiltered;
        return false;
      }

      break;
    }

    default: break;
  }

  return true;
}

- (void)enable {
  // clang-format off
  std::set<es_event_type_t> events{
    ES_EVENT_TYPE_NOTIFY_CLONE,
    ES_EVENT_TYPE_NOTIFY_CLOSE,
    ES_EVENT_TYPE_NOTIFY_COPYFILE,
    ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED,
    ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA,
    ES_EVENT_TYPE_NOTIFY_EXEC,
    ES_EVENT_TYPE_NOTIFY_EXIT,
    ES_EVENT_TYPE_NOTIFY_FORK,
    ES_EVENT_TYPE_NOTIFY_LINK,
    ES_EVENT_TYPE_NOTIFY_RENAME,
    ES_EVENT_TYPE_NOTIFY_UNLINK,
    ES_EVENT_TYPE_NOTIFY_AUTHENTICATION,
    ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN,
    ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT,
    ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN,
    ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT,
    ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK,
    ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK,
    ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH,
    ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH,
    ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN,
    ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT,
    ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD,
    ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE,
    ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED,
    ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED,
    ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME,
  };

#if HAVE_MACOS_15
  if (@available(macOS 15.0, *)) {
    events.insert(ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE);
  }
#endif  // HAVE_MACOS_15

#if HAVE_MACOS_15_4
  if (@available(macOS 15.4, *)) {
    events.insert(ES_EVENT_TYPE_NOTIFY_TCC_MODIFY);
  }
#endif  // HAVE_MACOS_15_4
  // clang-format on

  [super subscribe:events];
}

@end
