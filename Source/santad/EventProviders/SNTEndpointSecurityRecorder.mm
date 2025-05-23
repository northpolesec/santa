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

#include <EndpointSecurity/EndpointSecurity.h>

#include "Source/common/Platform.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTLogging.h"
#include "Source/common/String.h"
#include "Source/common/TelemetryEventMap.h"
#include "Source/santad/EventProviders/AuthResultCache.h"
#include "Source/santad/EventProviders/EndpointSecurity/EnrichedTypes.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/Metrics.h"
#include "Source/santad/ProcessTree/process_tree.h"

using santa::AuthResultCache;
using santa::EndpointSecurityAPI;
using santa::EnrichedMessage;
using santa::Enricher;
using santa::EventDisposition;
using santa::Logger;
using santa::Message;
using santa::PrefixTree;
using santa::Unit;
using santa::santad::process_tree::ProcessTree;

es_file_t *GetTargetFileForPrefixTree(const es_message_t *msg) {
  switch (msg->event_type) {
    case ES_EVENT_TYPE_NOTIFY_CLONE: return msg->event.clone.source;
    case ES_EVENT_TYPE_NOTIFY_CLOSE: return msg->event.close.target;
    case ES_EVENT_TYPE_NOTIFY_COPYFILE: return msg->event.copyfile.source;
    case ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA: return msg->event.exchangedata.file1;
    case ES_EVENT_TYPE_NOTIFY_LINK: return msg->event.link.source;
    case ES_EVENT_TYPE_NOTIFY_RENAME: return msg->event.rename.source;
    case ES_EVENT_TYPE_NOTIFY_UNLINK: return msg->event.unlink.target;
    default: return NULL;
  }
}

@interface SNTEndpointSecurityRecorder ()
@property SNTCompilerController *compilerController;
@property SNTConfigurator *configurator;
@end

@implementation SNTEndpointSecurityRecorder {
  std::shared_ptr<AuthResultCache> _authResultCache;
  std::shared_ptr<Enricher> _enricher;
  std::shared_ptr<Logger> _logger;
  std::shared_ptr<PrefixTree<Unit>> _prefixTree;
}

- (instancetype)initWithESAPI:(std::shared_ptr<EndpointSecurityAPI>)esApi
                      metrics:(std::shared_ptr<santa::Metrics>)metrics
                       logger:(std::shared_ptr<Logger>)logger
                     enricher:(std::shared_ptr<Enricher>)enricher
           compilerController:(SNTCompilerController *)compilerController
              authResultCache:(std::shared_ptr<AuthResultCache>)authResultCache
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
    _authResultCache = authResultCache;
    _prefixTree = prefixTree;
    _configurator = [SNTConfigurator configurator];

    [self establishClientOrDie];
  }
  return self;
}

- (NSString *)description {
  return @"Recorder";
}

- (void)handleMessage:(Message &&)esMsg
    recordEventMetrics:(void (^)(EventDisposition))recordEventMetrics {
  // Pre-enrichment processing
  switch (esMsg->event_type) {
    case ES_EVENT_TYPE_NOTIFY_CLOSE: {
      BOOL shouldLogClose = esMsg->event.close.modified;

      if (esMsg->version >= 6) {
        // As of macSO 13.0 we have a new field for if a file was mmaped with
        // write permissions on close events. However due to a bug in ES, it
        // only worked for certain conditions until macOS 13.5 (FB12094635).
        //
        // If something was mmaped writable it was probably written to. Often
        // developer tools do this to avoid lots of write syscalls, e.g. go's
        // tool chain. We log this so the compiler controller can take that into
        // account.
        shouldLogClose |= esMsg->event.close.was_mapped_writable;
      }

      if (!shouldLogClose) {
        // Ignore unmodified files
        // Note: Do not record metrics in this case. These are not considered "drops"
        // because this is not a failure case. Ideally we would tell ES to not send
        // these events in the first place but no such mechanism currently exists.
        return;
      }

      self->_authResultCache->RemoveFromCache(esMsg->event.close.target);

      break;
    }

    default: break;
  }

  [self.compilerController handleEvent:esMsg withLogger:self->_logger];

  // The logger will take care of this, but we check early so we
  // don't do any unnecessary work
  if (!_logger->ShouldLog(santa::ESEventToTelemetryEvent(esMsg->event_type))) {
    recordEventMetrics(EventDisposition::kDropped);
    return;
  }

  switch (esMsg->event_type) {
    case ES_EVENT_TYPE_NOTIFY_CLONE: OS_FALLTHROUGH;
    case ES_EVENT_TYPE_NOTIFY_CLOSE: OS_FALLTHROUGH;
    case ES_EVENT_TYPE_NOTIFY_COPYFILE: OS_FALLTHROUGH;
    case ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA: OS_FALLTHROUGH;
    case ES_EVENT_TYPE_NOTIFY_LINK: OS_FALLTHROUGH;
    case ES_EVENT_TYPE_NOTIFY_RENAME: OS_FALLTHROUGH;
    case ES_EVENT_TYPE_NOTIFY_UNLINK: {
      es_file_t *targetFile = GetTargetFileForPrefixTree(&(*esMsg));

      if (!targetFile) {
        break;
      }

      // Only log file changes that match the given regex
      NSString *targetPath = santa::StringToNSString(targetFile->path.data);
      if (![[self.configurator fileChangesRegex]
              numberOfMatchesInString:targetPath
                              options:0
                                range:NSMakeRange(0, targetPath.length)]) {
        // Note: Do not record metrics in this case. These are not considered "drops"
        // because this is not a failure case.
        // TODO(mlw): Consider changes to configuration that would allow muting paths
        // to filter on the kernel side rather than in user space.
        return;
      }

      if (self->_prefixTree->HasPrefix(targetFile->path.data)) {
        recordEventMetrics(EventDisposition::kDropped);
        return;
      }

      break;
    }

    default: break;
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
