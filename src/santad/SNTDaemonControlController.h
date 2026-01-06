/// Copyright 2015-2022 Google Inc. All rights reserved.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///    http://www.apache.org/licenses/LICENSE-2.0
///
///    Unless required by applicable law or agreed to in writing, software
///    distributed under the License is distributed on an "AS IS" BASIS,
///    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
///    See the License for the specific language governing permissions and
///    limitations under the License.

#import <Foundation/Foundation.h>

#include <memory>

#import "src/common/SNTXPCControlInterface.h"
#include "src/common/faa/WatchItems.h"
#include "src/santad/event_providers/AuthResultCache.h"
#import "src/santad/logs/endpoint_security/Logger.h"

@class SNTNotificationQueue;
@class SNTSyncdQueue;

///
///  SNTDaemonControlController handles all of the RPCs from santactl
///
@interface SNTDaemonControlController : NSObject <SNTDaemonControlXPC>

- (instancetype)initWithAuthResultCache:(std::shared_ptr<santa::AuthResultCache>)authResultCache
                      notificationQueue:(SNTNotificationQueue *)notQueue
                             syncdQueue:(SNTSyncdQueue *)syncdQueue
                                 logger:(std::shared_ptr<santa::Logger>)logger
                             watchItems:(std::shared_ptr<santa::WatchItems>)watchItems;

@end
