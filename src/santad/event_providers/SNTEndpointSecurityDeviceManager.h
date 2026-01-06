/// Copyright 2021-2022 Google Inc. All rights reserved.
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

#include <DiskArbitration/DiskArbitration.h>
#import <Foundation/Foundation.h>

#import "src/common/SNTCommonEnums.h"
#import "src/common/SNTDeviceEvent.h"
#import "src/common/SNTStoredNetworkMountEvent.h"
#import "src/santad/event_providers/AuthResultCache.h"
#include "src/santad/event_providers/endpoint_security/EndpointSecurityAPI.h"
#include "src/santad/event_providers/endpoint_security/Enricher.h"
#import "src/santad/event_providers/SNTEndpointSecurityClient.h"
#import "src/santad/event_providers/SNTEndpointSecurityEventHandler.h"
#include "src/santad/logs/endpoint_security/Logger.h"
#include "src/santad/Metrics.h"

NS_ASSUME_NONNULL_BEGIN

typedef void (^SNTDeviceBlockCallback)(SNTDeviceEvent *event);
typedef void (^SNTNetworkMountCallback)(SNTStoredNetworkMountEvent *event);

/*
 * Manages DiskArbitration and EndpointSecurity to monitor/block/remount USB
 * storage devices.
 */
@interface SNTEndpointSecurityDeviceManager
    : SNTEndpointSecurityClient <SNTEndpointSecurityEventHandler>

@property(nonatomic, readwrite) BOOL blockUSBMount;
@property(nonatomic, readwrite, nullable) NSArray<NSString *> *remountArgs;
@property(nonatomic, nullable) SNTDeviceBlockCallback deviceBlockCallback;
@property(nonatomic, nullable) SNTNetworkMountCallback networkMountCallback;

- (instancetype)initWithESAPI:(std::shared_ptr<santa::EndpointSecurityAPI>)esApi
                      metrics:(std::shared_ptr<santa::Metrics>)metrics
                       logger:(std::shared_ptr<santa::Logger>)logger
                     enricher:(std::shared_ptr<santa::Enricher>)enricher
              authResultCache:(std::shared_ptr<santa::AuthResultCache>)authResultCache
                blockUSBMount:(BOOL)blockUSBMount
               remountUSBMode:(nullable NSArray<NSString *> *)remountUSBMode
           startupPreferences:(SNTDeviceManagerStartupPreferences)startupPrefs;

@end

NS_ASSUME_NONNULL_END
