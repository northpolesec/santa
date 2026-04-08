/// Copyright 2021-2022 Google Inc. All rights reserved.
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

#include <DiskArbitration/DiskArbitration.h>
#import <Foundation/Foundation.h>

#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTDeviceEvent.h"
#import "Source/common/SNTStoredNetworkMountEvent.h"
#import "Source/common/SNTStoredUSBMountEvent.h"
#include "Source/common/es/ESMetricsObserver.h"
#include "Source/common/es/EndpointSecurityAPI.h"
#include "Source/common/es/Enricher.h"
#import "Source/common/es/SNTEndpointSecurityClient.h"
#import "Source/common/es/SNTEndpointSecurityEventHandler.h"
#import "Source/santad/EventProviders/AuthResultCache.h"
#include "Source/santad/Logs/EndpointSecurity/Logger.h"

NS_ASSUME_NONNULL_BEGIN

typedef void (^SNTDeviceBlockCallback)(SNTDeviceEvent* event, SNTStoredUSBMountEvent* usbEvent);
typedef void (^SNTNetworkMountCallback)(SNTStoredNetworkMountEvent* event);

/*
 * Manages DiskArbitration and EndpointSecurity to monitor/block/remount USB
 * storage devices.
 */
@interface SNTEndpointSecurityDeviceManager
    : SNTEndpointSecurityClient <SNTEndpointSecurityEventHandler>

@property(nonatomic, readwrite) SNTRemovableMediaAction removableMediaAction;
@property(nonatomic, readwrite, nullable) NSArray<NSString*>* removableMediaRemountFlags;
@property(nonatomic, readwrite) SNTRemovableMediaAction encryptedRemovableMediaAction;
@property(nonatomic, readwrite, nullable) NSArray<NSString*>* encryptedRemovableMediaRemountFlags;
@property(nonatomic, nullable) SNTDeviceBlockCallback deviceBlockCallback;
@property(nonatomic, nullable) SNTNetworkMountCallback networkMountCallback;

- (instancetype)initWithESAPI:(std::shared_ptr<santa::EndpointSecurityAPI>)esApi
                                metrics:(std::shared_ptr<santa::ESMetricsObserver>)metrics
                                 logger:(std::shared_ptr<santa::Logger>)logger
                               enricher:(std::shared_ptr<santa::Enricher>)enricher
                        authResultCache:(std::shared_ptr<santa::AuthResultCache>)authResultCache
                   removableMediaAction:(SNTRemovableMediaAction)removableMediaAction
             removableMediaRemountFlags:(nullable NSArray<NSString*>*)removableMediaRemountFlags
          encryptedRemovableMediaAction:(SNTRemovableMediaAction)encryptedRemovableMediaAction
    encryptedRemovableMediaRemountFlags:
        (nullable NSArray<NSString*>*)encryptedRemovableMediaRemountFlags
                     startupPreferences:(SNTDeviceManagerStartupPreferences)startupPrefs;

@end

NS_ASSUME_NONNULL_END
