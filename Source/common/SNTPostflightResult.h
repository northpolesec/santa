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

#import <Foundation/Foundation.h>

#include "Source/common/SNTCommonEnums.h"

@class SNTSyncState;

@interface SNTPostflightResult : NSObject <NSSecureCoding>

- (instancetype)initWithSyncState:(SNTSyncState *)syncState;

/// If the value for the backing property was set, the given block will be called.
- (void)clientMode:(void (^)(SNTClientMode))block;
- (void)syncType:(void (^)(SNTSyncType))block;
- (void)allowlistRegex:(void (^)(NSString *))block;
- (void)blocklistRegex:(void (^)(NSString *))block;
- (void)blockUSBMount:(void (^)(BOOL))block;
- (void)remountUSBMode:(void (^)(NSArray *))block;
- (void)enableBundles:(void (^)(BOOL))block;
- (void)enableTransitiveRules:(void (^)(BOOL))block;
- (void)enableAllEventUpload:(void (^)(BOOL))block;
- (void)disableUnknownEventUpload:(void (^)(BOOL))block;
- (void)overrideFileAccessAction:(void (^)(NSString *))block;

@end
