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

#import <Foundation/Foundation.h>

typedef NS_ENUM(NSInteger, SNTSignalState) {
  SNTSignalStateUnknown,
  SNTSignalStateAdd,
  SNTSignalStateRemove,
};

/// A detection signal config rule synced from the server during rule download. Add rules carry
/// the serialized santa.common.v1.Signal proto in `data`; remove rules carry only `name`. Stored
/// (add) rules in the rules database are passed to Sleigh for signal scans.
@interface SNTSignal : NSObject <NSSecureCoding>

@property(readonly) SNTSignalState state;
@property(readonly, copy) NSString* name;
@property(readonly) NSData* data;

- (instancetype)initAddRuleWithName:(NSString*)name data:(NSData*)data;
- (instancetype)initRemoveRuleWithName:(NSString*)name;

@end
