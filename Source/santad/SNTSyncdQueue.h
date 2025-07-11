/// Copyright 2016 Google Inc. All rights reserved.
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

#import "Source/common/SNTCommonEnums.h"

@class SNTExportConfiguration;
@class SNTStoredEvent;
@class MOLXPCConnection;

@interface SNTSyncdQueue : NSObject

- (void)reassessSyncServiceConnection;
- (void)reassessSyncServiceConnectionImmediately;

- (void)addEvents:(NSArray<SNTStoredEvent *> *)events isFromBundle:(BOOL)isFromBundle;
- (void)addBundleEvent:(SNTStoredEvent *)event reply:(void (^)(SNTBundleEventAction))reply;
- (void)exportTelemetryFile:(NSFileHandle *)telemetryFile
                   fileName:(NSString *)fileName
                     config:(SNTExportConfiguration *)config
          completionHandler:(void (^)(BOOL))completionHandler;

@end
