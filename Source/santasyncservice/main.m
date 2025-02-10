/// Copyright 2020 Google Inc. All rights reserved.
/// Copyright 2025 North Pole Security, Inc.
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

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTXPCSyncServiceInterface.h"
#import "Source/santasyncservice/SNTSyncService.h"

int main(int argc, const char *argv[]) {
  @autoreleasepool {
    // The LOG* functions make use of SNTConfigurator, which if initialized now will fail to update
    // values after SNTSyncService drops privileges. Since SNTConfigurator is a singleton, we need
    // to initialize it after privileges are dropped. To that end, don't log until after privileges
    // are dropped.

    MOLXPCConnection *c =
        [[MOLXPCConnection alloc] initServerWithName:[SNTXPCSyncServiceInterface serviceID]];
    c.privilegedInterface = c.unprivilegedInterface =
        [SNTXPCSyncServiceInterface syncServiceInterface];
    c.exportedObject = [[SNTSyncService alloc] init];
    [c resume];
    [[NSRunLoop mainRunLoop] run];
  }
}
