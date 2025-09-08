/// Copyright 2020 Google Inc. All rights reserved.
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

#import "Source/common/SNTXPCSyncServiceInterface.h"

@implementation SNTXPCSyncServiceInterface

+ (NSXPCInterface *)syncServiceInterface {
  NSXPCInterface *r = [NSXPCInterface interfaceWithProtocol:@protocol(SNTSyncServiceXPC)];

  [r setClasses:[NSSet setWithObjects:[NSArray class], [SNTStoredEvent class],
                                      [SNTStoredExecutionEvent class],
                                      [SNTStoredFileAccessEvent class], nil]
        forSelector:@selector(postEventsToSyncServer:)
      argumentIndex:0
            ofReply:NO];

  [r setClasses:[NSSet setWithObjects:[NSArray class], [NSFileHandle class], nil]
        forSelector:@selector(exportTelemetryFiles:fileName:totalSize:contentType:config:reply:)
      argumentIndex:0
            ofReply:NO];

  return r;
}

+ (NSString *)serviceID {
  return @"com.northpolesec.santa.syncservice";
}

+ (MOLXPCConnection *)configuredConnection {
  MOLXPCConnection *c = [[MOLXPCConnection alloc] initClientWithName:[self serviceID]
                                                          privileged:YES];
  c.remoteInterface = [self syncServiceInterface];
  return c;
}

@end
