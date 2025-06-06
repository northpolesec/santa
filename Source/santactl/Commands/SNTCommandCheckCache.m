/// Copyright 2016-2022 Google Inc. All rights reserved.
/// Copyright 2024 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     https://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#import <Foundation/Foundation.h>

#include <sys/stat.h>

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/santactl/SNTCommand.h"
#import "Source/santactl/SNTCommandController.h"

@interface SNTCommandCheckCache : SNTCommand <SNTCommandProtocol>
@end

@implementation SNTCommandCheckCache

REGISTER_COMMAND_NAME(@"checkcache")

+ (BOOL)requiresRoot {
  // This command is technically an information leak. Require root so that
  // normal users don't gain additional insights.
  return YES;
}

+ (BOOL)requiresDaemonConn {
  return YES;
}

+ (NSString *)shortHelpText {
  return @"Prints the authorization status of a file in the cache.";
}

+ (NSString *)longHelpText {
  return @"Prints the authorization status of a file in the cache.\n"
         @"\n"
         @"IMPORTANT: This command is intended for development purposes only.\n";
}

+ (BOOL)isHidden {
  return YES;
}

- (void)runWithArguments:(NSArray *)arguments {
  SantaVnode vnodeID = [self vnodeIDForFile:arguments.firstObject];
  [[self.daemonConn synchronousRemoteObjectProxy]
      checkCacheForVnodeID:vnodeID
                 withReply:^(SNTAction action) {
                   if (action == SNTActionRespondAllow) {
                     TEE_LOGI(@"File exists in [allowlist] cache");
                     exit(0);
                   } else if (action == SNTActionRespondDeny) {
                     TEE_LOGI(@"File exists in [blocklist] cache");
                     exit(0);
                   } else if (action == SNTActionRespondAllowCompiler) {
                     TEE_LOGI(@"File exists in [allowlist compiler] cache");
                     exit(0);
                   } else if (action == SNTActionUnset) {
                     TEE_LOGI(@"File does not exist in cache");
                     exit(0);
                   }
                 }];
}

- (SantaVnode)vnodeIDForFile:(NSString *)path {
  struct stat fstat = {};
  stat(path.fileSystemRepresentation, &fstat);
  SantaVnode ret = {.fsid = fstat.st_dev, .fileid = fstat.st_ino};
  return ret;
}

@end
