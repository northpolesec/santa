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
#import <MOLXPCConnection/MOLXPCConnection.h>

#include "Source/common/SNTLogging.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/santactl/SNTCommand.h"
#import "Source/santactl/SNTCommandController.h"

@interface SNTCommandInstall : SNTCommand <SNTCommandProtocol>
@end

@implementation SNTCommandInstall

REGISTER_COMMAND_NAME(@"install")

+ (BOOL)requiresRoot {
  return YES;
}

+ (BOOL)requiresDaemonConn {
  return YES;
}

+ (NSString *)shortHelpText {
  return @"Instruct the daemon to install Santa.app."
}

+ (NSString *)longHelpText {
  return @"Instruct the daemon to install Santa.app.\n"
         @"\n"
         @"  --path {path}: Path to the Santa.app bundle to install.\n"
         @"\n";
}

+ (BOOL)isHidden {
  return YES;
}

- (void)runWithArguments:(NSArray *)arguments {
  NSString *path;

  for (NSUInteger i = 0; i < arguments.count; ++i) {
    NSString *arg = arguments[i];

    if ([arg caseInsensitiveCompare:@"--path"] == NSOrderedSame) {
      if (++i > arguments.count - 1) {
        [self printErrorUsageAndExit:@"--path requires an argument"];
      }
      path = arguments[i];
    }
  }

  if (!path) {
    [self printErrorUsageAndExit:@"No path specified"];
  }

  LOGI(@"Asking daemon to install: %@", path);

  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  [[self.daemonConn remoteObjectProxy] installSantaApp:(NSString *)path
                                                 reply:^(BOOL success) {
                                                   LOGI(@"Got reply from daemon: %d", success);
                                                   dispatch_semaphore_signal(sema);
                                                 }];

  if (dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC)) > 0) {
    LOGW(@"Timed out waiting for install to complete.");
  }

  exit(EXIT_SUCCESS);
}

@end
