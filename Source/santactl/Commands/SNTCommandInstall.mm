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
  return @"Instruct the daemon to install Santa.app.";
}

+ (NSString *)longHelpText {
  return @"Instruct the daemon to install Santa.app.\n\n";
}

+ (BOOL)isHidden {
  return YES;
}

- (void)runWithArguments:(NSArray *)arguments {
  NSString *installFromPath = @"/Library/Caches/com.northpolesec.santa/Santa.app";
  int64_t secondsToWait = 15;

  LOGI(@"Asking daemon to install: %@", installFromPath);
  LOGI(@"...Waitng for up to %lld seconds...", secondsToWait);

  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  [[self.daemonConn remoteObjectProxy]
    installSantaApp:installFromPath
              reply:^(BOOL success) {
                if (success) {
                  LOGI(@"Installation was successful");
                } else {
                  LOGI(@"Installation unsuccessful. Please consult logs for more information.");
                }

                dispatch_semaphore_signal(sema);
              }];

  if (dispatch_semaphore_wait(sema,
                              dispatch_time(DISPATCH_TIME_NOW, secondsToWait * NSEC_PER_SEC)) > 0) {
    LOGW(@"Timed out waiting for install to complete.");
    exit(EXIT_FAILURE);
  }

  exit(EXIT_SUCCESS);
}

@end
