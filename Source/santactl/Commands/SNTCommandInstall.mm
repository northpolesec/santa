/// Copyright 2024 North Pole Security, Inc.
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

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTLiteDetector.h"
#include "Source/common/SNTLogging.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/common/SNTXPCUnprivilegedControlInterface.h"
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

+ (NSString*)shortHelpText {
  return @"Instruct the daemon to install Santa.app or santanetd.";
}

+ (NSString*)longHelpText {
  return @"Instruct the daemon to install Santa.app.\n"
         @"Options:\n"
         @"  --network-extension:  Install and activate the santanetd content filter instead.\n"
         @"                        WARNING: All network connections will reset.\n"
         @"  --allow-downgrade:    Allow installing a Lite variant when SyncV2 is enabled.\n";
}

+ (BOOL)isHidden {
  return YES;
}

- (void)runWithArguments:(NSArray*)arguments {
  BOOL installNetworkExtension = NO;
  BOOL allowDowngrade = NO;

  for (NSString* arg in arguments) {
    if ([arg caseInsensitiveCompare:@"--network-extension"] == NSOrderedSame) {
      installNetworkExtension = YES;
    } else if ([arg caseInsensitiveCompare:@"--allow-downgrade"] == NSOrderedSame) {
      allowDowngrade = YES;
    }
  }

  if (installNetworkExtension) {
    [self installNetworkExtension];
  } else {
    [self installSantaApp:allowDowngrade];
  }

  // Each install action is responsible for exiting appropriately
  exit(EXIT_FAILURE);
}

- (void)installNetworkExtension {
  int64_t secondsToWait = 60;

  TEE_LOGI(@"Requesting Santa network extension installation...");
  TEE_LOGI(@"...Waiting for up to %lld seconds...", secondsToWait);
  TEE_LOGI(@"NOTE: All network connections will reset when the extension activates.");

  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  __block BOOL success = NO;
  [[self.daemonConn remoteObjectProxy] installNetworkExtension:^(BOOL installTriggered) {
    success = installTriggered;
    if (success) {
      TEE_LOGI(@"Network extension installation was successful");
    } else {
      TEE_LOGW(@"Network extension installation unsuccessful. Is this machine authorized? "
               @"Please consult logs.");
    }

    dispatch_semaphore_signal(sema);
  }];

  if (dispatch_semaphore_wait(sema,
                              dispatch_time(DISPATCH_TIME_NOW, secondsToWait * NSEC_PER_SEC)) > 0) {
    TEE_LOGW(@"Timed out waiting for network extension install to complete.");
    exit(EXIT_FAILURE);
  }

  exit(success ? EXIT_SUCCESS : EXIT_FAILURE);
}

- (void)installSantaApp:(BOOL)allowDowngrade {
  NSString* installFromPath = @"/var/db/santa/migration/Santa.app";

  if (santa::SNTIsLiteAppBundle(installFromPath)) {
    __block BOOL isSyncV2 = NO;
    [[self.daemonConn synchronousRemoteObjectProxy] isSyncV2Enabled:^(BOOL val) {
      isSyncV2 = val;
    }];

    if (isSyncV2 && !allowDowngrade) {
      TEE_LOGE(@"Refusing to install Lite variant while SyncV2 is enabled. "
               @"Use --allow-downgrade to override.");
      exit(EXIT_FAILURE);
    } else if (isSyncV2 && allowDowngrade) {
      TEE_LOGW(@"Installing Lite variant with --allow-downgrade while SyncV2 is enabled.");
    }
  }

  int64_t secondsToWait = 15;

  TEE_LOGI(@"Asking daemon to install: %@", installFromPath);
  TEE_LOGI(@"...Waiting for up to %lld seconds...", secondsToWait);

  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  [[self.daemonConn remoteObjectProxy]
      installSantaApp:installFromPath
                reply:^(BOOL success) {
                  if (success) {
                    TEE_LOGI(@"Installation was successful");
                  } else {
                    TEE_LOGI(
                        @"Installation unsuccessful. Please consult logs for more information.");
                  }

                  dispatch_semaphore_signal(sema);
                }];

  if (dispatch_semaphore_wait(sema,
                              dispatch_time(DISPATCH_TIME_NOW, secondsToWait * NSEC_PER_SEC)) > 0) {
    TEE_LOGW(@"Timed out waiting for install to complete.");
    exit(EXIT_FAILURE);
  }

  exit(EXIT_SUCCESS);
}

@end
