/// Copyright 2015 Google Inc. All rights reserved.
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

#import "Source/gui/SNTSystemExtensionDelegate.h"

#import <NetworkExtension/NetworkExtension.h>

#import "Source/common/SNTLogging.h"
#import "Source/common/SNTXPCControlInterface.h"

@implementation SNTSystemExtensionDelegate

- (instancetype)initForNetworkExtension:(BOOL)isNetworkExtension activation:(BOOL)isActivation {
  self = [super init];
  if (self) {
    _isNetworkExtension = isNetworkExtension;
    _isActivation = isActivation;

    dispatch_queue_t queue = dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0);

    NSString *bundleID = [SNTXPCControlInterface santaExtensionBundleID];
    if (isNetworkExtension) {
      bundleID = [SNTXPCControlInterface santanetdExtensionBundleID];
    }

    if (isActivation) {
      _request = [OSSystemExtensionRequest activationRequestForExtension:bundleID queue:queue];
    } else {
      _request = [OSSystemExtensionRequest deactivationRequestForExtension:bundleID queue:queue];
    }

    _request.delegate = self;
  }
  return self;
}

+ (instancetype)delegateForSantadActivation {
  return [[self alloc] initForNetworkExtension:NO activation:YES];
}

+ (instancetype)delegateForSantadDeactivation {
  return [[self alloc] initForNetworkExtension:NO activation:NO];
}

+ (instancetype)delegateForSantanetdActivation {
  return [[self alloc] initForNetworkExtension:YES activation:YES];
}

+ (instancetype)delegateForSantanetdDeactivation {
  return [[self alloc] initForNetworkExtension:YES activation:NO];
}

- (void)submit {
  if (self.isNetworkExtension && !self.isActivation) {
    [self disableFilterConfiguration];
  }
  [[OSSystemExtensionManager sharedManager] submitRequest:self.request];
}

#pragma mark OSSystemExtensionRequestDelegate

- (OSSystemExtensionReplacementAction)request:(OSSystemExtensionRequest *)request
                  actionForReplacingExtension:(OSSystemExtensionProperties *)oldExt
                                withExtension:(OSSystemExtensionProperties *)newExt {
  LOGI(@"SystemExtension \"%@\" request for replacement", request.identifier);
  return OSSystemExtensionReplacementActionReplace;
}

- (void)requestNeedsUserApproval:(OSSystemExtensionRequest *)request {
  LOGI(@"SystemExtension \"%@\" request needs user approval", request.identifier);

  // If the sysx is not authorized, don't wait around. macOS will start the sysx once authorized.
  exit(1);
}

- (void)request:(OSSystemExtensionRequest *)request didFailWithError:(NSError *)error {
  LOGE(@"SystemExtension \"%@\" request did fail: %@", request.identifier, error);
  exit((int)error.code);
}

- (void)request:(OSSystemExtensionRequest *)request
    didFinishWithResult:(OSSystemExtensionRequestResult)result {
  LOGI(@"SystemExtension \"%@\" request did finish: %ld", request.identifier, (long)result);

  // If this is a network extension, we need to configure the content filter
  // if (self.isNetworkExtension) {
  //   if (self.isActivation) {
  //     [self enableFilterConfiguration];
  //   } else {
  //     [self disableFilterConfiguration];
  //   }
  if (self.isNetworkExtension && self.isActivation) {
    [self enableFilterConfiguration];
  } else {
    exit(0);
  }
}

- (void)enableFilterConfiguration {
  LOGI(@"Configuring content filter for network extension");

  NEFilterManager *manager = [NEFilterManager sharedManager];
  [manager loadFromPreferencesWithCompletionHandler:^(NSError *error) {
    if (error) {
      LOGE(@"Failed to load filter preferences: %@", error);
      exit(1);
      return;
    }

    NEFilterProviderConfiguration *providerConfig = [[NEFilterProviderConfiguration alloc] init];
    providerConfig.filterSockets = YES;
    providerConfig.filterPackets = NO;
    providerConfig.organization = @"North Pole Security";
    providerConfig.filterDataProviderBundleIdentifier = @"com.northpolesec.santa.netd";

    manager.providerConfiguration = providerConfig;
    manager.localizedDescription = @"Santa Network Extension";
    manager.enabled = YES;

    [manager saveToPreferencesWithCompletionHandler:^(NSError *saveError) {
      if (saveError) {
        LOGE(@"Failed to save filter configuration: %@", saveError);
        exit(1);
      } else {
        LOGI(@"Filter configuration saved and enabled - network extension will launch "
             @"automatically");
        exit(0);
      }
    }];
  }];
}

- (void)disableFilterConfiguration {
  LOGI(@"Removing content filter configuration");

  dispatch_semaphore_t sema = dispatch_semaphore_create(0);

  NEFilterManager *manager = [NEFilterManager sharedManager];
  [manager loadFromPreferencesWithCompletionHandler:^(NSError *error) {
    if (error) {
      LOGE(@"Unable to load save preferences while trying to deactivate the extension: %@", error);
      dispatch_semaphore_signal(sema);
      return;
    }

    [manager removeFromPreferencesWithCompletionHandler:^(NSError *removeError) {
      if (removeError) {
        LOGE(@"Failed to remove filter configuration: %@", removeError);
      } else {
        LOGI(@"Filter configuration removed successfully");
      }

      dispatch_semaphore_signal(sema);
    }];
  }];

  if (dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC))) {
    LOGW(@"Unable to remove filter configuration profile.");
  }
}

@end
