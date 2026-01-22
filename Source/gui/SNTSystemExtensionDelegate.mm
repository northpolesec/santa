/// Copyright 2026 North Pole Security, Inc.
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

#import "Source/gui/SNTSystemExtensionDelegate.h"

#include <stdlib.h>

#import "Source/common/SNTLogging.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "src/santanetd/SNDFilterConfigurationHelper.h"

@interface SNTSystemExtensionDelegate()
@property dispatch_queue_t q;
@end

@implementation SNTSystemExtensionDelegate

- (instancetype)initForNetworkExtension:(BOOL)isNetworkExtension activation:(BOOL)isActivation {
  self = [super init];
  if (self) {
    _isNetworkExtension = isNetworkExtension;
    _isActivation = isActivation;

    _q = dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0);

    NSString *bundleID = [SNTXPCControlInterface santaExtensionBundleID];
    if (isNetworkExtension) {
      bundleID = [SNTXPCControlInterface santanetdExtensionBundleID];
    }

    if (isActivation) {
      _request = [OSSystemExtensionRequest activationRequestForExtension:bundleID queue:_q];
    } else {
      _request = [OSSystemExtensionRequest deactivationRequestForExtension:bundleID queue:_q];
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

- (void)submitAndExitAsync {
  // Submit the system extension request on a background queue to avoid blocking
  // the main queue. This process will exit either after the request finishes
  // (either successfully or unsuccessfully).
  dispatch_async(self.q, ^{
    if (self.isNetworkExtension && !self.isActivation) {
      [SNDFilterConfigurationHelper disableFilterConfiguration];
    }
    [[OSSystemExtensionManager sharedManager] submitRequest:self.request];
  });
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
  exit(EXIT_FAILURE);
}

- (void)request:(OSSystemExtensionRequest *)request didFailWithError:(NSError *)error {
  LOGE(@"SystemExtension \"%@\" request did fail: %@", request.identifier, error);
  exit(EXIT_FAILURE);
}

- (void)request:(OSSystemExtensionRequest *)request
    didFinishWithResult:(OSSystemExtensionRequestResult)result {
  LOGI(@"SystemExtension \"%@\" request did finish: %ld", request.identifier, (long)result);

  BOOL success = YES;
  if (self.isNetworkExtension && self.isActivation) {
    success = [SNDFilterConfigurationHelper enableFilterConfiguration];
  }

  exit(success ? EXIT_SUCCESS : EXIT_FAILURE);
}

@end
