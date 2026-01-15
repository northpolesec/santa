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

#import <Cocoa/Cocoa.h>
#import <SystemExtensions/SystemExtensions.h>

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/gui/SNTAppDelegate.h"

@interface SNTSystemExtensionDelegate : NSObject <OSSystemExtensionRequestDelegate>
@end

@implementation SNTSystemExtensionDelegate

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
  exit(0);
}

@end

int main(int argc, const char *argv[]) {
  @autoreleasepool {
    OSSystemExtensionRequest *req;
    NSArray *args = [NSProcessInfo processInfo].arguments;
    dispatch_queue_t q = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0);

    if ([args containsObject:@"--load-system-extension"]) {
      LOGI(@"Requesting Santa System Extension activation");
      req = [OSSystemExtensionRequest
          activationRequestForExtension:[SNTXPCControlInterface santaExtensionBundleID]
                                  queue:q];
    } else if ([args containsObject:@"--unload-system-extension"]) {
      LOGI(@"Requesting Santa System Extension deactivation");
      req = [OSSystemExtensionRequest
          deactivationRequestForExtension:[SNTXPCControlInterface santaExtensionBundleID]
                                    queue:q];
    } else if ([args containsObject:@"--load-network-extension"]) {
      LOGI(@"Requesting Santa Network Extension (Content Filter) activation");
      LOGW(@"WARNING: All network connections will reset when filter activates");
      req = [OSSystemExtensionRequest
          activationRequestForExtension:[SNTXPCControlInterface santanetdExtensionBundleID]
                                  queue:q];
    } else if ([args containsObject:@"--unload-network-extension"]) {
      LOGI(@"Requesting Santa Network Extension (Content Filter) deactivation");
      req = [OSSystemExtensionRequest
          deactivationRequestForExtension:[SNTXPCControlInterface santanetdExtensionBundleID]
                                    queue:q];
    }

    if (req) {
      SNTSystemExtensionDelegate *ed = [[SNTSystemExtensionDelegate alloc] init];
      req.delegate = ed;
      [[OSSystemExtensionManager sharedManager] submitRequest:req];
      dispatch_after(dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC * 60), q, ^{
        LOGW(@"Timed out waiting for Santa system extension operation");
        exit(1);
      });
      [[NSRunLoop mainRunLoop] run];
    } else {
      NSApplication *app = [NSApplication sharedApplication];
      SNTAppDelegate *delegate = [[SNTAppDelegate alloc] init];
      [app setDelegate:delegate];
      [app finishLaunching];
      [app run];
    }
  }
}
