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

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTLogging.h"
#import "Source/gui/SNTAppDelegate.h"
#import "Source/gui/SNTSystemExtensionDelegate.h"

int main(int argc, const char *argv[]) {
  @autoreleasepool {
    SNTSystemExtensionDelegate *delegate;
    NSArray *args = [NSProcessInfo processInfo].arguments;

    if ([args containsObject:@"--load-system-extension"]) {
      LOGI(@"Requesting Santa System Extension activation");
      delegate = [SNTSystemExtensionDelegate delegateForSantadActivation];
    } else if ([args containsObject:@"--unload-system-extension"]) {
      LOGI(@"Requesting Santa System Extension deactivation");
      delegate = [SNTSystemExtensionDelegate delegateForSantadDeactivation];
    }
#ifdef DEBUG
    else if ([args containsObject:@"--load-network-extension"]) {
      LOGI(@"Requesting Santa Network Extension (Content Filter) activation");
      LOGW(@"WARNING: All network connections will reset when filter activates");
      delegate = [SNTSystemExtensionDelegate delegateForSantanetdActivation];
    } else if ([args containsObject:@"--unload-network-extension"]) {
      LOGI(@"Requesting Santa Network Extension (Content Filter) deactivation");
      delegate = [SNTSystemExtensionDelegate delegateForSantanetdDeactivation];
    }
#endif

    if (delegate) {
      [delegate submitAndExitAsync];

      // The call to submitAndExitAsync should trigger a process exit. But just in
      // case something funky happens, force an exit after a timeout.
      dispatch_after(dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC * 60),
                     dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
                       LOGW(@"Timed out waiting for Santa system extension operation");
                       exit(1);
                     });
      [[NSRunLoop mainRunLoop] run];
    } else {
      NSApplication *app = [NSApplication sharedApplication];
      SNTAppDelegate *appDelegate = [[SNTAppDelegate alloc] init];
      [app setDelegate:appDelegate];
      [app finishLaunching];
      [app run];
    }
  }
}
