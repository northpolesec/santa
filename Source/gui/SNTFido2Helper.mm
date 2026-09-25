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

#import "Source/gui/SNTFido2Helper.h"

#import <Cocoa/Cocoa.h>

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTLogging.h"
#import "Source/gui/SNTMessageView-Swift.h"
#import "Source/gui/SNTMessageWindowController.h"

#include <fido.h>

#include <vector>

static const size_t kMaxFido2Devices = 8;

// How long each poll of one device waits before moving on to the next. Short
// enough that a Cancel is noticed promptly and that a touch on any key is seen
// without waiting on the others.
static const int kTouchPollIntervalMS = 200;

// How long to wait for the user to touch their key. The prompt's Cancel button
// does not interrupt libfido2 -- the handle is not safe to touch from another
// thread -- so an abandoned request occupies the serial queue until this
// expires. Keep it short enough that a user who cancels and retries is not left
// waiting on the previous attempt.
static const int kTouchTimeoutMS = 30000;

// State shared between the background authorization and the prompt's buttons.
// The reply block runs at most once; whichever side claims the request first
// wins and the other is discarded.
@interface SNTFido2Request : NSObject
@property(nonatomic) NSWindow* promptWindow;
/// Set when a prompt button has taken the request over, so the device loop can
/// stop early and free the queue for the next request.
@property(atomic) BOOL abandoned;
- (BOOL)claim;
@end

@implementation SNTFido2Request {
  NSLock* _lock;
  BOOL _claimed;
}

- (instancetype)init {
  self = [super init];
  if (self) {
    _lock = [[NSLock alloc] init];
  }
  return self;
}

- (BOOL)claim {
  [_lock lock];
  BOOL won = !_claimed;
  _claimed = YES;
  [_lock unlock];
  return won;
}

@end

@implementation SNTFido2Helper

// libfido2 handles are not safe to use from more than one thread, so every
// device operation runs here, one at a time.
+ (dispatch_queue_t)queue {
  static dispatch_queue_t q;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    q = dispatch_queue_create("com.northpolesec.santa.fido2", DISPATCH_QUEUE_SERIAL);
  });
  return q;
}

#pragma mark - Authorization

+ (void)authorizeWithReason:(NSString*)reason
        offerTouchIDInstead:(BOOL)offerTouchID
                 replyBlock:(void (^)(SNTFido2Result result))replyBlock {
  SNTFido2Request* request = [[SNTFido2Request alloc] init];

  dispatch_async([self queue], ^{
    // Ask every attached key for a touch before showing anything. With no key
    // attached there is nothing to prompt for, and a caller that accepts more
    // than one method needs to hear that without the user seeing a key prompt
    // flash past.
    std::vector<fido_dev_t*> devices = [self openDevicesAndBeginTouch];
    if (devices.empty()) {
      LOGI(@"FIDO2: No devices attached");
      if ([request claim]) {
        replyBlock(SNTFido2ResultNoDevice);
      }
      return;
    }

    // Async, not sync: the dismissal below is also queued on main, so it is
    // ordered after this, and nothing may block the main thread on this queue.
    dispatch_async(dispatch_get_main_queue(), ^{
      request.promptWindow = [self showPromptWindowWithReason:reason
                                                 offerTouchID:offerTouchID
                                                      request:request
                                                   replyBlock:replyBlock];
    });

    SNTFido2Result result = [self waitForTouchOnDevices:devices request:request];
    [self closeDevices:devices];

    if (![request claim]) {
      // A prompt button already took the request over and replied.
      return;
    }
    [self dismissPromptForRequest:request];
    replyBlock(result);
  });
}

+ (void)dismissPromptForRequest:(SNTFido2Request*)request {
  dispatch_async(dispatch_get_main_queue(), ^{
    [request.promptWindow close];
    request.promptWindow = nil;
  });
}

+ (NSWindow*)showPromptWindowWithReason:(NSString*)reason
                           offerTouchID:(BOOL)offerTouchID
                                request:(SNTFido2Request*)request
                             replyBlock:(void (^)(SNTFido2Result))replyBlock {
  // Neither button interrupts the device operation in flight; they abandon it.
  // The result that eventually arrives is discarded by the claim below.
  auto finish = ^(SNTFido2Result result) {
    request.abandoned = YES;
    if (![request claim]) {
      return;
    }
    [self dismissPromptForRequest:request];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
      replyBlock(result);
    });
  };

  NSWindow* window = [SNTMessageWindowController defaultWindow];
  window.releasedWhenClosed = NO;
  window.canHide = NO;
  window.hidesOnDeactivate = NO;
  window.contentViewController =
      [SNTFido2PromptViewFactory makePromptViewControllerWithDetail:reason ?: @""
          offerTouchID:offerTouchID
          onCancel:^{
            finish(SNTFido2ResultDenied);
          }
          onTouchID:^{
            finish(SNTFido2ResultUseTouchID);
          }];

  // Above Santa's notification windows (NSModalPanelWindowLevel).
  [window setContentSize:window.contentViewController.view.fittingSize];
  window.level = NSPopUpMenuWindowLevel;
  [window center];
  [window makeKeyAndOrderFront:nil];
  [NSApp activateIgnoringOtherApps:YES];
  return window;
}

#pragma mark - Device operations

#pragma mark - Device operations

// All run on the serial queue: libfido2 handles are not safe to use from more
// than one thread.

// Opens every attached FIDO2 device and asks each for a touch. Returns the
// devices that accepted the request; the caller owns them and must pass them to
// +closeDevices:.
//
// fido_dev_get_touch_begin/fido_dev_get_touch_status is libfido2's supported
// non-blocking path. The blocking alternative would have to take the devices in
// turn, so touching the second key would do nothing until the first timed out.
+ (std::vector<fido_dev_t*>)openDevicesAndBeginTouch {
  std::vector<fido_dev_t*> devices;

  fido_dev_info_t* devlist = fido_dev_info_new(kMaxFido2Devices);
  if (!devlist) {
    LOGE(@"FIDO2: Failed to allocate device info list");
    return devices;
  }

  size_t found = 0;
  int r = fido_dev_info_manifest(devlist, kMaxFido2Devices, &found);
  if (r != FIDO_OK) {
    LOGE(@"FIDO2: Failed to enumerate devices (error: %d)", r);
    fido_dev_info_free(&devlist, kMaxFido2Devices);
    return devices;
  }

  for (size_t i = 0; i < found; i++) {
    const char* path = fido_dev_info_path(fido_dev_info_ptr(devlist, i));

    fido_dev_t* dev = fido_dev_new();
    if (!dev) {
      break;
    }
    if ((r = fido_dev_open(dev, path)) != FIDO_OK) {
      LOGE(@"FIDO2: Failed to open device at %s (error: %d)", path, r);
      fido_dev_free(&dev);
      continue;
    }
    if ((r = fido_dev_get_touch_begin(dev)) != FIDO_OK) {
      LOGE(@"FIDO2: Device at %s will not report touch (error: %d)", path, r);
      fido_dev_close(dev);
      fido_dev_free(&dev);
      continue;
    }
    devices.push_back(dev);
  }

  fido_dev_info_free(&devlist, kMaxFido2Devices);
  return devices;
}

+ (void)closeDevices:(std::vector<fido_dev_t*>&)devices {
  for (fido_dev_t* dev : devices) {
    // Withdraw any request still outstanding. Safe here, and only here: this
    // runs on the same queue that issued it, with no call in flight.
    fido_dev_cancel(dev);
    fido_dev_close(dev);
    fido_dev_free(&dev);
  }
  devices.clear();
}

// Polls every device in turn until one reports a touch, the deadline passes, or
// a prompt button takes the request over.
+ (SNTFido2Result)waitForTouchOnDevices:(std::vector<fido_dev_t*>&)devices
                                request:(SNTFido2Request*)request {
  LOGI(@"FIDO2: Waiting for a touch on any of %zu attached key(s)...", devices.size());

  uint64_t deadline =
      clock_gettime_nsec_np(CLOCK_MONOTONIC) + (uint64_t)kTouchTimeoutMS * NSEC_PER_MSEC;

  // Devices that error out are dropped as we go; running out means every key
  // failed, which is a denial rather than a timeout.
  while (!devices.empty() && clock_gettime_nsec_np(CLOCK_MONOTONIC) < deadline) {
    if (request.abandoned) {
      return SNTFido2ResultDenied;
    }

    for (auto it = devices.begin(); it != devices.end();) {
      int touched = 0;
      int r = fido_dev_get_touch_status(*it, &touched, kTouchPollIntervalMS);
      if (r != FIDO_OK) {
        LOGE(@"FIDO2: Device stopped responding (error: %d)", r);
        fido_dev_close(*it);
        fido_dev_free(&(*it));
        it = devices.erase(it);
        continue;
      }
      if (touched) {
        LOGI(@"FIDO2: User presence confirmed");
        return SNTFido2ResultApproved;
      }
      ++it;
    }
  }

  LOGE(@"FIDO2: No key was touched");
  return SNTFido2ResultDenied;
}

@end
