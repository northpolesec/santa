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

#import "Source/gui/SNTBinaryMessageWindowController.h"

#import <LocalAuthentication/LocalAuthentication.h>
#import <MOLCertificate/MOLCertificate.h>
#import <MOLXPCConnection/MOLXPCConnection.h>
#import <SecurityInterface/SFCertificatePanel.h>
#import <dispatch/dispatch.h>

#import "Source/common/CertificateHelpers.h"
#import "Source/common/SNTBlockMessage.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTRule.h"
#import "Source/common/SNTStoredEvent.h"
#import "Source/common/SNTXPCControlInterface.h"

@interface SNTBinaryMessageWindowController ()
///  The custom message to display for this event
@property(copy) NSString *customMessage;

///  The custom URL to use for this event
@property(copy) NSString *customURL;

///  The reply block to call when the user has made a decision in standalone
///  mode.
@property(copy) void (^replyBlock)(BOOL authenticated);

///  A 'friendly' string representing the certificate information
@property(readonly, nonatomic) NSString *publisherInfo;

///  An optional message to display with this block.
@property(readonly, nonatomic) NSAttributedString *attributedCustomMessage;

///  Reference to the "Application Name" label in the XIB. Used to remove if application
///  doesn't have a CFBundleName.
@property(weak) IBOutlet NSTextField *applicationNameLabel;

@end

@implementation SNTBinaryMessageWindowController

- (instancetype)initWithEvent:(SNTStoredEvent *)event
                    customMsg:(NSString *)message
                    customURL:(NSString *)url 
                    reply:(void (^)(BOOL authenticated))replyBlock {
  self = [super initWithWindowNibName:@"MessageWindow"];
  if (self) {
    _event = event;
    _customMessage = message;
    _customURL = url;
    _replyBlock = replyBlock;
    _progress = [NSProgress discreteProgressWithTotalUnitCount:1];
    [_progress addObserver:self
                forKeyPath:@"fractionCompleted"
                   options:NSKeyValueObservingOptionNew
                   context:NULL];
  }
  return self;
}

- (void)dealloc {
  [_progress removeObserver:self forKeyPath:@"fractionCompleted"];
}

- (void)observeValueForKeyPath:(NSString *)keyPath
                      ofObject:(id)object
                        change:(NSDictionary *)change
                       context:(void *)context {
  if ([keyPath isEqualToString:@"fractionCompleted"]) {
    dispatch_async(dispatch_get_main_queue(), ^{
      NSProgress *progress = object;
      if (progress.fractionCompleted != 0.0) {
        self.hashingIndicator.indeterminate = NO;
      }
      self.hashingIndicator.doubleValue = progress.fractionCompleted;
    });
  }
}

- (void)loadWindow {
  [super loadWindow];
  NSURL *url = [SNTBlockMessage eventDetailURLForEvent:self.event customURL:self.customURL];
  BOOL isStandalone = [[SNTConfigurator configurator] enableStandaloneMode];

  if (!url && !isStandalone) {
    LOGE(@"PLM -- No URL to open for event %@", self.event.idx);
    [self.openEventButton removeFromSuperview];
  } else if (isStandalone) {

    [self.openEventButton setTitle:@"Approve"];
    // Require the button keyEquivalent set to be CMD + Return
    [self.openEventButton setKeyEquivalent:@"\r"];                                   // Return Key
    [self.openEventButton setKeyEquivalentModifierMask:NSEventModifierFlagCommand];  // Command Key
  } else if (self.customURL.length == 0) {
    // Set the button text only if a per-rule custom URL is not used. If a
    // custom URL is used, it is assumed that the `EventDetailText` config value
    // does not apply and the default text will be used.
    NSString *eventDetailText = [[SNTConfigurator configurator] eventDetailText];
    if (eventDetailText) {
      [self.openEventButton setTitle:eventDetailText];
      // Require the button keyEquivalent set to be CMD + Return
      [self.openEventButton setKeyEquivalent:@"\r"];  // Return Key
      [self.openEventButton
        setKeyEquivalentModifierMask:NSEventModifierFlagCommand];  // Command Key
    }
  }

  NSString *dismissButtonText = [[SNTConfigurator configurator] dismissText];
  if (dismissButtonText.length) {
    [self.dismissEventButton setTitle:dismissButtonText];
  }

  if (!self.event.needsBundleHash) {
    [self.bundleHashLabel removeFromSuperview];
    [self.hashingIndicator removeFromSuperview];
    [self.foundFileCountLabel removeFromSuperview];
  } else {
    self.openEventButton.enabled = NO;
    self.hashingIndicator.indeterminate = YES;
    [self.hashingIndicator startAnimation:self];
    self.bundleHashLabel.hidden = YES;
    self.foundFileCountLabel.stringValue = @"";
  }

  if (!self.event.fileBundleName) {
    [self.applicationNameLabel removeFromSuperview];
  }

  if ([[SNTConfigurator configurator] enableStandaloneMode]) {
    self.replyBlock(NO);
  }
}

- (NSString *)messageHash {
  return self.event.fileSHA256;
}

- (IBAction)showCertInfo:(id)sender {
  // SFCertificatePanel expects an NSArray of SecCertificateRef's
  [[[SFCertificatePanel alloc] init] beginSheetForWindow:self.window
                                           modalDelegate:nil
                                          didEndSelector:nil
                                             contextInfo:nil
                                            certificates:CertificateChain(self.event.signingChain)
                                               showGroup:YES];
}

// Check if the user is able to authenticate using Touch ID. Returns YES if the
// user is able to NO Otherwise
- (BOOL) isAbleToAuthenticateInStandaloneMode:(NSError **)err {
  LAContext *context = [[LAContext alloc] init];

  if (![context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:err]) {
    return NO;
  }

  return YES;
}

// When running in standalone mode, the user is prompted to approve the binary.
- (void)approveBinaryForStandaloneMode {
  LAContext *context = [[LAContext alloc] init];

  dispatch_semaphore_t sema = dispatch_semaphore_create(0);

  // Check if we can do Touch ID. If not disable the button and display an
  // error to the user.
  NSError *err;

  LOGE(@"PLM -- Attempting to authenticate user for standalone mode");

  // If we're unable to authenticate the user using touch ID, remove the approval button.
  if (![self isAbleToAuthenticateInStandaloneMode:&err]) {
      LOGE(@"PLM -- Unable to authenticate user for standalone mode: %@", err);
      [self.openEventButton removeFromSuperview];
  }

  [context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
          localizedReason:[NSString stringWithFormat:@"Approve %@", self.event.signingID]
                    reply:^(BOOL success, NSError *error) {
                      if (self.replyBlock == nil) {
                        dispatch_semaphore_signal(sema); 
                        return;
                      }

                      if (success) {
                          self.replyBlock(YES);
                      } else {
                          self.replyBlock(NO);
                      }
                      dispatch_semaphore_signal(sema); 
                    }];

  //TODO do we need to use a semaphore here?
  dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
}

- (IBAction)openEventDetails:(id)sender {
  if ([[SNTConfigurator configurator] enableStandaloneMode]) {
    [self closeWindow:sender];
    [self approveBinaryForStandaloneMode];
    return;
  }

  NSURL *url = [SNTBlockMessage eventDetailURLForEvent:self.event customURL:self.customURL];

  [self closeWindow:sender];
  [[NSWorkspace sharedWorkspace] openURL:url];
}

#pragma mark Generated properties

+ (NSSet *)keyPathsForValuesAffectingValueForKey:(NSString *)key {
  if (![key isEqualToString:@"event"]) {
    return [NSSet setWithObject:@"event"];
  } else {
    return [NSSet set];
  }
}

- (NSString *)publisherInfo {
  return Publisher(self.event.signingChain, self.event.teamID);
}

- (NSAttributedString *)attributedCustomMessage {
  return [SNTBlockMessage attributedBlockMessageForEvent:self.event
                                           customMessage:self.customMessage];
}

- (void)updateBlockNotification:(SNTStoredEvent *)event withBundleHash:(NSString *)bundleHash {
  // UI updates must happen on the main thread.
  dispatch_async(dispatch_get_main_queue(), ^{
    if ([self.event.idx isEqual:event.idx]) {
      if (bundleHash) {
        [self.bundleHashLabel setHidden:NO];
      } else {
        [self.bundleHashLabel removeFromSuperview];
        [self.bundleHashTitle removeFromSuperview];
      }
      self.event.fileBundleHash = bundleHash;
      [self.foundFileCountLabel removeFromSuperview];
      [self.hashingIndicator setHidden:YES];
      [self.openEventButton setEnabled:YES];
    }
  });
}

@end
