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

#import <Cocoa/Cocoa.h>

@protocol SNTMessageWindowControllerDelegate
- (void)windowDidCloseSilenceHash:(NSString *)hash withInterval:(NSTimeInterval)interval;
@end

@interface SNTMessageWindowController : NSWindowController <NSWindowDelegate>

- (IBAction)showWindow:(id)sender;
- (IBAction)closeWindow:(id)sender;

/// Generate a distinct key for a given displayed event. This key is used for silencing future
/// notifications.
- (NSString *)messageHash;

///  Linked to checkbox in UI to prevent future notifications for the given event for a given period
@property NSTimeInterval silenceFutureNotificationsPeriod;

@property(weak) id<SNTMessageWindowControllerDelegate> delegate;

@end
