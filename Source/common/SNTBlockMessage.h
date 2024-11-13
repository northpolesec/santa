/// Copyright 2016 Google Inc. All rights reserved.
/// Copyright 2024 North Pole Security, Inc.
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

#ifdef SANTAGUI
#import <Cocoa/Cocoa.h>
#else
#import <Foundation/Foundation.h>
#endif

@class SNTFileAccessEvent;
@class SNTDeviceEvent;
@class SNTStoredEvent;

@interface SNTBlockMessage : NSObject

NS_ASSUME_NONNULL_BEGIN

///
///  Return a message suitable for presenting to the user.
///
///  In SantaGUI this will return an NSAttributedString with links and formatting included
///  while for santad all HTML will be properly stripped.
///
+ (NSAttributedString *)formatMessage:(NSString *)message withFallback:(NSString *)fallback;

///
///  Uses either the configured message depending on the event type or a custom message
///  if the rule that blocked this file included one, formatted using
///  +[SNTBlockMessage formatMessage].
///
+ (NSAttributedString *)attributedBlockMessageForEvent:(nullable SNTStoredEvent *)event
                                         customMessage:(nullable NSString *)customMessage;

+ (NSAttributedString *)attributedBlockMessageForFileAccessEvent:
                          (nullable SNTFileAccessEvent *)event
                                                   customMessage:(nullable NSString *)customMessage;

+ (NSAttributedString *)attributedBlockMessageForDeviceEvent:(nullable SNTDeviceEvent *)event;

///
///  Return a URL generated from the EventDetailURL configuration key
///  after replacing templates in the URL with values from the event.
///
+ (nullable NSURL *)eventDetailURLForEvent:(nullable SNTStoredEvent *)event
                                 customURL:(nullable NSString *)url;
+ (nullable NSURL *)eventDetailURLForFileAccessEvent:(nullable SNTFileAccessEvent *)event
                                           customURL:(nullable NSString *)url;

///
///  Strip HTML from a string, replacing <br /> with newline.
///
+ (NSString *)stringFromHTML:(NSString *)html;

NS_ASSUME_NONNULL_END

@end
