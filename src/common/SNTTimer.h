/// Copyright 2025 North Pole Security, Inc.
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

typedef bool (^SNTOnTimerCallback)(void);

typedef NS_ENUM(NSInteger, SNTTimerRescheduleMode) {
  SNTTimerRescheduleModeLeadingEdge,
  SNTTimerRescheduleModeTrailingEdge,
};

// SNTTimer provides an Objective-C wrapper around santa::Timer for
// easier use within Objective-C classes.
@interface SNTTimer : NSObject

- (instancetype)initWithMinInterval:(uint32_t)minInterval
                        maxInterval:(uint32_t)maxInterval
                               name:(NSString *)name
                        fireOnStart:(BOOL)fireOnStart
                     rescheduleMode:(SNTTimerRescheduleMode)rescheduleMode
                           qosClass:(qos_class_t)qosClass
                           callback:(SNTOnTimerCallback)callback;

- (BOOL)startWithInterval:(uint32_t)seconds;
- (void)stop;
- (BOOL)isStarted;

@end
