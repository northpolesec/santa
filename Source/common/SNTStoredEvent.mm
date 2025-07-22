/// Copyright 2015 Google Inc. All rights reserved.
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

#import "Source/common/SNTStoredEvent.h"

#import "Source/common/CoderMacros.h"

@implementation SNTStoredEvent

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder {
  ENCODE(coder, idx);
  ENCODE(coder, occurrenceDate);
}

- (instancetype)init {
  self = [super init];
  if (self) {
    _idx = @(arc4random());
    _occurrenceDate = [NSDate date];
  }
  return self;
}

- (instancetype)initWithCoder:(NSCoder *)decoder {
  self = [super init];
  if (self) {
    DECODE(decoder, idx, NSNumber);
    DECODE(decoder, occurrenceDate, NSDate);
  }
  return self;
}

- (BOOL)isEqual:(id)other {
  if (other == self) return YES;
  if (![other isKindOfClass:[SNTStoredEvent class]]) return NO;
  SNTStoredEvent *o = other;
  return [self.idx isEqual:o.idx];
}

- (NSUInteger)hash {
  NSUInteger prime = 31;
  NSUInteger result = 1;
  result = prime * result + [self.idx hash];
  return result;
}

- (NSString *)hashForEvent;
{
  [self doesNotRecognizeSelector:_cmd];
  return nil;
}

@end
