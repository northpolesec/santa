/// Copyright 2026 North Pole Security, Inc.
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

#import "Source/common/SNTStoredSignalReport.h"

#import "Source/common/CoderMacros.h"

@implementation SNTStoredSignalReport

- (instancetype)initWithReportData:(NSData*)reportData {
  if (!reportData) {
    return nil;
  }
  self = [super init];
  if (self) {
    _idx = @(arc4random());
    _reportData = [reportData copy];
  }
  return self;
}

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder*)coder {
  ENCODE(coder, idx);
  ENCODE(coder, name);
  ENCODE(coder, reportData);
}

- (instancetype)initWithCoder:(NSCoder*)decoder {
  self = [super init];
  if (self) {
    DECODE(decoder, idx, NSNumber);
    DECODE(decoder, name, NSString);
    DECODE(decoder, reportData, NSData);
    // Maintain the same invariant as the designated initializer: reject corrupt/incomplete
    // archives.
    if (!_idx || !_reportData) {
      return nil;
    }
  }
  return self;
}

@end
