/// Copyright 2025 North Pole Security, Inc.
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

#import "Source/common/SNTExportConfiguration.h"

#import "Source/common/CoderMacros.h"
#import "Source/common/SNTLogging.h"

@interface SNTExportConfiguration ()
@property NSURL *url;
@property NSDictionary *formValues;
@end

@implementation SNTExportConfiguration

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder {
  ENCODE(coder, url);
  ENCODE(coder, formValues);
}

- (instancetype)initWithCoder:(NSCoder *)decoder {
  self = [super init];
  if (self) {
    DECODE(decoder, url, NSURL);
    DECODE_DICT(decoder, formValues);
  }
  return self;
}

- (instancetype)initWithURL:(NSURL *)url formValues:(NSDictionary *)formValues {
  self = [super init];
  if (self) {
    _url = url;
    _formValues = [formValues copy];
  }
  return self;
}

- (NSString *)description {
  return self.url.absoluteString;
}

@end
