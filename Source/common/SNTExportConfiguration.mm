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

@implementation SNTExportConfigurationAWS

- (instancetype)initWithToken:(NSData *)token {
  self = [super self];
  if (self) {
    _token = token;
  }
  return self;
}

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder {
  ENCODE(coder, token);
}

- (instancetype)initWithCoder:(NSCoder *)decoder {
  self = [super init];
  if (self) {
    DECODE(decoder, token, NSData);
  }
  return self;
}

@end

@implementation SNTExportConfigurationGCP

- (instancetype)initWithToken:(NSData *)token {
  self = [super self];
  if (self) {
    _token = token;
  }
  return self;
}

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder {
  ENCODE(coder, token);
}

- (instancetype)initWithCoder:(NSCoder *)decoder {
  self = [super init];
  if (self) {
    DECODE(decoder, token, NSData);
  }
  return self;
}

@end

@implementation SNTExportConfiguration

- (instancetype)initWithAWSToken:(NSData *)token {
  self = [super init];
  if (self) {
    _config = [[SNTExportConfigurationAWS alloc] initWithToken:token];
    _configType = SNTExportConfigurationTypeAWS;
  }
  return self;
}

- (instancetype)initWithGCPToken:(NSData *)token {
  self = [super init];
  if (self) {
    _config = [[SNTExportConfigurationGCP alloc] initWithToken:token];
    _configType = SNTExportConfigurationTypeGCP;
  }
  return self;
}

- (NSString *)description {
  return
      [NSString stringWithFormat:@"SNTExportConfiguration: Type: %@",
                                 self.configType == SNTExportConfigurationTypeAWS   ? @"AWS"
                                 : self.configType == SNTExportConfigurationTypeGCP ? @"GCP"
                                                                                    : @"UNKNOWN"];
}

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder {
  ENCODE(coder, config);
  ENCODE_BOXABLE(coder, configType);
}

- (instancetype)initWithCoder:(NSCoder *)decoder {
  self = [super init];
  if (self) {
    DECODE_SET(decoder, config,
               ([NSSet setWithObjects:[SNTExportConfigurationAWS class],
                                      [SNTExportConfigurationGCP class], nil]));
    DECODE_SELECTOR(decoder, configType, NSNumber, integerValue);
  }
  return self;
}

- (NSData *)serialize {
  NSError *error;
  NSData *data = [NSKeyedArchiver archivedDataWithRootObject:self
                                       requiringSecureCoding:YES
                                                       error:&error];
  if (error) {
    LOGE(@"Export config serialization failed: %@", error.localizedDescription);
    return nil;
  }

  return data;
}

+ (instancetype)deserialize:(NSData *)data {
  if (!data) {
    return nil;
  }

  NSSet *allowedClasses =
      [NSSet setWithObjects:[SNTExportConfiguration class], [SNTExportConfigurationAWS class],
                            [SNTExportConfigurationGCP class], nil];

  NSError *error;
  id object = [NSKeyedUnarchiver unarchivedObjectOfClasses:allowedClasses
                                                  fromData:data
                                                     error:&error];
  if (error) {
    LOGE(@"Export config deserialization failed: %@", error.localizedDescription);
    return nil;
  }

  if (![object isKindOfClass:[SNTExportConfiguration class]]) {
    LOGE(@"Unexpected export config type: %@", [object class]);
    return nil;
  }

  return object;
}

@end
