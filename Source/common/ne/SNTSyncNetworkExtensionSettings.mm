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

#import "Source/common/ne/SNTSyncNetworkExtensionSettings.h"

#import "Source/common/CoderMacros.h"
#import "Source/common/SNTLogging.h"

@interface SNTSyncNetworkExtensionSettings ()
@property(readwrite) BOOL enable;
@property(readwrite) SNTNetworkFlowDefaultAction flowDefaultAction;
@property(readwrite) NSTimeInterval dnsUpstreamTimeoutSecs;
@end

@implementation SNTSyncNetworkExtensionSettings

- (instancetype)initWithEnable:(BOOL)enable
             flowDefaultAction:(SNTNetworkFlowDefaultAction)flowDefaultAction {
  return [self initWithEnable:enable flowDefaultAction:flowDefaultAction dnsUpstreamTimeoutSecs:0];
}

- (instancetype)initWithEnable:(BOOL)enable
             flowDefaultAction:(SNTNetworkFlowDefaultAction)flowDefaultAction
        dnsUpstreamTimeoutSecs:(NSTimeInterval)dnsUpstreamTimeoutSecs {
  self = [super init];
  if (self) {
    _enable = enable;
    _flowDefaultAction = flowDefaultAction;
    _dnsUpstreamTimeoutSecs = dnsUpstreamTimeoutSecs;
  }
  return self;
}

- (BOOL)isEqual:(id)other {
  if (other == nil) {
    return NO;
  }

  if (self == other) {
    return YES;
  }

  if (![other isKindOfClass:[SNTSyncNetworkExtensionSettings class]]) {
    return NO;
  }

  SNTSyncNetworkExtensionSettings* otherSettings = (SNTSyncNetworkExtensionSettings*)other;
  return self.enable == otherSettings.enable &&
         self.flowDefaultAction == otherSettings.flowDefaultAction &&
         self.dnsUpstreamTimeoutSecs == otherSettings.dnsUpstreamTimeoutSecs;
}

- (NSUInteger)hash {
  NSUInteger prime = 31;
  NSUInteger result = 1;
  result = prime * result + self.enable;
  result = prime * result + self.flowDefaultAction;
  result = prime * result + (NSUInteger)self.dnsUpstreamTimeoutSecs;
  return result;
}

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder*)coder {
  ENCODE_BOXABLE(coder, enable);
  ENCODE_BOXABLE(coder, flowDefaultAction);
  ENCODE_BOXABLE(coder, dnsUpstreamTimeoutSecs);
}

- (instancetype)initWithCoder:(NSCoder*)decoder {
  self = [self init];
  if (self) {
    DECODE_SELECTOR(decoder, enable, NSNumber, boolValue);
    DECODE_SELECTOR(decoder, flowDefaultAction, NSNumber, integerValue);
    DECODE_SELECTOR(decoder, dnsUpstreamTimeoutSecs, NSNumber, doubleValue);
  }
  return self;
}

- (NSData*)serialize {
  NSError* error;
  NSData* data = [NSKeyedArchiver archivedDataWithRootObject:self
                                       requiringSecureCoding:YES
                                                       error:&error];
  if (error) {
    LOGE(@"SNTSyncNetworkExtensionSettings serialization failed: %@", error.localizedDescription);
    return nil;
  }

  return data;
}

+ (instancetype)deserialize:(NSData*)data {
  if (!data) {
    return nil;
  }

  NSError* error;
  id object = [NSKeyedUnarchiver unarchivedObjectOfClass:[SNTSyncNetworkExtensionSettings class]
                                                fromData:data
                                                   error:&error];
  if (error) {
    LOGE(@"SNTSyncNetworkExtensionSettings deserialization failed: %@", error.localizedDescription);
    return nil;
  }

  return object;
}

@end
