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

#import <Foundation/Foundation.h>

typedef NS_ENUM(NSInteger, SNTExportConfigurationType) {
  SNTExportConfigurationTypeUnknown = 0,
  SNTExportConfigurationTypeAWS,
  SNTExportConfigurationTypeGCP,
};

/// Protocol required for valid configuration types
@protocol SNTExportConfigurationProtocol <NSObject, NSSecureCoding>
@end

/// Configuration required for exporting to AWS
@interface SNTExportConfigurationAWS : NSObject <SNTExportConfigurationProtocol>
@property(readonly) NSData *token;
- (instancetype)initWithToken:(NSData *)token;
@end

/// Configuration required for exporting to GCP
@interface SNTExportConfigurationGCP : NSObject <SNTExportConfigurationProtocol>
@property(readonly) NSData *token;
- (instancetype)initWithToken:(NSData *)token;
@end

/// Lightweight container for holding the export configuration and its type
@interface SNTExportConfiguration : NSObject <NSSecureCoding>

@property(readonly) SNTExportConfigurationType configType;
@property(readonly) id<SNTExportConfigurationProtocol> config;

- (instancetype)initWithAWSToken:(NSData *)token;
- (instancetype)initWithGCPToken:(NSData *)token;

- (NSData *)serialize;
+ (instancetype)deserialize:(NSData *)data;

@end
