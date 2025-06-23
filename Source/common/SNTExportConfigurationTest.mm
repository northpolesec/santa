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

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

@interface SNTExportConfigurationTest : XCTestCase
@end

@implementation SNTExportConfigurationTest

- (void)testTypes {
  SNTExportConfiguration *cfg =
      [[SNTExportConfiguration alloc] initWithAWSAccessKey:@"MyAccessKey"
                                           secretAccessKey:@"MySecretAccessKey"
                                              sessionToken:@"MySessionToken"
                                                bucketName:@"MyBucketName"
                                           objectKeyPrefix:@"MyObjectKeyPrefix"];
  XCTAssertEqual(cfg.configType, SNTExportConfigurationTypeAWS);
  XCTAssertTrue([cfg.config isKindOfClass:[SNTExportConfigurationAWS class]]);

  cfg = [[SNTExportConfiguration alloc] initWithGCPBearerToken:@"MyBearerToken"
                                                    bucketName:@"MyBucketName"
                                               objectKeyPrefix:@"MyObjectKeyPrefix"];
  XCTAssertEqual(cfg.configType, SNTExportConfigurationTypeGCP);
  XCTAssertTrue([cfg.config isKindOfClass:[SNTExportConfigurationGCP class]]);
}

- (void)testEncodeDecodeSerializeDeserialize {
  // Encode and decode AWS config
  SNTExportConfiguration *cfg =
      [[SNTExportConfiguration alloc] initWithAWSAccessKey:@"MyAccessKey"
                                           secretAccessKey:@"MySecretAccessKey"
                                              sessionToken:@"MySessionToken"
                                                bucketName:@"MyBucketName"
                                           objectKeyPrefix:@"MyObjectKeyPrefix"];

  NSData *data = [NSKeyedArchiver archivedDataWithRootObject:cfg
                                       requiringSecureCoding:YES
                                                       error:nil];

  // Ensure the serialize method returns the same bytes as NSKeyedArchiver
  NSData *serializedData = [cfg serialize];
  XCTAssertEqualObjects(data, serializedData);

  NSSet *allowedClasses =
      [NSSet setWithObjects:[SNTExportConfiguration class], [SNTExportConfigurationAWS class],
                            [SNTExportConfigurationGCP class], nil];

  id obj = [NSKeyedUnarchiver unarchivedObjectOfClasses:allowedClasses fromData:data error:nil];
  XCTAssertTrue([obj isKindOfClass:[SNTExportConfiguration class]]);
  XCTAssertTrue(
      [((SNTExportConfiguration *)obj).config isKindOfClass:[SNTExportConfigurationAWS class]]);
  SNTExportConfigurationAWS *awsConfig =
      (SNTExportConfigurationAWS *)((SNTExportConfiguration *)obj).config;
  XCTAssertEqualObjects(awsConfig.accessKey, @"MyAccessKey");
  XCTAssertEqualObjects(awsConfig.secretAccessKey, @"MySecretAccessKey");
  XCTAssertEqualObjects(awsConfig.sessionToken, @"MySessionToken");
  XCTAssertEqualObjects(awsConfig.bucketName, @"MyBucketName");
  XCTAssertEqualObjects(awsConfig.objectKeyPrefix, @"MyObjectKeyPrefix");

  // Ensure deserializing the serialized data results in an object with the
  // same content as what is returned by NSKeyedUnarchiver
  SNTExportConfiguration *deserializedObj = [SNTExportConfiguration deserialize:serializedData];
  XCTAssertTrue([deserializedObj.config isKindOfClass:[SNTExportConfigurationAWS class]]);
  awsConfig = (SNTExportConfigurationAWS *)(deserializedObj.config);
  XCTAssertEqualObjects(awsConfig.accessKey, @"MyAccessKey");
  XCTAssertEqualObjects(awsConfig.secretAccessKey, @"MySecretAccessKey");
  XCTAssertEqualObjects(awsConfig.sessionToken, @"MySessionToken");
  XCTAssertEqualObjects(awsConfig.bucketName, @"MyBucketName");
  XCTAssertEqualObjects(awsConfig.objectKeyPrefix, @"MyObjectKeyPrefix");

  // Encode and decode GCP config
  cfg = [[SNTExportConfiguration alloc] initWithGCPBearerToken:@"MyBearerToken"
                                                    bucketName:@"MyBucketName"
                                               objectKeyPrefix:@"MyObjectKeyPrefix"];

  data = [NSKeyedArchiver archivedDataWithRootObject:cfg requiringSecureCoding:YES error:nil];
  // Ensure the serialize method returns the same bytes as NSKeyedArchiver
  serializedData = [cfg serialize];
  XCTAssertEqualObjects(data, serializedData);

  obj = [NSKeyedUnarchiver unarchivedObjectOfClasses:allowedClasses fromData:data error:nil];
  XCTAssertTrue([obj isKindOfClass:[SNTExportConfiguration class]]);
  XCTAssertTrue(
      [((SNTExportConfiguration *)obj).config isKindOfClass:[SNTExportConfigurationGCP class]]);

  SNTExportConfigurationGCP *gcpConfig =
      (SNTExportConfigurationGCP *)((SNTExportConfiguration *)obj).config;
  XCTAssertEqualObjects(gcpConfig.bearerToken, @"MyBearerToken");
  XCTAssertEqualObjects(gcpConfig.bucketName, @"MyBucketName");
  XCTAssertEqualObjects(gcpConfig.objectKeyPrefix, @"MyObjectKeyPrefix");

  // Ensure deserializing the serialized data results in an object with the
  // same content as what is returned by NSKeyedUnarchiver
  deserializedObj = [SNTExportConfiguration deserialize:serializedData];
  XCTAssertTrue([deserializedObj.config isKindOfClass:[SNTExportConfigurationGCP class]]);
  gcpConfig = (SNTExportConfigurationGCP *)(deserializedObj.config);
  XCTAssertEqualObjects(gcpConfig.bearerToken, @"MyBearerToken");
  XCTAssertEqualObjects(gcpConfig.bucketName, @"MyBucketName");
  XCTAssertEqualObjects(gcpConfig.objectKeyPrefix, @"MyObjectKeyPrefix");
}

@end
