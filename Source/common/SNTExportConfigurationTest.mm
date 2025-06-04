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
  SNTExportConfiguration *cfg = [[SNTExportConfiguration alloc]
      initWithAWSToken:[@"foo" dataUsingEncoding:NSUTF8StringEncoding]];
  XCTAssertEqual(cfg.configType, SNTExportConfigurationTypeAWS);
  XCTAssertTrue([cfg.config isKindOfClass:[SNTExportConfigurationAWS class]]);

  cfg = [[SNTExportConfiguration alloc]
      initWithGCPToken:[@"foo" dataUsingEncoding:NSUTF8StringEncoding]];
  XCTAssertTrue([cfg.config isKindOfClass:[SNTExportConfigurationGCP class]]);
}

- (void)testEncodeDecodeSerializeDeserialize {
  // Encode and decode AWS config
  SNTExportConfiguration *cfg = [[SNTExportConfiguration alloc]
      initWithAWSToken:[@"foo" dataUsingEncoding:NSUTF8StringEncoding]];

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
  NSString *tokenValue = [[NSString alloc]
      initWithData:((SNTExportConfigurationAWS *)((SNTExportConfiguration *)obj).config).token
          encoding:NSUTF8StringEncoding];
  XCTAssertEqualObjects(tokenValue, @"foo");

  // Ensure deserializing the serialized data results in an object with the
  // same content as what is returned by NSKeyedUnarchiver
  SNTExportConfiguration *deserializedObj = [SNTExportConfiguration deserialize:serializedData];
  XCTAssertTrue([deserializedObj.config isKindOfClass:[SNTExportConfigurationAWS class]]);
  tokenValue =
      [[NSString alloc] initWithData:((SNTExportConfigurationAWS *)(deserializedObj.config)).token
                            encoding:NSUTF8StringEncoding];
  XCTAssertEqualObjects(tokenValue, @"foo");

  // Encode and decode GCP config
  cfg = [[SNTExportConfiguration alloc]
      initWithGCPToken:[@"bar" dataUsingEncoding:NSUTF8StringEncoding]];

  data = [NSKeyedArchiver archivedDataWithRootObject:cfg requiringSecureCoding:YES error:nil];
  // Ensure the serialize method returns the same bytes as NSKeyedArchiver
  serializedData = [cfg serialize];
  XCTAssertEqualObjects(data, serializedData);

  obj = [NSKeyedUnarchiver unarchivedObjectOfClasses:allowedClasses fromData:data error:nil];
  XCTAssertTrue([obj isKindOfClass:[SNTExportConfiguration class]]);
  XCTAssertTrue(
      [((SNTExportConfiguration *)obj).config isKindOfClass:[SNTExportConfigurationGCP class]]);

  tokenValue = [[NSString alloc]
      initWithData:((SNTExportConfigurationGCP *)((SNTExportConfiguration *)obj).config).token
          encoding:NSUTF8StringEncoding];
  XCTAssertEqualObjects(tokenValue, @"bar");

  // Ensure deserializing the serialized data results in an object with the
  // same content as what is returned by NSKeyedUnarchiver
  deserializedObj = [SNTExportConfiguration deserialize:serializedData];
  XCTAssertTrue([deserializedObj.config isKindOfClass:[SNTExportConfigurationGCP class]]);
  tokenValue =
      [[NSString alloc] initWithData:((SNTExportConfigurationGCP *)(deserializedObj.config)).token
                            encoding:NSUTF8StringEncoding];
  XCTAssertEqualObjects(tokenValue, @"bar");
}

@end
