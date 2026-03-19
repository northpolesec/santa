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

- (void)testInitialization {
  NSURL *url = [NSURL URLWithString:@"https://example.com/upload"];
  NSDictionary *formValues = @{@"key1" : @"value1", @"key2" : @"value2"};

  SNTExportConfiguration *cfg = [[SNTExportConfiguration alloc] initWithURL:url
                                                                 formValues:formValues];

  XCTAssertEqualObjects(cfg.url, url);
  XCTAssertEqualObjects(cfg.formValues[@"key1"], @"value1");
  XCTAssertEqualObjects(cfg.formValues[@"key2"], @"value2");
}

- (void)testEncodeDecodeSecureCoding {
  NSURL *url = [NSURL URLWithString:@"https://example.com/upload"];
  NSDictionary *formValues = @{@"key1" : @"value1", @"key2" : @"value2"};

  SNTExportConfiguration *cfg = [[SNTExportConfiguration alloc] initWithURL:url
                                                                 formValues:formValues];
  NSData *data = [NSKeyedArchiver archivedDataWithRootObject:cfg
                                       requiringSecureCoding:YES
                                                       error:nil];
  XCTAssertNotNil(data);

  NSSet *allowedClasses = [NSSet setWithObjects:[SNTExportConfiguration class], nil];
  id obj = [NSKeyedUnarchiver unarchivedObjectOfClasses:allowedClasses fromData:data error:nil];
  XCTAssertTrue([obj isKindOfClass:[SNTExportConfiguration class]]);

  SNTExportConfiguration *decodedConfig = (SNTExportConfiguration *)obj;
  XCTAssertEqualObjects(decodedConfig.url, url);
  XCTAssertEqualObjects(decodedConfig.formValues[@"key1"], @"value1");
  XCTAssertEqualObjects(decodedConfig.formValues[@"key2"], @"value2");
}

@end
