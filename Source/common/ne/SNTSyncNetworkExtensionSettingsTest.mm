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

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

@interface SNTSyncNetworkExtensionSettings (Testing)
@property(readwrite) BOOL enable;
@end

@interface SNTSyncNetworkExtensionSettingsTest : XCTestCase
@end

@implementation SNTSyncNetworkExtensionSettingsTest

- (void)testInitialization {
  // Test initialization with enable=YES
  SNTSyncNetworkExtensionSettings *settings =
      [[SNTSyncNetworkExtensionSettings alloc] initWithEnable:YES];
  XCTAssertNotNil(settings);
  XCTAssertTrue(settings.enable);

  // Test initialization with enable=NO
  settings = [[SNTSyncNetworkExtensionSettings alloc] initWithEnable:NO];
  XCTAssertNotNil(settings);
  XCTAssertFalse(settings.enable);
}

- (void)testEncodeDecodeSecureCoding {
  // Test with enable=YES
  SNTSyncNetworkExtensionSettings *settings =
      [[SNTSyncNetworkExtensionSettings alloc] initWithEnable:YES];
  NSData *serialized = [settings serialize];
  XCTAssertNotNil(serialized);

  SNTSyncNetworkExtensionSettings *deserialized =
      [SNTSyncNetworkExtensionSettings deserialize:serialized];
  XCTAssertNotNil(deserialized);
  XCTAssertTrue(deserialized.enable);
  XCTAssertEqual(deserialized.enable, settings.enable);

  // Test with enable=NO
  settings = [[SNTSyncNetworkExtensionSettings alloc] initWithEnable:NO];
  serialized = [settings serialize];
  XCTAssertNotNil(serialized);

  deserialized = [SNTSyncNetworkExtensionSettings deserialize:serialized];
  XCTAssertNotNil(deserialized);
  XCTAssertFalse(deserialized.enable);
  XCTAssertEqual(deserialized.enable, settings.enable);
}

- (void)testDeserializeNilData {
  // Test that deserializing nil data returns nil
  SNTSyncNetworkExtensionSettings *deserialized = [SNTSyncNetworkExtensionSettings deserialize:nil];
  XCTAssertNil(deserialized);
}

@end
