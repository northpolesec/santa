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

#import "Source/common/ne/SNTNetworkExtensionSettings.h"

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

@interface SNTNetworkExtensionSettings (Testing)
@property(readwrite) BOOL enable;
@end

// Simulates a future version of SNTNetworkExtensionSettings that encodes an additional
// unknown key. Used in testForwardCompatibility to produce archive data with extra keys.
@interface SNTNetworkExtensionSettingsFuture : SNTNetworkExtensionSettings
@end

@implementation SNTNetworkExtensionSettingsFuture
- (void)encodeWithCoder:(NSCoder *)coder {
  [super encodeWithCoder:coder];
  [coder encodeObject:@"futureValue" forKey:@"futureProperty"];
}
@end

@interface SNTNetworkExtensionSettingsTest : XCTestCase
@end

@implementation SNTNetworkExtensionSettingsTest

- (void)testInitialization {
  SNTNetworkExtensionSettings *settings = [[SNTNetworkExtensionSettings alloc] initWithEnable:YES];
  XCTAssertNotNil(settings);
  XCTAssertTrue(settings.enable);

  settings = [[SNTNetworkExtensionSettings alloc] initWithEnable:NO];
  XCTAssertNotNil(settings);
  XCTAssertFalse(settings.enable);
}

- (void)testRoundtripEncodeDecode {
  SNTNetworkExtensionSettings *settings = [[SNTNetworkExtensionSettings alloc] initWithEnable:YES];
  NSData *data = [NSKeyedArchiver archivedDataWithRootObject:settings
                                       requiringSecureCoding:YES
                                                       error:nil];
  XCTAssertNotNil(data);

  SNTNetworkExtensionSettings *deserialized =
      [NSKeyedUnarchiver unarchivedObjectOfClass:[SNTNetworkExtensionSettings class]
                                        fromData:data
                                           error:nil];
  XCTAssertNotNil(deserialized);
  XCTAssertTrue(deserialized.enable);

  settings = [[SNTNetworkExtensionSettings alloc] initWithEnable:NO];
  data = [NSKeyedArchiver archivedDataWithRootObject:settings requiringSecureCoding:YES error:nil];
  XCTAssertNotNil(data);

  deserialized = [NSKeyedUnarchiver unarchivedObjectOfClass:[SNTNetworkExtensionSettings class]
                                                   fromData:data
                                                      error:nil];
  XCTAssertNotNil(deserialized);
  XCTAssertFalse(deserialized.enable);
}

- (void)testForwardCompatibility {
  // Simulate a new sender encoding an archive with an unknown key.
  // Old receiver should decode successfully, ignoring the unknown key.
  //
  // SNTNetworkExtensionSettingsFuture is a stand-in for a hypothetical future version of
  // SNTNetworkExtensionSettings that adds an extra property. We archive it, then remap the
  // class name back to SNTNetworkExtensionSettings during decode to simulate an old receiver
  // processing data produced by a new sender.
  SNTNetworkExtensionSettingsFuture *future =
      [[SNTNetworkExtensionSettingsFuture alloc] initWithEnable:YES];

  NSData *data = [NSKeyedArchiver archivedDataWithRootObject:future
                                       requiringSecureCoding:YES
                                                       error:nil];
  XCTAssertNotNil(data);

  NSKeyedUnarchiver *unarchiver = [[NSKeyedUnarchiver alloc] initForReadingFromData:data
                                                                              error:nil];
  unarchiver.requiresSecureCoding = YES;
  [unarchiver setClass:[SNTNetworkExtensionSettings class]
          forClassName:NSStringFromClass([SNTNetworkExtensionSettingsFuture class])];

  SNTNetworkExtensionSettings *deserialized =
      [unarchiver decodeObjectOfClass:[SNTNetworkExtensionSettings class]
                               forKey:NSKeyedArchiveRootObjectKey];
  [unarchiver finishDecoding];

  XCTAssertNotNil(deserialized);
  XCTAssertTrue(deserialized.enable);
}

- (void)testBackwardCompatibility {
  // Simulate an old sender that didn't encode the 'enable' key.
  // New receiver should get default value (NO for BOOL).
  SNTNetworkExtensionSettings *empty = [[SNTNetworkExtensionSettings alloc] init];
  NSData *data = [NSKeyedArchiver archivedDataWithRootObject:empty
                                       requiringSecureCoding:YES
                                                       error:nil];

  SNTNetworkExtensionSettings *deserialized =
      [NSKeyedUnarchiver unarchivedObjectOfClass:[SNTNetworkExtensionSettings class]
                                        fromData:data
                                           error:nil];
  XCTAssertNotNil(deserialized);
  // Missing keys should result in default values (NO for BOOL).
  XCTAssertFalse(deserialized.enable);
}

@end
