/// Copyright 2025 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     https://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#import "Source/common/SNTSyncStateAccessor.h"

@interface SNTSyncStateAccessorTest : XCTestCase
@end

@implementation SNTSyncStateAccessorTest

- (void)testInitialization {
  NSDictionary *syncState = @{@"key1" : @"value1"};
  NSDictionary *overrides = @{@"key2" : @"value2"};

  SNTSyncStateAccessor *accessor =
      [[SNTSyncStateAccessor alloc] initWithSyncState:syncState overrides:overrides];

  XCTAssertNotNil(accessor);
  XCTAssertEqualObjects(accessor.underlyingSyncState, syncState);
  XCTAssertEqualObjects(accessor.underlyingOverrides, overrides);
}

- (void)testInitializationWithNilValues {
  SNTSyncStateAccessor *accessor =
      [[SNTSyncStateAccessor alloc] initWithSyncState:nil overrides:nil];

  XCTAssertNotNil(accessor);
  XCTAssertEqualObjects(accessor.underlyingSyncState, @{});
  XCTAssertEqualObjects(accessor.underlyingOverrides, @{});
}

- (void)testOverridePrecedence {
  NSDictionary *syncState = @{@"key1" : @"syncValue"};
  NSDictionary *overrides = @{@"key1" : @"overrideValue"};

  SNTSyncStateAccessor *accessor =
      [[SNTSyncStateAccessor alloc] initWithSyncState:syncState overrides:overrides];

  // Override should take precedence
  XCTAssertEqualObjects(accessor[@"key1"], @"overrideValue");
}

- (void)testFallbackToSyncState {
  NSDictionary *syncState = @{@"key1" : @"syncValue"};
  NSDictionary *overrides = @{@"key2" : @"overrideValue"};

  SNTSyncStateAccessor *accessor =
      [[SNTSyncStateAccessor alloc] initWithSyncState:syncState overrides:overrides];

  // Should fall back to sync state
  XCTAssertEqualObjects(accessor[@"key1"], @"syncValue");
}

- (void)testNilForNonexistentKey {
  SNTSyncStateAccessor *accessor = [[SNTSyncStateAccessor alloc] initWithSyncState:@{}
                                                                          overrides:@{}];

  XCTAssertNil(accessor[@"nonexistent"]);
}

- (void)testObjectForKeyEqualsSubscript {
  NSDictionary *syncState = @{@"key1" : @"value1"};
  SNTSyncStateAccessor *accessor =
      [[SNTSyncStateAccessor alloc] initWithSyncState:syncState overrides:nil];

  XCTAssertEqualObjects([accessor objectForKey:@"key1"], accessor[@"key1"]);
}

- (void)testCount {
  NSDictionary *syncState = @{@"key1" : @"value1", @"key2" : @"value2"};
  NSDictionary *overrides = @{@"key3" : @"value3"};

  SNTSyncStateAccessor *accessor =
      [[SNTSyncStateAccessor alloc] initWithSyncState:syncState overrides:overrides];

  XCTAssertEqual(accessor.count, 3);
}

- (void)testCountWithOverlappingKeys {
  NSDictionary *syncState = @{@"key1" : @"syncValue", @"key2" : @"value2"};
  NSDictionary *overrides = @{@"key1" : @"overrideValue"};

  SNTSyncStateAccessor *accessor =
      [[SNTSyncStateAccessor alloc] initWithSyncState:syncState overrides:overrides];

  // Count should be 2 (unique keys)
  XCTAssertEqual(accessor.count, 2);
}

- (void)testAllKeys {
  NSDictionary *syncState = @{@"key1" : @"value1", @"key2" : @"value2"};
  NSDictionary *overrides = @{@"key3" : @"value3"};

  SNTSyncStateAccessor *accessor =
      [[SNTSyncStateAccessor alloc] initWithSyncState:syncState overrides:overrides];

  NSArray *allKeys = accessor.allKeys;
  XCTAssertEqual(allKeys.count, 3);
  XCTAssertTrue([allKeys containsObject:@"key1"]);
  XCTAssertTrue([allKeys containsObject:@"key2"]);
  XCTAssertTrue([allKeys containsObject:@"key3"]);
}

- (void)testUpdateSyncStateValue {
  NSDictionary *syncState = @{@"key1" : @"oldValue"};
  SNTSyncStateAccessor *accessor =
      [[SNTSyncStateAccessor alloc] initWithSyncState:syncState overrides:nil];

  [accessor updateSyncStateValue:@"newValue" forKey:@"key1"];

  XCTAssertEqualObjects(accessor[@"key1"], @"newValue");
  XCTAssertEqualObjects(accessor.underlyingSyncState[@"key1"], @"newValue");
}

- (void)testUpdateSyncStateValueDoesNotAffectOverrides {
  NSDictionary *syncState = @{@"key1" : @"syncValue"};
  NSDictionary *overrides = @{@"key1" : @"overrideValue"};

  SNTSyncStateAccessor *accessor =
      [[SNTSyncStateAccessor alloc] initWithSyncState:syncState overrides:overrides];

  [accessor updateSyncStateValue:@"newSyncValue" forKey:@"key1"];

  // Override should still take precedence
  XCTAssertEqualObjects(accessor[@"key1"], @"overrideValue");
  // But sync state should be updated
  XCTAssertEqualObjects(accessor.underlyingSyncState[@"key1"], @"newSyncValue");
}

- (void)testUpdateSyncStateValueWithNil {
  NSDictionary *syncState = @{@"key1" : @"value1"};
  SNTSyncStateAccessor *accessor =
      [[SNTSyncStateAccessor alloc] initWithSyncState:syncState overrides:nil];

  [accessor updateSyncStateValue:nil forKey:@"key1"];

  XCTAssertNil(accessor[@"key1"]);
  XCTAssertNil(accessor.underlyingSyncState[@"key1"]);
}

- (void)testReplaceAllOverrides {
  NSDictionary *syncState = @{@"key1" : @"syncValue"};
  NSDictionary *oldOverrides = @{@"key1" : @"oldOverride"};

  SNTSyncStateAccessor *accessor =
      [[SNTSyncStateAccessor alloc] initWithSyncState:syncState overrides:oldOverrides];

  XCTAssertEqualObjects(accessor[@"key1"], @"oldOverride");

  NSDictionary *newOverrides = @{@"key1" : @"newOverride"};
  [accessor replaceAllOverrides:newOverrides];

  XCTAssertEqualObjects(accessor[@"key1"], @"newOverride");
  XCTAssertEqualObjects(accessor.underlyingOverrides, newOverrides);
}

- (void)testReplaceAllOverridesWithNil {
  NSDictionary *syncState = @{@"key1" : @"syncValue"};
  NSDictionary *overrides = @{@"key1" : @"overrideValue"};

  SNTSyncStateAccessor *accessor =
      [[SNTSyncStateAccessor alloc] initWithSyncState:syncState overrides:overrides];

  [accessor replaceAllOverrides:nil];

  // Should fall back to sync state
  XCTAssertEqualObjects(accessor[@"key1"], @"syncValue");
  XCTAssertEqualObjects(accessor.underlyingOverrides, @{});
}

- (void)testReplaceAllOverridesRemovesOldOverrides {
  NSDictionary *syncState = @{@"key1" : @"syncValue"};
  NSDictionary *oldOverrides = @{@"key2" : @"override2"};

  SNTSyncStateAccessor *accessor =
      [[SNTSyncStateAccessor alloc] initWithSyncState:syncState overrides:oldOverrides];

  NSDictionary *newOverrides = @{@"key3" : @"override3"};
  [accessor replaceAllOverrides:newOverrides];

  // Old override should be gone
  XCTAssertNil(accessor[@"key2"]);
  // New override should be present
  XCTAssertEqualObjects(accessor[@"key3"], @"override3");
}

@end
