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

#include "src/santad/EntitlementsFilter.h"

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#include <memory>

using santa::EntitlementsFilter;

@interface EntitlementsFilterTest : XCTestCase
@end

@implementation EntitlementsFilterTest

#pragma mark - Basic Filtering Tests

- (void)testFilterNilAndEmptyEntitlements {
  std::unique_ptr<EntitlementsFilter> filter = EntitlementsFilter::Create(@[], @[]);

  NSDictionary *result = filter->Filter("TEAMID123", nil);
  XCTAssertNil(result, @"Filtering nil entitlements should return nil");

  result = filter->Filter("TEAMID123", @{});
  XCTAssertNotNil(result, @"Empty entitlements should return an empty dictionary");
  XCTAssertEqual(result.count, 0, @"Result should be empty");
}

- (void)testFilterNoFiltersReturnsDeepCopy {
  std::unique_ptr<EntitlementsFilter> filter = EntitlementsFilter::Create(@[], @[]);

  NSDictionary *entitlements = @{
    @"com.apple.security.app-sandbox" : @YES,
    @"com.apple.security.network.client" : @YES,
    @"keychain-access-groups" : @[ @"group1", @"group2" ],
  };

  NSDictionary *result = filter->Filter("TEAMID123", entitlements);

  XCTAssertEqual(result.count, 3);
  XCTAssertEqualObjects(result[@"com.apple.security.app-sandbox"], @YES);
  XCTAssertEqualObjects(result[@"com.apple.security.network.client"], @YES);

  // Verify it's a deep copy - modifying result shouldn't affect original
  NSMutableDictionary *mutableResult = [result mutableCopy];
  mutableResult[@"com.apple.security.app-sandbox"] = @NO;
  XCTAssertEqualObjects(entitlements[@"com.apple.security.app-sandbox"], @YES,
                        @"Original should be unchanged");
}

#pragma mark - TeamID Filtering Tests

- (void)testFilterTeamIDInFilterReturnsNil {
  std::unique_ptr<EntitlementsFilter> filter =
      EntitlementsFilter::Create(@[ @"TEAMID123", @"TEAMID456" ], @[]);

  NSDictionary *entitlements = @{
    @"com.apple.security.app-sandbox" : @YES,
  };

  NSDictionary *result = filter->Filter("TEAMID123", entitlements);

  XCTAssertNil(result, @"Entitlements for filtered TeamID should be dropped");
}

- (void)testFilterTeamIDNotInFilterReturnsEntitlements {
  std::unique_ptr<EntitlementsFilter> filter =
      EntitlementsFilter::Create(@[ @"TEAMID123", @"TEAMID456" ], @[]);

  NSDictionary *entitlements = @{
    @"com.apple.security.app-sandbox" : @YES,
  };

  NSDictionary *result = filter->Filter("OTHERTEAM", entitlements);

  XCTAssertEqualObjects(result[@"com.apple.security.app-sandbox"], @YES);
}

- (void)testFilterNullTeamIDNotFiltered {
  std::unique_ptr<EntitlementsFilter> filter = EntitlementsFilter::Create(@[ @"TEAMID123" ], @[]);

  NSDictionary *entitlements = @{
    @"com.apple.security.app-sandbox" : @YES,
  };

  NSDictionary *result = filter->Filter(NULL, entitlements);

  XCTAssertEqual(result.count, 1);
}

#pragma mark - Prefix Filtering Tests

- (void)testFilterPrefixMatchesAreExcluded {
  std::unique_ptr<EntitlementsFilter> filter = EntitlementsFilter::Create(@[], @[ @"com.apple." ]);

  NSDictionary *entitlements = @{
    @"com.apple.security.app-sandbox" : @YES,
    @"com.apple.security.network.client" : @YES,
    @"com.myapp.custom" : @YES,
  };

  NSDictionary *result = filter->Filter("TEAMID123", entitlements);

  XCTAssertEqual(result.count, 1, @"Only non-matching prefixes should remain");
  XCTAssertEqualObjects(result[@"com.myapp.custom"], @YES);
  XCTAssertNil(result[@"com.apple.security.app-sandbox"]);
  XCTAssertNil(result[@"com.apple.security.network.client"]);
}

- (void)testFilterMultiplePrefixes {
  std::unique_ptr<EntitlementsFilter> filter =
      EntitlementsFilter::Create(@[], @[ @"com.apple.", @"com.example." ]);

  NSDictionary *entitlements = @{
    @"com.apple.security.app-sandbox" : @YES,
    @"com.example.testing" : @YES,
    @"com.myapp.custom" : @YES,
    @"keychain-access-groups" : @[ @"group1" ],
  };

  NSDictionary *result = filter->Filter("TEAMID123", entitlements);

  XCTAssertNotNil(result);
  XCTAssertEqual(result.count, 2);
  XCTAssertEqualObjects(result[@"com.myapp.custom"], @YES);
  XCTAssertEqualObjects(result[@"keychain-access-groups"], (@[ @"group1" ]));
}

- (void)testFilterAllEntitlementsExcludedReturnsNil {
  std::unique_ptr<EntitlementsFilter> filter = EntitlementsFilter::Create(@[], @[ @"com.apple." ]);

  NSDictionary *entitlements = @{
    @"com.apple.security.app-sandbox" : @YES,
    @"com.apple.security.network.client" : @YES,
  };

  NSDictionary *result = filter->Filter("TEAMID123", entitlements);

  XCTAssertNil(result, @"When all entitlements are filtered, should return nil");
}

#pragma mark - Update Filter Tests

- (void)testUpdateTeamIDFilter {
  std::unique_ptr<EntitlementsFilter> filter = EntitlementsFilter::Create(@[ @"TEAMID123" ], @[]);

  NSDictionary *entitlements = @{@"com.apple.security.app-sandbox" : @YES};

  // Initially, TEAMID123 is filtered but TEAMID456 is not
  XCTAssertNil(filter->Filter("TEAMID123", entitlements));
  XCTAssertNotNil(filter->Filter("TEAMID456", entitlements));

  // Update to filter TEAMID456 instead
  filter->UpdateTeamIDFilter(@[ @"TEAMID456" ]);

  // Now TEAMID123 is not filtered but TEAMID456 is
  XCTAssertNotNil(filter->Filter("TEAMID123", entitlements));
  XCTAssertNil(filter->Filter("TEAMID456", entitlements));
}

- (void)testUpdateTeamIDFilterToEmpty {
  std::unique_ptr<EntitlementsFilter> filter = EntitlementsFilter::Create(@[ @"TEAMID123" ], @[]);

  NSDictionary *entitlements = @{@"com.apple.security.app-sandbox" : @YES};

  // Initially TEAMID123 is filtered
  XCTAssertNil(filter->Filter("TEAMID123", entitlements));

  // Update to empty filter
  filter->UpdateTeamIDFilter(@[]);

  // Now nothing is filtered by TeamID
  XCTAssertNotNil(filter->Filter("TEAMID123", entitlements));
}

- (void)testUpdatePrefixFilter {
  std::unique_ptr<EntitlementsFilter> filter = EntitlementsFilter::Create(@[], @[ @"com.apple." ]);

  NSDictionary *entitlements = @{
    @"com.apple.security.app-sandbox" : @YES,
    @"com.example.custom" : @YES,
  };

  // Initially com.apple. is filtered
  NSDictionary *result = filter->Filter("TEAMID123", entitlements);
  XCTAssertEqual(result.count, 1);
  XCTAssertNil(result[@"com.apple.security.app-sandbox"]);

  // Update to filter com.example. instead
  filter->UpdatePrefixFilter(@[ @"com.example." ]);

  result = filter->Filter("TEAMID123", entitlements);
  XCTAssertEqual(result.count, 1);
  XCTAssertNotNil(result[@"com.apple.security.app-sandbox"]);
  XCTAssertNil(result[@"com.example.custom"]);
}

- (void)testUpdatePrefixFilterToEmpty {
  std::unique_ptr<EntitlementsFilter> filter = EntitlementsFilter::Create(@[], @[ @"com.apple." ]);

  NSDictionary *entitlements = @{
    @"com.apple.security.app-sandbox" : @YES,
    @"com.example.custom" : @YES,
  };

  // Initially com.apple. is filtered
  NSDictionary *result = filter->Filter("TEAMID123", entitlements);
  XCTAssertEqual(result.count, 1);

  // Update to empty filter (no prefix filtering)
  filter->UpdatePrefixFilter(@[]);

  // Now all entitlements are returned
  result = filter->Filter("TEAMID123", entitlements);
  XCTAssertEqual(result.count, 2);
  XCTAssertNotNil(result[@"com.apple.security.app-sandbox"]);
  XCTAssertNotNil(result[@"com.example.custom"]);
}

#pragma mark - Thread Safety Tests

- (void)testConcurrentUpdateAndFilter {
  std::unique_ptr<EntitlementsFilter> filter = EntitlementsFilter::Create(@[], @[ @"com.apple." ]);

  NSDictionary *entitlements = @{
    @"com.apple.security.app-sandbox" : @YES,
    @"com.example.custom" : @YES,
    @"com.myapp.custom" : @YES,
  };

  dispatch_queue_t queue = dispatch_queue_create("test.concurrent", DISPATCH_QUEUE_CONCURRENT);
  dispatch_group_t group = dispatch_group_create();

  // Get raw pointer for use in blocks
  EntitlementsFilter *filterPtr = filter.get();

  // Launch concurrent readers
  for (int i = 0; i < 50; i++) {
    dispatch_group_async(group, queue, ^{
      NSDictionary *result = filterPtr->Filter("TEAMID123", entitlements);
      XCTAssertNotNil(result);
      // Result count will vary depending on which filter is active
      XCTAssertGreaterThan(result.count, 0);
    });
  }

  // Launch concurrent writers
  for (int i = 0; i < 10; i++) {
    dispatch_group_async(group, queue, ^{
      if (i % 2 == 0) {
        filterPtr->UpdatePrefixFilter(@[ @"com.apple." ]);
      } else {
        filterPtr->UpdatePrefixFilter(@[ @"com.example." ]);
      }
    });
  }

  // Wait for all to complete without crashing
  long success = dispatch_group_wait(group, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));
  XCTAssertEqual(success, 0, @"All concurrent operations should complete without deadlock");
}

@end
