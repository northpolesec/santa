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

#include "Source/santad/RecentBlocks.h"

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

using santa::RecentBlocks;

@interface RecentBlocksTest : XCTestCase
@end

@implementation RecentBlocksTest

- (void)testRecordedFieldsAndOrder {
  RecentBlocks blocks;

  blocks.Record(12, 34, 501, @"/usr/bin/first", @"abc123", @"No matching rule");
  blocks.Record(56, 78, 501, @"/usr/bin/second", nil, @"Binary rule");

  NSArray<NSDictionary*>* got = blocks.Since([NSDate distantPast], 501);

  XCTAssertEqual(got.count, (NSUInteger)2);
  XCTAssertEqualObjects(got[0][santa::kRecentBlockPath], @"/usr/bin/first");
  XCTAssertEqualObjects(got[0][santa::kRecentBlockPID], @(12));
  XCTAssertEqualObjects(got[0][santa::kRecentBlockPPID], @(34));
  XCTAssertEqualObjects(got[0][santa::kRecentBlockUID], @(501));
  XCTAssertEqualObjects(got[0][santa::kRecentBlockSHA256], @"abc123");
  XCTAssertEqualObjects(got[0][santa::kRecentBlockReason], @"No matching rule");
  XCTAssertGreaterThan([got[0][santa::kRecentBlockTimestamp] doubleValue], 0);

  // Oldest first, and a nil value is recorded as an empty string rather than
  // being dropped from the dictionary.
  XCTAssertEqualObjects(got[1][santa::kRecentBlockPath], @"/usr/bin/second");
  XCTAssertEqualObjects(got[1][santa::kRecentBlockSHA256], @"");
}

- (void)testSinceExcludesOlderBlocks {
  RecentBlocks blocks;

  blocks.Record(12, 34, 501, @"/usr/bin/old", nil, @"Binary rule");

  XCTAssertEqual(blocks.Since([NSDate dateWithTimeIntervalSinceNow:1], 501).count, (NSUInteger)0);
  XCTAssertEqual(blocks.Since([NSDate dateWithTimeIntervalSinceNow:-60], 501).count, (NSUInteger)1);
}

- (void)testOnlyTheCallersOwnBlocksUnlessRoot {
  RecentBlocks blocks;

  blocks.Record(12, 34, 501, @"/usr/bin/mine", nil, @"Binary rule");
  blocks.Record(56, 78, 502, @"/usr/bin/theirs", nil, @"Binary rule");

  NSArray<NSDictionary*>* mine = blocks.Since([NSDate distantPast], 501);
  XCTAssertEqual(mine.count, (NSUInteger)1);
  XCTAssertEqualObjects(mine[0][santa::kRecentBlockPath], @"/usr/bin/mine");

  XCTAssertEqual(blocks.Since([NSDate distantPast], 0).count, (NSUInteger)2);
}

- (void)testOldestBlocksAreDroppedWhenFull {
  RecentBlocks blocks;

  for (size_t i = 0; i < RecentBlocks::kCapacity + 5; ++i) {
    blocks.Record((pid_t)i, 0, 501, [NSString stringWithFormat:@"/usr/bin/%zu", i], nil,
                  @"Binary rule");
  }

  NSArray<NSDictionary*>* got = blocks.Since([NSDate distantPast], 501);

  XCTAssertEqual(got.count, RecentBlocks::kCapacity);
  XCTAssertEqualObjects(got.firstObject[santa::kRecentBlockPath], @"/usr/bin/5");
  NSString* newest = [NSString stringWithFormat:@"/usr/bin/%zu", RecentBlocks::kCapacity + 4];
  XCTAssertEqualObjects(got.lastObject[santa::kRecentBlockPath], newest);
}

@end
