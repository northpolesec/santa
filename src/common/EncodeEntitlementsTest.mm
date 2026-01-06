/// Copyright 2024 North Pole Security, Inc.
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

#include "src/common/EncodeEntitlements.h"
#include "XCTest/XCTest.h"

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

namespace santa {
extern id StandardizedNestedObjects(id obj, int level);
}  // namespace santa

using santa::EncodeEntitlementsCommon;
using santa::StandardizedNestedObjects;

@interface EncodeEntitlementsTest : XCTestCase
@end

@implementation EncodeEntitlementsTest

- (void)testStandardizedNestedObjectsTypes {
  id val = StandardizedNestedObjects(@"asdf", 1);
  XCTAssertTrue([val isKindOfClass:[NSString class]]);

  val = StandardizedNestedObjects(@(0), 1);
  XCTAssertTrue([val isKindOfClass:[NSNumber class]]);

  val = StandardizedNestedObjects(@[], 1);
  XCTAssertTrue([val isKindOfClass:[NSArray class]]);

  val = StandardizedNestedObjects(@{}, 1);
  XCTAssertTrue([val isKindOfClass:[NSDictionary class]]);

  val = StandardizedNestedObjects([[NSData alloc] init], 1);
  XCTAssertTrue([val isKindOfClass:[NSString class]]);

  val = StandardizedNestedObjects([NSDate now], 1);
  XCTAssertTrue([val isKindOfClass:[NSString class]]);
}

- (void)testStandardizedNestedObjectsLevels {
  NSArray *nestedObj = @[
    @[
      @[
        @[ @"111", @"112" ],
        @[ @"113", @"114" ],
      ],
      @[
        @[ @"121", @"122" ],
        @[ @"123", @"124" ],
      ]
    ],
    @[
      @[
        @[ @"211", @"212" ],
        @[ @"213", @"214" ],
      ],
      @[
        @[ @"221", @"222" ],
        @[ @"223", @"224" ],
      ]
    ]
  ];

  id val = StandardizedNestedObjects(nestedObj, 1);

  XCTAssertEqual(((NSArray *)val).count, 2);
  XCTAssertEqualObjects(
      val[0], @"(\n        (\n                (\n            111,\n            112\n        ),\n   "
              @"             (\n            113,\n            114\n        )\n    ),\n        (\n  "
              @"              (\n            121,\n            122\n        ),\n                "
              @"(\n            123,\n            124\n        )\n    )\n)");
  XCTAssertEqualObjects(
      val[1], @"(\n        (\n                (\n            211,\n            212\n        ),\n   "
              @"             (\n            213,\n            214\n        )\n    ),\n        (\n  "
              @"              (\n            221,\n            222\n        ),\n                "
              @"(\n            223,\n            224\n        )\n    )\n)");

  val = StandardizedNestedObjects(nestedObj, 3);

  XCTAssertEqual(((NSArray *)val).count, 2);
  XCTAssertEqual(((NSArray *)val[0]).count, 2);
  XCTAssertEqual(((NSArray *)val[1]).count, 2);
  XCTAssertEqual(((NSArray *)val[0][0]).count, 2);
  XCTAssertEqual(((NSArray *)val[0][1]).count, 2);
  XCTAssertEqualObjects(val[0][0][0], @"(\n    111,\n    112\n)");
  XCTAssertEqualObjects(val[0][0][1], @"(\n    113,\n    114\n)");
  XCTAssertEqualObjects(val[0][1][0], @"(\n    121,\n    122\n)");
  XCTAssertEqualObjects(val[0][1][1], @"(\n    123,\n    124\n)");
  XCTAssertEqualObjects(val[1][0][0], @"(\n    211,\n    212\n)");
  XCTAssertEqualObjects(val[1][0][1], @"(\n    213,\n    214\n)");
  XCTAssertEqualObjects(val[1][1][0], @"(\n    221,\n    222\n)");
  XCTAssertEqualObjects(val[1][1][1], @"(\n    223,\n    224\n)");
}

- (void)testEncodeEntitlementsCommonBasic {
  NSDictionary *entitlements = @{
    @"ent1" : @"val1",
    @"ent2" : @"val2",
  };

  EncodeEntitlementsCommon(
      entitlements, false,
      ^(NSUInteger count, bool is_filtered) {
        XCTAssertEqual(count, entitlements.count);
        XCTAssertFalse(is_filtered);
      },
      ^(NSString *entitlement, NSString *value) {
        if ([entitlement isEqualToString:@"ent1"]) {
          XCTAssertEqualObjects(value, @"\"val1\"");
        } else if ([entitlement isEqualToString:@"ent2"]) {
          XCTAssertEqualObjects(value, @"\"val2\"");
        } else {
          XCTFail(@"Unexpected entitlement: %@", entitlement);
        }
      });
}

- (void)testEncodeEntitlementsCommonFiltered {
  NSMutableDictionary *entitlements = [NSMutableDictionary dictionary];

  EncodeEntitlementsCommon(entitlements, true,
                           ^(NSUInteger count, bool is_filtered) {
                             XCTAssertEqual(count, entitlements.count);
                             XCTAssertTrue(is_filtered);
                           },
                           ^(NSString *entitlement, NSString *value){
                               // noop
                           });

  // Create a large dictionary that will get capped
  for (int i = 0; i < 100; i++) {
    entitlements[[NSString stringWithFormat:@"ent%d", i]] = [NSString stringWithFormat:@"val%d", i];
  }

  EncodeEntitlementsCommon(entitlements, false,
                           ^(NSUInteger count, bool is_filtered) {
                             XCTAssertLessThan(count, entitlements.count);
                             XCTAssertTrue(is_filtered);
                           },
                           ^(NSString *entitlement, NSString *value){
                               // noop
                           });
}

@end
