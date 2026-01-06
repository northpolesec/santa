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

#include "src/common/SantaSetCache.h"
#include "XCTest/XCTest.h"

#import <XCTest/XCTest.h>

using santa::SantaSetCache;

// Test aliases
using IntSantaSetCache = SantaSetCache<int, int>;

@interface SantaSetCacheTest : XCTestCase
@end

@implementation SantaSetCacheTest

- (void)testBasic {
  IntSantaSetCache cache(3, 3);

  XCTAssertTrue(cache.Set(1, 1));
  XCTAssertFalse(cache.Set(1, 1));

  IntSantaSetCache::SharedConstValueSet val = cache.UnsafeGet(1);
  XCTAssertNotEqual(val, nullptr);
  XCTAssertEqual(val->size(), 1);

  XCTAssertTrue(cache.Set(1, 2));
  XCTAssertTrue(cache.Set(1, 3));

  XCTAssertEqual(val->size(), 3);

  // Add another key and check the value
  XCTAssertTrue(cache.Set(2, 1));
  val = cache.UnsafeGet(2);
  XCTAssertNotEqual(val, nullptr);
  XCTAssertEqual(val->size(), 1);

  // Key 3 hasn't been added
  val = cache.UnsafeGet(3);
  XCTAssertEqual(val, nullptr);

  XCTAssertEqual(cache.Size(), 2);

  cache.Remove(1);
  val = cache.UnsafeGet(1);
  XCTAssertEqual(val, nullptr);

  XCTAssertEqual(cache.Size(), 1);

  XCTAssertTrue(cache.Contains(2, 1));

  cache.Clear();

  XCTAssertFalse(cache.Contains(2, 1));

  XCTAssertEqual(cache.Size(), 0);
}

- (void)testCapacities {
  IntSantaSetCache cache(3, 2);

  XCTAssertTrue(cache.Set(1, 1));
  XCTAssertTrue(cache.Set(1, 2));

  IntSantaSetCache::SharedConstValueSet val = cache.UnsafeGet(1);
  XCTAssertEqual(val->size(), 2);

  // Overflow the inner set so that the initial values are cleared
  XCTAssertTrue(cache.Set(1, 3));
  val = cache.UnsafeGet(1);
  XCTAssertEqual(val->size(), 1);
  XCTAssertEqual(val->count(1), 0);
  XCTAssertEqual(val->count(2), 0);
  XCTAssertEqual(val->count(3), 1);

  // Max out outer cache size
  XCTAssertEqual(cache.Size(), 1);
  XCTAssertTrue(cache.Set(2, 1));
  XCTAssertTrue(cache.Set(3, 1));
  XCTAssertEqual(cache.Size(), 3);

  // Re-add existing value
  XCTAssertFalse(cache.Set(3, 1));
  XCTAssertEqual(cache.Size(), 3);

  // Old inner set should still exist
  val = cache.UnsafeGet(1);
  XCTAssertEqual(val->size(), 1);
  XCTAssertEqual(val->count(3), 1);

  // Overflow the outer cache
  XCTAssertTrue(cache.Set(4, 1));
  XCTAssertEqual(cache.Size(), 1);

  // Old value is now gone, new value exists
  val = cache.UnsafeGet(1);
  XCTAssertEqual(val, nullptr);

  val = cache.UnsafeGet(4);
  XCTAssertEqual(val->size(), 1);
  XCTAssertEqual(val->count(1), 1);
}

- (void)testObjects {
  SantaSetCache<int, std::pair<std::string, std::string>> cache(3, 2);

  XCTAssertTrue(cache.Set(1, {"hi", "bye"}));
  XCTAssertTrue(cache.Set(1, {"bye", "hi"}));
  XCTAssertFalse(cache.Set(1, {"hi", "bye"}));

  auto val = cache.UnsafeGet(1);
  XCTAssertEqual(val->size(), 2);

  XCTAssertTrue(cache.Set(1, {"foo", "bar"}));
  val = cache.UnsafeGet(1);
  XCTAssertEqual(val->size(), 1);
  XCTAssertTrue(cache.Set(1, {"hi", "bye"}));
  XCTAssertEqual(val->size(), 2);
}

@end
