/// Copyright 2016 Google Inc. All rights reserved.
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

#include "Source/common/SantaCache.h"

#import <XCTest/XCTest.h>

#include <numeric>
#include <set>
#include <string>
#include <vector>

@interface SantaCacheTest : XCTestCase
@end

@implementation SantaCacheTest

- (void)setUp {
  self.continueAfterFailure = NO;
}

- (void)testSetAndGet {
  auto sut = SantaCache<uint64_t, uint64_t>();

  sut.set(72057611258548992llu, 10000192);
  XCTAssertEqual(sut.get(72057611258548992llu), 10000192);
}

- (void)testCacheRemove {
  auto sut = SantaCache<uint64_t, uint64_t>();

  sut.set(0xDEADBEEF, 42);
  sut.remove(0xDEADBEEF);

  XCTAssertEqual(sut.get(0xDEADBEEF), 0);
}

- (void)testBucketGrowCopy {
  auto sut = SantaCache<uint64_t, uint64_t>();

  sut.set(386, 42);
  sut.set(2434, 42);

  XCTAssertEqual(sut.get(386), 42);
  XCTAssertEqual(sut.get(2434), 42);
}

- (void)testBucketShrinkCopy {
  auto sut = SantaCache<uint64_t, uint64_t>(100, 1);

  sut.set(386, 42);
  sut.set(2434, 42);
  sut.set(4482, 42);

  sut.remove(2434);

  XCTAssertEqual(sut.get(386), 42);
  XCTAssertEqual(sut.get(2434), 0);
  XCTAssertEqual(sut.get(4482), 42);
}

- (void)testCacheResetAtLimit {
  auto sut = SantaCache<uint64_t, uint64_t>(5);

  sut.set(1, 42);
  sut.set(2, 42);
  sut.set(3, 42);
  sut.set(4, 42);
  sut.set(5, 42);
  XCTAssertEqual(sut.get(3), 42);
  sut.set(6, 42);
  XCTAssertEqual(sut.get(3), 0);
  XCTAssertEqual(sut.get(6), 42);
}

// Helper to test bucket distributions for uint64_t/uint64_t combinations.
- (void)distributionTestHelper:(SantaCache<uint64_t, uint64_t> *)sut bucketRatio:(int)br {
  uint16_t count[512];
  uint16_t array_size = 512;
  uint64_t start_bucket = 0;
  std::vector<uint16_t> per_bucket;
  do {
    sut->bucket_counts(count, &array_size, &start_bucket);
    for (int i = 0; i < array_size; ++i) {
      per_bucket.push_back(count[i]);
    }
  } while (start_bucket > 0);

  // Calculate mean
  double mean = std::accumulate(per_bucket.begin(), per_bucket.end(), 0.0) / per_bucket.size();
  XCTAssertLessThanOrEqual(mean, br, @"Mean per-bucket count is greater than %d", br);

  // Calculate stdev
  double accum = 0.0;
  std::for_each(per_bucket.begin(), per_bucket.end(),
                [&](const double d) { accum += (d - mean) * (d - mean); });
  double stddev = sqrt(accum / (per_bucket.size() - 1));
  double maxStdDev = (double)br / 2;
  XCTAssertLessThanOrEqual(stddev, maxStdDev,
                           @"Standard deviation between buckets is greater than %f", maxStdDev);
}

- (void)testDistributionRandomKeys {
  const int bucket_ratio = 5;
  SantaCache<uint64_t, uint64_t> sut(5000, bucket_ratio);

  // Fill the cache with random keys, all set to 1.
  for (int i = 0; i < 4000; ++i) {
    sut.set((uint64_t)arc4random() << 32 | arc4random(), 1);
  }

  [self distributionTestHelper:&sut bucketRatio:bucket_ratio];
}

- (void)testDistributionMontonicKeys {
  const int bucket_ratio = 5;
  SantaCache<uint64_t, uint64_t> sut(5000, bucket_ratio);

  // Fill the cache with monotonic keys, all set to 1.
  for (int i = 0; i < 4000; ++i) {
    sut.set(i, 1);
  }

  [self distributionTestHelper:&sut bucketRatio:bucket_ratio];
}

- (void)testThreading {
  auto sut = new SantaCache<uint64_t, uint64_t>();

  for (int x = 0; x < 200; ++x) {
    dispatch_group_t group = dispatch_group_create();

    dispatch_group_enter(group);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
      for (int i = 0; i < 5000; ++i)
        sut->set(i, 10000 - i);
      dispatch_group_leave(group);
    });

    dispatch_group_enter(group);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
      for (int i = 5000; i < 10000; ++i)
        sut->set(i, 10000 - i);
      dispatch_group_leave(group);
    });

    if (dispatch_group_wait(group, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC))) {
      XCTFail("Timed out while setting values for test");
    }

    for (int i = 0; i < 10000; ++i)
      XCTAssertEqual(sut->get(i), 10000 - i);
  }

  delete sut;
}

- (void)testCount {
  auto sut = SantaCache<uint64_t, int>();

  XCTAssertEqual(sut.count(), 0);

  sut.set(4012, 42);
  sut.set(42, 0);
  sut.set(0x8BADF00D, 40010);

  XCTAssertEqual(sut.count(), 2);
}

- (void)testDoubles {
  auto sut = SantaCache<double, double>();

  sut.set(3.14, 2.718281);
  sut.set(1.41429, 2.5029);
  sut.set(4.6692, 1.2020569);
  sut.set(1.61803398, 0.57721);

  XCTAssertEqual(sut.count(), 4);
  XCTAssertEqual(sut.get(3.14), 2.718281);
  XCTAssertEqual(sut.get(1.41429), 2.5029);
  XCTAssertEqual(sut.get(4.6692), 1.2020569);
  XCTAssertEqual(sut.get(1.61803398), 0.57721);

  XCTAssertEqual(sut.get(5.5555), 0);
  XCTAssertEqual(sut.get(3.1459124), 0);
}

- (void)testStrings {
  auto sut = SantaCache<std::string, std::string>();

  std::string s1 = "foo";
  std::string s2 = "bar";

  sut.set(s1, "deadbeef");
  sut.set(s2, "feedface");

  XCTAssertEqual(sut.count(), 2);
  XCTAssertEqual(sut.get(s1), "deadbeef");
  XCTAssertEqual(sut.get(s2), "feedface");

  sut.remove(s2);

  XCTAssertTrue(sut.get(s2).empty());
}

- (void)testCompareAndSwap {
  auto sut = SantaCache<uint64_t, uint64_t>(100, 2);

  sut.set(1, 42);
  sut.set(1, 666, 1);
  sut.set(1, 666, 0);
  XCTAssertEqual(sut.get(1), 42);

  sut.set(1, 0);
  XCTAssertEqual(sut.get(1), 0);

  sut.set(1, 42, 1);
  XCTAssertEqual(sut.get(1), 0);

  sut.set(1, 42, 0);
  XCTAssertEqual(sut.get(1), 42);

  sut.set(1, 0, 666);
  XCTAssertEqual(sut.get(1), 42);
  sut.set(1, 0, 42);
  XCTAssertEqual(sut.get(1), 0);
}

struct S {
  uint64_t first_val;
  uint64_t second_val;

  bool operator==(const S &rhs) const {
    return first_val == rhs.first_val && second_val == rhs.second_val;
  }

  template <typename H>
  friend H AbslHashValue(H h, const S &v) {
    return H::combine(std::move(h), v.first_val, v.second_val);
  }
};

- (void)testStructKeys {
  auto sut = SantaCache<S, uint64_t>(10, 2);

  S s1 = {1024, 2048};
  S s2 = {4096, 8192};
  S s3 = {16384, 32768};
  sut.set(s1, 10);
  sut.set(s2, 20);
  sut.set(s3, 30);

  XCTAssertEqual(sut.get(s1), 10);
  XCTAssertEqual(sut.get(s2), 20);
  XCTAssertEqual(sut.get(s3), 30);
}

- (void)testBucketCounts {
  SantaCache<uint64_t, uint64_t> sut(UINT16_MAX, 1);

  // These tests verify that the bucket_counts() function can't be abused
  // with integer {over,under}flow issues in the input or going out-of-bounds
  // on the buckets array.
  uint16_t size = 2048;
  uint64_t start = (UINT64_MAX - 2047);
  uint16_t per_bucket_counts[2048];
  sut.bucket_counts(per_bucket_counts, &size, &start);
  XCTAssertEqual(start, 0, @"Check a high start can't overflow");

  size = UINT16_MAX;
  start = UINT16_MAX - 1;
  sut.bucket_counts(per_bucket_counts, &size, &start);
  XCTAssertEqual(start, 0, @"Check a large size can't overflow");
}

- (void)testUpdateScalarExisting {
  SantaCache<uint64_t, uint64_t> sut;

  XCTAssertTrue(sut.set(12, 34));
  XCTAssertEqual(sut.get(12), 34);

  sut.update(12, ^(uint64_t &val) {
    XCTAssertEqual(val, 34);
    val = 56;
  });

  XCTAssertEqual(sut.get(12), 56);
}

- (void)testUpdateScalarNew {
  SantaCache<uint64_t, uint64_t> sut;

  sut.update(12, ^(uint64_t &val) {
    XCTAssertEqual(val, 0);
    val = 56;
  });

  XCTAssertEqual(sut.get(12), 56);
}

- (void)testUpdateObjectExisting {
  SantaCache<uint64_t, std::set<int>> sut;
  XCTAssertEqual(sut.get(12).size(), 0);

  XCTAssertTrue(sut.set(12, std::set<int>{11, 22, 33}));

  auto res = sut.get(12);
  XCTAssertEqual(res.size(), 3);
  XCTAssertEqual(res.count(11), 1);
  XCTAssertEqual(res.count(22), 1);
  XCTAssertEqual(res.count(33), 1);
  XCTAssertEqual(res.count(44), 0);

  sut.update(12, ^(std::set<int> &val) {
    XCTAssertEqual(val.size(), 3);
    val.insert(44);
  });

  res = sut.get(12);
  XCTAssertEqual(res.size(), 4);
  XCTAssertEqual(res.count(11), 1);
  XCTAssertEqual(res.count(22), 1);
  XCTAssertEqual(res.count(33), 1);
  XCTAssertEqual(res.count(44), 1);
}

- (void)testUpdateObjectNew {
  SantaCache<uint64_t, std::set<int>> sut;

  sut.update(12, ^(std::set<int> &val) {
    XCTAssertEqual(val.size(), 0);
    val = {11, 22, 33, 44};
  });

  auto res = sut.get(12);
  XCTAssertEqual(res.size(), 4);
  XCTAssertEqual(res.count(11), 1);
  XCTAssertEqual(res.count(22), 1);
  XCTAssertEqual(res.count(33), 1);
  XCTAssertEqual(res.count(44), 1);
}

- (void)testUpdateSharedObjectExisting {
  using IntSet = std::set<int>;
  SantaCache<uint64_t, std::shared_ptr<IntSet>> sut;

  XCTAssertEqual(sut.get(12), nullptr);
  XCTAssertTrue(sut.set(12, std::make_shared<IntSet>(IntSet{11, 22, 33})));

  auto res = sut.get(12);
  XCTAssertNotEqual(res, nullptr);
  XCTAssertEqual(res->size(), 3);
  XCTAssertEqual(res->count(11), 1);
  XCTAssertEqual(res->count(22), 1);
  XCTAssertEqual(res->count(33), 1);
  XCTAssertEqual(res->count(44), 0);

  sut.update(12, ^(std::shared_ptr<IntSet> &val) {
    XCTAssertNotEqual(val, nullptr);
    XCTAssertEqual(val->size(), 3);
    val->insert(44);
  });

  res = sut.get(12);
  XCTAssertEqual(res->size(), 4);
  XCTAssertEqual(res->count(11), 1);
  XCTAssertEqual(res->count(22), 1);
  XCTAssertEqual(res->count(33), 1);
  XCTAssertEqual(res->count(44), 1);
}

- (void)testUpdateSharedObjectNew {
  using IntSet = std::set<int>;
  SantaCache<uint64_t, std::shared_ptr<IntSet>> sut;

  sut.update(12, ^(std::shared_ptr<IntSet> &val) {
    // shared_ptr is initially null
    XCTAssertEqual(val, nullptr);
    val = std::make_shared<IntSet>(IntSet{11, 22, 33});
  });

  auto res = sut.get(12);
  XCTAssertEqual(res->size(), 3);
  XCTAssertEqual(res->count(11), 1);
  XCTAssertEqual(res->count(22), 1);
  XCTAssertEqual(res->count(33), 1);
  XCTAssertEqual(res->count(44), 0);
}

- (void)testUpdateSharedObjectMaxCapacity {
  using IntSet = std::set<int>;
  SantaCache<uint64_t, std::shared_ptr<IntSet>> sut(3);

  sut.update(12, ^(std::shared_ptr<IntSet> &val) {
    XCTAssertEqual(val, nullptr);
    val = std::make_shared<IntSet>(IntSet{11, 22});
  });

  sut.update(34, ^(std::shared_ptr<IntSet> &val) {
    XCTAssertEqual(val, nullptr);
    val = std::make_shared<IntSet>(IntSet{33, 44});
  });

  sut.update(56, ^(std::shared_ptr<IntSet> &val) {
    XCTAssertEqual(val, nullptr);
    val = std::make_shared<IntSet>(IntSet{55, 66});
  });

  XCTAssertEqual(sut.count(), 3);

  sut.update(78, ^(std::shared_ptr<IntSet> &val) {
    XCTAssertEqual(val, nullptr);
    val = std::make_shared<IntSet>(IntSet{77, 88});
  });

  XCTAssertEqual(sut.count(), 1);

  sut.clear();

  XCTAssertEqual(sut.count(), 0);
}

- (void)testContains {
  SantaCache<uint64_t, uint64_t> sut;

  XCTAssertEqual(sut.count(), 0);

  XCTAssertFalse(sut.contains(1));
  XCTAssertFalse(sut.contains(1, ^(const uint64_t &) {
    return true;
  }));

  XCTAssertTrue(sut.set(1, 2));
  XCTAssertEqual(sut.count(), 1);
  XCTAssertTrue(sut.contains(1));
  XCTAssertFalse(sut.contains(1, ^(const uint64_t &) {
    return false;
  }));
  XCTAssertTrue(sut.contains(1, ^(const uint64_t &x) {
    return x == 2;
  }));
  XCTAssertFalse(sut.contains(1, ^(const uint64_t &x) {
    return x == 3;
  }));
}

- (void)testForeach {
  SantaCache<uint64_t, uint64_t> sut;
  sut.set(1, 11);
  sut.set(2, 22);
  sut.set(3, 33);
  sut.set(4, 44);
  sut.set(5, 55);

  sut.set(6, 66);
  sut.remove(6);

  NSDictionary *want = @{@(1) : @(11), @(2) : @(22), @(3) : @(33), @(4) : @(44), @(5) : @(55)};
  __block NSMutableDictionary *got = [[NSMutableDictionary alloc] init];

  sut.foreach(^(uint64_t k, uint64_t v) {
    [got setObject:@(v) forKey:@(k)];
  });

  XCTAssertEqualObjects(got, want);
}

- (void)testForeachSharedObject {
  SantaCache<uint64_t, std::shared_ptr<uint64_t>> sut;
  sut.set(1, std::make_shared<uint64_t>(11));
  sut.set(2, std::make_shared<uint64_t>(22));
  sut.set(3, std::make_shared<uint64_t>(33));

  sut.set(4, std::make_shared<uint64_t>(44));
  sut.remove(4);

  NSDictionary *want = @{@(1) : @(11), @(2) : @(22), @(3) : @(33)};
  __block NSMutableDictionary *got = [[NSMutableDictionary alloc] init];

  sut.foreach(^(uint64_t k, std::shared_ptr<uint64_t> v) {
    [got setObject:@(*v) forKey:@(k)];
  });

  XCTAssertEqualObjects(got, want);
}

- (void)testClear {
  SantaCache<uint64_t, uint64_t> sut;
  sut.set(1, 11);
  sut.set(2, 22);
  sut.set(3, 33);
  sut.set(4, 44);

  XCTAssertEqual(sut.count(), 4);
  XCTAssertEqual(sut.get(3), 33);

  sut.clear();

  XCTAssertEqual(sut.count(), 0);
  XCTAssertEqual(sut.get(3), 0);
}
- (void)testClearCallback {
  SantaCache<uint64_t, std::shared_ptr<uint64_t>> sut;
  sut.set(1, std::make_shared<uint64_t>(11));
  sut.set(2, std::make_shared<uint64_t>(22));
  sut.set(3, std::make_shared<uint64_t>(33));

  XCTAssertEqual(sut.count(), 3);
  XCTAssertEqual(*sut.get(2), 22);

  NSDictionary *want = @{@(1) : @(11), @(2) : @(22), @(3) : @(33)};
  __block NSMutableDictionary *got = [[NSMutableDictionary alloc] init];

  sut.clear(^(uint64_t k, std::shared_ptr<uint64_t> v) {
    [got setObject:@(*v) forKey:@(k)];
  });

  XCTAssertEqualObjects(got, want);

  XCTAssertEqual(sut.count(), 0);
  XCTAssertEqual(sut.get(2), nullptr);
}

@end
