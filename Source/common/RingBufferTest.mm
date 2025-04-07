/// Copyright 2024 North Pole Security, Inc.
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

#include "Source/common/RingBuffer.h"

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#include <optional>

using santa::RingBuffer;

@interface RingBufferTest : XCTestCase
@end

@implementation RingBufferTest

- (void)testBasic {
  RingBuffer<int> rb(3);
  XCTAssertEqual(rb.Capacity(), 3);
  XCTAssertTrue(rb.Empty());
  XCTAssertFalse(rb.Full());

  XCTAssertFalse(rb.Dequeue().has_value());

  // Add an item to the ring
  XCTAssertEqual(rb.Enqueue(1), std::nullopt);

  // The ring is now not empty, but still not full
  XCTAssertFalse(rb.Empty());
  XCTAssertFalse(rb.Full());

  // Remove the item and check the contents
  std::optional<int> res = rb.Dequeue();
  XCTAssertTrue(res.has_value());
  XCTAssertEqual(res.value(), 1);

  // The ring should be empty again and return no value
  XCTAssertTrue(rb.Empty());
  XCTAssertFalse(rb.Dequeue().has_value());

  // Ensure this works for non-rvalues
  int x = 2;
  XCTAssertEqual(rb.Enqueue(x), std::nullopt);
  res = rb.Dequeue();
  XCTAssertTrue(res.has_value());
  XCTAssertEqual(res.value(), x);

  // The ring should be empty again
  XCTAssertTrue(rb.Empty());

  // Fill up the ring
  XCTAssertEqual(rb.Enqueue(3), std::nullopt);
  XCTAssertEqual(rb.Enqueue(4), std::nullopt);
  XCTAssertEqual(rb.Enqueue(5), std::nullopt);

  XCTAssertTrue(rb.Full());

  // Add another item to overwrite the oldest item in the queue
  res = rb.Enqueue(6);
  XCTAssertTrue(res.has_value());
  XCTAssertEqual(res.value(), 3);
  XCTAssertTrue(rb.Full());

  // Drain the queue and ensure proper values
  XCTAssertEqual(rb.Dequeue().value(), 4);
  XCTAssertFalse(rb.Full());
  XCTAssertEqual(rb.Dequeue().value(), 5);
  XCTAssertEqual(rb.Dequeue().value(), 6);

  // Make sure nothing left in the ring again
  XCTAssertTrue(rb.Empty());
  XCTAssertFalse(rb.Dequeue().has_value());
}

- (void)testIDValues {
  RingBuffer<id> rb(2);

  XCTAssertEqual(rb.Capacity(), 2);
  XCTAssertTrue(rb.Empty());
  XCTAssertFalse(rb.Full());

  // Add an object and check ring state
  XCTAssertEqual(rb.Enqueue(@"foo"), std::nullopt);
  XCTAssertFalse(rb.Full());
  XCTAssertFalse(rb.Empty());

  // Remove the object, confirm the value, and check ring state
  XCTAssertEqualObjects(rb.Dequeue().value(), @"foo");

  XCTAssertEqual(rb.Enqueue(@"throwaway"), std::nullopt);

  // Add an object within a new scope to ensure the ring properly holds onto the object
  @autoreleasepool {
    NSString *pidStr = [NSString stringWithFormat:@"pid: %d", getpid()];
    XCTAssertEqual(rb.Enqueue([pidStr copy]), std::nullopt);
    pidStr = nil;
  }

  XCTAssertTrue(rb.Full());
  XCTAssertFalse(rb.Empty());

  NSString *str = @"bar";
  NSString *res = rb.Enqueue(str).value_or(nil);
  XCTAssertEqualObjects(res, @"throwaway");

  // Drain the ring and check values
  res = rb.Dequeue().value_or(@"BAD");
  XCTAssertEqualObjects(res, ([NSString stringWithFormat:@"pid: %d", getpid()]));

  res = rb.Dequeue().value_or(@"BAD");
  XCTAssertEqualObjects(res, @"bar");

  XCTAssertFalse(rb.Full());
  XCTAssertTrue(rb.Empty());
}

- (void)testIterator {
  RingBuffer<int> rb(4);
  XCTAssertEqual(rb.Capacity(), 4);
  XCTAssertTrue(rb.Empty());
  XCTAssertFalse(rb.Full());

  rb.Enqueue(1);
  rb.Enqueue(2);
  rb.Enqueue(3);
  rb.Enqueue(4);
  rb.Enqueue(5);
  int expected = 2;
  for (const auto &val : rb) {
    XCTAssertEqual(val, expected);
    expected++;
  }
}

- (void)testErase {
  struct Foo {
    int x;
    int y;
  };

  RingBuffer<Foo> rb(4);

  XCTAssertEqual(rb.Capacity(), 4);
  XCTAssertTrue(rb.Empty());
  XCTAssertFalse(rb.Full());

  // Add two items and delete the first one.
  rb.Enqueue({1, 100});
  rb.Enqueue({2, 200});
  XCTAssertFalse(rb.Empty());

  // Delete the beginning and verify the second item still exists
  rb.Erase(rb.begin());
  Foo res = rb.Dequeue().value_or(Foo{0, 0});
  XCTAssertEqual(res.x, 2);
  XCTAssertEqual(res.y, 200);
  XCTAssertTrue(rb.Empty());

  // Add two more items
  rb.Enqueue({3, 300});
  rb.Enqueue({4, 400});
  XCTAssertFalse(rb.Empty());

  // Delete the end and verify the first one still exists
  rb.Erase(--rb.end());
  res = rb.Dequeue().value_or(Foo{0, 0});
  XCTAssertEqual(res.x, 3);
  XCTAssertEqual(res.y, 300);
  XCTAssertTrue(rb.Empty());

  // Add a few items and selectively delete, the ensure remaining values match expectations
  rb.Enqueue({500, 5});
  rb.Enqueue({6, 600});
  rb.Enqueue({700, 7});
  rb.Enqueue({8, 800});

  rb.Erase(std::remove_if(rb.begin(), rb.end(), [](const Foo &f) { return f.x < f.y; }), rb.end());

  res = rb.Dequeue().value_or(Foo{0, 0});
  XCTAssertEqual(res.x, 500);
  XCTAssertEqual(res.y, 5);
  res = rb.Dequeue().value_or(Foo{0, 0});
  XCTAssertEqual(res.x, 700);
  XCTAssertEqual(res.y, 7);
  XCTAssertTrue(rb.Empty());
}

@end
