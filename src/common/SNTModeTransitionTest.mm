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

#import "src/common/SNTModeTransition.h"

#include <limits>

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

@interface SNTModeTransition (Testing)
@property(readwrite) NSNumber *maxMinutes;
@property(readwrite) NSNumber *defaultDurationMinutes;
@end

@interface SNTModeTransitionTest : XCTestCase
@end

@implementation SNTModeTransitionTest

- (void)testInitializationType {
  // Ensure the initializers set the correct type
  SNTModeTransition *mt = [[SNTModeTransition alloc] initRevocation];
  XCTAssertEqual(mt.type, SNTModeTransitionTypeRevoke);

  mt = [[SNTModeTransition alloc] initOnDemandMinutes:10];
  XCTAssertEqual(mt.type, SNTModeTransitionTypeOnDemand);

  mt = [[SNTModeTransition alloc] initOnDemandMinutes:10 defaultDuration:1];
  XCTAssertEqual(mt.type, SNTModeTransitionTypeOnDemand);
}

- (void)testInitializationClamp {
  // Initializing with a max of 0 is invalid
  SNTModeTransition *mt = [[SNTModeTransition alloc] initOnDemandMinutes:0];
  XCTAssertNil(mt);

  // Default minutes should be clamped to max minutes
  mt = [[SNTModeTransition alloc] initOnDemandMinutes:10];
  XCTAssertEqualObjects(mt.maxMinutes, @(10));
  XCTAssertEqualObjects(mt.maxMinutes, mt.defaultDurationMinutes);

  // Max minutes should be clamped by a max. Default should match max minutes if not specified
  mt = [[SNTModeTransition alloc] initOnDemandMinutes:std::numeric_limits<uint32_t>::max()];
  XCTAssertLessThan([mt.maxMinutes unsignedIntValue], std::numeric_limits<uint32_t>::max());
  XCTAssertEqualObjects(mt.maxMinutes, mt.defaultDurationMinutes);

  // Default minutes of 0 is invalid, clamped to max minutes
  mt = [[SNTModeTransition alloc] initOnDemandMinutes:10 defaultDuration:0];
  XCTAssertEqualObjects(mt.maxMinutes, @(10));
  XCTAssertEqualObjects(mt.maxMinutes, mt.defaultDurationMinutes);

  // Default minutes higher than max minutes is clamped to max minutes
  mt = [[SNTModeTransition alloc] initOnDemandMinutes:10 defaultDuration:123];
  XCTAssertEqualObjects(mt.maxMinutes, @(10));
  XCTAssertEqualObjects(mt.maxMinutes, mt.defaultDurationMinutes);
}

- (void)testGetDurationMinutes {
  SNTModeTransition *mt = [[SNTModeTransition alloc] initOnDemandMinutes:100 defaultDuration:10];

  // A nil request returns the default
  XCTAssertEqual([mt getDurationMinutes:nil], [mt.defaultDurationMinutes unsignedIntValue]);
  // A request of 0 minutes returns the default
  XCTAssertEqual([mt getDurationMinutes:@(0)], [mt.defaultDurationMinutes unsignedIntValue]);

  // Requesting less than the defualt is permitted
  XCTAssertEqual([mt getDurationMinutes:@(2)], 2);

  // Requesting more than the default is permitted
  XCTAssertEqual([mt getDurationMinutes:@(50)], 50);

  // Requesting more than the max is clamped
  XCTAssertEqual([mt getDurationMinutes:@(500)], [mt.maxMinutes unsignedIntValue]);
}

- (void)testEncodeDecodeSecureCoding {
  SNTModeTransition *mt = [[SNTModeTransition alloc] initRevocation];
  NSData *mtSerialized = [mt serialize];

  SNTModeTransition *mtDeserialized = [SNTModeTransition deserialize:mtSerialized];
  XCTAssertEqual(mtDeserialized.type, SNTModeTransitionTypeRevoke);
  XCTAssertEqual(mtDeserialized.type, mt.type);

  mt = [[SNTModeTransition alloc] initOnDemandMinutes:100 defaultDuration:10];
  mtSerialized = [mt serialize];

  mtDeserialized = [SNTModeTransition deserialize:mtSerialized];
  XCTAssertEqual(mtDeserialized.type, SNTModeTransitionTypeOnDemand);
  XCTAssertEqual(mtDeserialized.type, mt.type);
  XCTAssertEqualObjects(mtDeserialized.maxMinutes, @(100));
  XCTAssertEqualObjects(mtDeserialized.maxMinutes, mt.maxMinutes);
  XCTAssertEqualObjects(mtDeserialized.defaultDurationMinutes, @(10));
  XCTAssertEqualObjects(mtDeserialized.defaultDurationMinutes, mt.defaultDurationMinutes);

  // Ensure that values are clamped when deserialized as well
  mt = [[SNTModeTransition alloc] initOnDemandMinutes:100 defaultDuration:10];
  mt.maxMinutes = @(std::numeric_limits<uint32_t>::max() - 1);
  mt.defaultDurationMinutes = @(std::numeric_limits<uint32_t>::max());
  XCTAssertEqualObjects(mt.maxMinutes, @(std::numeric_limits<uint32_t>::max() - 1));
  XCTAssertEqualObjects(mt.defaultDurationMinutes, @(std::numeric_limits<uint32_t>::max()));

  mtSerialized = [mt serialize];

  // Ensure serialized values are properly clamped on deserialization
  mtDeserialized = [SNTModeTransition deserialize:mtSerialized];
  XCTAssertEqual(mtDeserialized.type, SNTModeTransitionTypeOnDemand);
  XCTAssertLessThan([mtDeserialized.maxMinutes unsignedIntValue], [mt.maxMinutes unsignedIntValue]);
  XCTAssertGreaterThan([mtDeserialized.maxMinutes unsignedIntValue], 0);
  XCTAssertEqualObjects(mtDeserialized.maxMinutes, mtDeserialized.defaultDurationMinutes);
}

@end
