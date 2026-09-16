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

#import <XCTest/XCTest.h>
#include <sys/stat.h>

#include <optional>

#include "Source/common/SystemResources.h"

@interface SystemResourcesTest : XCTestCase
@end

@implementation SystemResourcesTest

- (void)tearDown {
  // The overrides below are declared behind #ifdef DEBUG so they cannot ship, and
  // DEBUG follows bazel's compilation mode: set under fastbuild, unset under
  // -c opt. Tests needing them skip rather than compile away, so a non-debug
  // build reports the gap instead of silently running a smaller suite. The two
  // tests that only read GetBootVolumeGroupDev() run in either configuration.
#ifdef DEBUG
  SetBootVolumeGroupDevForTesting(std::nullopt);
  SetBootVolumeGroupDevUnavailableForTesting(false);
#endif
  [super tearDown];
}

- (void)testBootVolumeGroupDevMatchesRootDirectory {
  struct stat rootStat;
  XCTAssertEqual(stat("/", &rootStat), 0);

  std::optional<dev_t> dev = GetBootVolumeGroupDev();
  XCTAssertTrue(dev.has_value());
  XCTAssertEqual(*dev, rootStat.st_dev);
}

- (void)testBootVolumeGroupDevCoversTheDataVolume {
  // The system and data volumes of a volume group are presented as one device,
  // so a path on the writable volume reports the same st_dev as "/".
  struct stat tmpStat;
  XCTAssertEqual(stat("/private/var/tmp", &tmpStat), 0);

  std::optional<dev_t> dev = GetBootVolumeGroupDev();
  XCTAssertTrue(dev.has_value());
  XCTAssertEqual(*dev, tmpStat.st_dev);
}

- (void)testTestingOverrideIsHonored {
#ifndef DEBUG
  XCTSkip(@"the boot volume group overrides are DEBUG-only and are not built with -c opt");
#else
  SetBootVolumeGroupDevForTesting(std::make_optional<dev_t>(424242));
  XCTAssertEqual(*GetBootVolumeGroupDev(), (dev_t)424242);

  SetBootVolumeGroupDevForTesting(std::nullopt);
  struct stat rootStat;
  XCTAssertEqual(stat("/", &rootStat), 0);
  XCTAssertEqual(*GetBootVolumeGroupDev(), rootStat.st_dev);
#endif
}

- (void)testTestingUnavailableOverrideIsHonored {
#ifndef DEBUG
  XCTSkip(@"the boot volume group overrides are DEBUG-only and are not built with -c opt");
#else
  // Passing std::nullopt to SetBootVolumeGroupDevForTesting restores normal
  // resolution rather than forcing an empty result, so a separate seam is needed
  // to exercise callers' handling of an undetermined device.
  SetBootVolumeGroupDevUnavailableForTesting(true);
  XCTAssertFalse(GetBootVolumeGroupDev().has_value());

  SetBootVolumeGroupDevUnavailableForTesting(false);
  XCTAssertTrue(GetBootVolumeGroupDev().has_value());
#endif
}

- (void)testUnavailableOverrideTakesPrecedenceOverValueOverride {
#ifndef DEBUG
  XCTSkip(@"the boot volume group overrides are DEBUG-only and are not built with -c opt");
#else
  SetBootVolumeGroupDevForTesting(std::make_optional<dev_t>(424242));
  SetBootVolumeGroupDevUnavailableForTesting(true);
  XCTAssertFalse(GetBootVolumeGroupDev().has_value());
#endif
}

@end
