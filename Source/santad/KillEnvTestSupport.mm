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

#include "Source/santad/KillEnvTestSupport.h"

#include "Source/common/SystemResources.h"

namespace santa::testing {

NSArray<NSString*>* SignalDescriptions(const std::vector<FakeSignal>& signals) {
  NSMutableArray<NSString*>* out = [NSMutableArray array];
  for (const FakeSignal& signal : signals) {
    [out addObject:[NSString stringWithFormat:@"%@:%d:%d", signal.group ? @"group" : @"pid",
                                              signal.target, signal.sig]];
  }
  return out;
}

}  // namespace santa::testing

@implementation FakeHost
- (uint64_t)mach {
  return AddNanosecondsToMachTime((uint64_t)(self.machOffsetSeconds * NSEC_PER_SEC),
                                  mach_continuous_time());
}
@end
