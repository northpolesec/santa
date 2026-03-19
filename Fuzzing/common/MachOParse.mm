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

#import <Foundation/Foundation.h>
#include <libproc.h>
#include <stddef.h>
#include <stdint.h>

#import "Source/common/SNTFileInfo.h"

int get_num_fds() {
  return proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, NULL, 0) / PROC_PIDLISTFD_SIZE;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static NSString *tmpPath =
      [NSTemporaryDirectory() stringByAppendingPathComponent:[[NSUUID UUID] UUIDString]];

  int num_fds_pre = get_num_fds();

  @autoreleasepool {
    NSData *input = [NSData dataWithBytesNoCopy:(void *)data length:size freeWhenDone:false];
    [input writeToFile:tmpPath atomically:false];

    NSError *error;
    SNTFileInfo *fi = [[SNTFileInfo alloc] initWithResolvedPath:tmpPath error:&error];
    if (!fi || error != nil) {
      NSLog(@"Error: %@", error);
      return -1;
    }

    // Mach-O Parsing
    [fi architectures];
    [fi isMissingPageZero];
    [fi infoPlist];
  }

  if (num_fds_pre != get_num_fds()) {
    abort();
  }

  return 0;
}
