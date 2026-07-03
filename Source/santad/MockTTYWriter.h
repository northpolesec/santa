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

#ifndef SANTA_SANTAD_MOCKTTYWRITER_H
#define SANTA_SANTAD_MOCKTTYWRITER_H

#import <Foundation/Foundation.h>
#include <gmock/gmock.h>

#include "Source/santad/TTYWriter.h"

namespace santa {

class MockTTYWriter : public TTYWriter {
 public:
  // The mock never dispatches (WriteWithoutSignal is stubbed), so the queue + silent flag
  // passed to the real base ctor are inert but valid.
  MockTTYWriter()
      : TTYWriter(
            dispatch_queue_create("com.northpolesec.santa.mockttywriter", DISPATCH_QUEUE_SERIAL),
            /*silent_tty_mode=*/false) {}

  MOCK_METHOD(void, WriteWithoutSignal, (NSString * ttyPath, NSString* msg), (override));
};

}  // namespace santa

#endif  // SANTA_SANTAD_MOCKTTYWRITER_H
