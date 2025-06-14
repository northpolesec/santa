/// Copyright 2025 North Pole Security, Inc.
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

#include "Source/common/Defer.h"

#include <Foundation/Foundation.h>
#include <XCTest/XCTest.h>
#include <dispatch/dispatch.h>

#include "Source/common/TestUtils.h"

using santa::Defer;

@interface DeferTest : XCTestCase
@property dispatch_semaphore_t sema;
@end

@implementation DeferTest

- (void)setUp {
  self.sema = dispatch_semaphore_create(0);
}

- (void)testBasic {
  (void)Defer(^{
    dispatch_semaphore_signal(self.sema);
  });

  XCTAssertSemaTrue(self.sema, 0, "Defer was not destructed");

  {
    Defer d(^{
      dispatch_semaphore_signal(self.sema);
    });
  }

  XCTAssertSemaTrue(self.sema, 0, "Defer was not destructed");
}

- (void)testCancel {
  {
    Defer d(^{
      dispatch_semaphore_signal(self.sema);
    });

    d.Cancel();
  }

  XCTAssertSemaFalse(self.sema, "Defer was unexpectedly destructed");
}

- (void)testExecute {
  {
    Defer d(^{
      dispatch_semaphore_signal(self.sema);
    });

    d.Execute();
    XCTAssertSemaTrue(self.sema, 0, "Defer was not executed early");
  }

  XCTAssertSemaFalse(self.sema, "Defer was destructed more than once");
}

@end
