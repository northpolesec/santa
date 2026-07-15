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

#include "Source/common/ScopedMachPort.h"

#import <XCTest/XCTest.h>
#include <mach/mach.h>

#include <utility>

using santa::ScopedMachPort;

namespace {

// Creates a port name owning a receive right plus one send-right user
// reference. The send-right count can then be observed to confirm that
// ScopedMachPort's retain/release adapters actually take effect.
mach_port_t MakePortWithSendRight() {
  mach_port_t port = MACH_PORT_NULL;
  if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port) != KERN_SUCCESS) {
    return MACH_PORT_NULL;
  }
  mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
  return port;
}

mach_port_urefs_t SendRefs(mach_port_t port) {
  mach_port_urefs_t refs = 0;
  mach_port_get_refs(mach_task_self(), port, MACH_PORT_RIGHT_SEND, &refs);
  return refs;
}

}  // namespace

@interface ScopedMachPortTest : XCTestCase
@end

@implementation ScopedMachPortTest

- (void)testDefaultConstruction {
  ScopedMachPort scoped;
  XCTAssertFalse(scoped);
  XCTAssertEqual(scoped.Unsafe(), (mach_port_t)MACH_PORT_NULL);
}

- (void)testReleaseOnScopeExit {
  mach_port_t port = MakePortWithSendRight();
  XCTAssertNotEqual(port, (mach_port_t)MACH_PORT_NULL);
  XCTAssertEqual(SendRefs(port), 1u);

  {
    ScopedMachPort scoped = ScopedMachPort::Assume(port);
    XCTAssertTrue(scoped);
    XCTAssertEqual(scoped.Unsafe(), port);
    XCTAssertEqual(SendRefs(port), 1u);
  }

  // The send right was released when the wrapper went out of scope. The name
  // survives because it still holds the receive right.
  XCTAssertEqual(SendRefs(port), 0u);

  mach_port_mod_refs(mach_task_self(), port, MACH_PORT_RIGHT_RECEIVE, -1);
}

- (void)testRetainIncrements {
  mach_port_t port = MakePortWithSendRight();
  XCTAssertEqual(SendRefs(port), 1u);

  {
    ScopedMachPort scoped = ScopedMachPort::Retain(port);
    XCTAssertEqual(SendRefs(port), 2u);
  }

  XCTAssertEqual(SendRefs(port), 1u);

  mach_port_deallocate(mach_task_self(), port);
  mach_port_mod_refs(mach_task_self(), port, MACH_PORT_RIGHT_RECEIVE, -1);
}

- (void)testMoveTransfersOwnership {
  mach_port_t port = MakePortWithSendRight();

  ScopedMachPort a = ScopedMachPort::Assume(port);
  ScopedMachPort b(std::move(a));
  XCTAssertFalse(a);
  XCTAssertTrue(b);
  XCTAssertEqual(b.Unsafe(), port);
  // The single send-right reference survived the move: no double release and
  // no spurious retain.
  XCTAssertEqual(SendRefs(port), 1u);

  b = ScopedMachPort();  // Release.
  XCTAssertEqual(SendRefs(port), 0u);
  mach_port_mod_refs(mach_task_self(), port, MACH_PORT_RIGHT_RECEIVE, -1);
}

- (void)testAssumeFrom {
  mach_port_t observed = MACH_PORT_NULL;
  {
    auto [kr, scoped] = ScopedMachPort::AssumeFrom([&observed](mach_port_t* out) {
      *out = MakePortWithSendRight();
      observed = *out;
      return KERN_SUCCESS;
    });

    XCTAssertEqual(kr, KERN_SUCCESS);
    XCTAssertTrue(scoped);
    XCTAssertEqual(scoped.Unsafe(), observed);
    XCTAssertEqual(SendRefs(observed), 1u);
  }

  XCTAssertEqual(SendRefs(observed), 0u);
  mach_port_mod_refs(mach_task_self(), observed, MACH_PORT_RIGHT_RECEIVE, -1);
}

@end
