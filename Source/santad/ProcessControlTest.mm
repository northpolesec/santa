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

#include "Source/santad/ProcessControl.h"

#import <XCTest/XCTest.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>

#include "Source/common/AuditUtilities.h"

using santa::ProcessControl;

@interface ProcessControlTest : XCTestCase
@property pid_t child;
@end

@implementation ProcessControlTest

- (void)setUp {
  char* argv[] = {(char*)"/bin/sleep", (char*)"30", nullptr};
  pid_t pid;
  XCTAssertEqual(posix_spawn(&pid, argv[0], nullptr, nullptr, argv, nullptr), 0);
  self.child = pid;
}

- (void)tearDown {
  kill(self.child, SIGKILL);
  waitpid(self.child, nullptr, 0);
}

- (audit_token_t)childToken {
  audit_token_t token;
  XCTAssertTrue(santa::AuditTokenForPid(self.child, &token));
  return token;
}

// The token of a process that had the child's pid before it, as when the pid
// was reused after the held process exited.
- (audit_token_t)staleChildToken {
  audit_token_t token = [self childToken];
  return santa::MakeStubAuditToken(self.child, santa::Pidversion(token) - 1);
}

- (BOOL)childAlive {
  return kill(self.child, 0) == 0;
}

- (void)testKillsTheProcessItWasGiven {
  santa::ProcessControlBlock control = santa::ProdSuspendResumeBlock();
  XCTAssertTrue(control([self childToken], ProcessControl::Kill));

  int status = 0;
  XCTAssertEqual(waitpid(self.child, &status, 0), self.child);
  XCTAssertTrue(WIFSIGNALED(status));
  XCTAssertEqual(WTERMSIG(status), SIGKILL);
}

- (void)testSignalsNothingWhenThePidNamesAnotherProcess {
  santa::ProcessControlBlock control = santa::ProdSuspendResumeBlock();
  XCTAssertFalse(control([self staleChildToken], ProcessControl::Kill));
  XCTAssertFalse(control([self staleChildToken], ProcessControl::Resume));
  XCTAssertTrue([self childAlive]);
}

@end
