/// Copyright 2026 North Pole Security, Inc.
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
#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#include "Source/santad/ProcessTree/annotations/sandbox_exec.h"
#include "Source/santad/ProcessTree/process.h"
#include "Source/santad/ProcessTree/process_tree.pb.h"
#include "Source/santad/ProcessTree/process_tree_test_helpers.h"

using namespace santa::santad::process_tree;
namespace ptpb = ::santa::pb::v1::process_tree;

static const struct Cred cred = {.uid = 0, .gid = 0};

static const CodeSigningInfo kSandboxExecCS = {
    .signing_id = "com.apple.sandbox-exec",
    .team_id = "",
    .cdhash = "",
    .is_platform_binary = true,
};

@interface SandboxExecArgvParserTest : XCTestCase
@end

@implementation SandboxExecArgvParserTest

- (void)testParseFileAbsolutePath {
  auto result =
      ParseSandboxExecArgv({"sandbox-exec", "-f", "/etc/sandbox/policy.sb", "/usr/bin/ls"});
  XCTAssertTrue(result.has_value());
  XCTAssertEqual(result->profile_path, "/etc/sandbox/policy.sb");
  XCTAssertEqual(result->status, SandboxPolicyStatus::kPending);
}

- (void)testParseFileRelativePath {
  auto result =
      ParseSandboxExecArgv({"sandbox-exec", "-f", "./block-tmp-reads.sb", "/usr/bin/claude"});
  XCTAssertTrue(result.has_value());
  XCTAssertEqual(result->profile_path, "./block-tmp-reads.sb");
  XCTAssertEqual(result->status, SandboxPolicyStatus::kPending);
}

- (void)testParseMalformedMissingFlag {
  auto result = ParseSandboxExecArgv({"sandbox-exec", "/usr/bin/ls"});
  XCTAssertFalse(result.has_value());
}

- (void)testParseMalformedMissingArg {
  auto result = ParseSandboxExecArgv({"sandbox-exec", "-f"});
  XCTAssertFalse(result.has_value());
}

- (void)testParseEmptyArgv {
  auto result = ParseSandboxExecArgv({});
  XCTAssertFalse(result.has_value());
}

- (void)testParseFileWithoutExtension {
  auto result = ParseSandboxExecArgv({"sandbox-exec", "-f", "/etc/sandbox/policy", "/usr/bin/ls"});
  XCTAssertTrue(result.has_value());
  XCTAssertEqual(result->profile_path, "/etc/sandbox/policy");
}

@end

@interface SandboxExecAnnotatorTest : XCTestCase
@property std::shared_ptr<ProcessTreeTestPeer> tree;
@property std::shared_ptr<const Process> initProc;
@end

@implementation SandboxExecAnnotatorTest

- (void)setUp {
  std::vector<std::unique_ptr<Annotator>> annotators;
  annotators.emplace_back(std::make_unique<SandboxExecAnnotator>());
  self.tree = std::make_shared<ProcessTreeTestPeer>(std::move(annotators));
  self.initProc = self.tree->InsertInit();
}

// Test: sandbox-exec followed by target binary confirms the annotation.
- (void)testPendingConfirmedOnNextExec {
  uint64_t event_id = 1;

  // PID 1.1: fork() -> PID 2.2
  const struct Pid fork_pid = {.pid = 2, .pidversion = 2};
  self.tree->HandleFork(event_id++, *self.initProc, fork_pid);

  // PID 2.2: exec("sandbox-exec -f /path/to/policy.sb /usr/bin/ls") -> PID 2.3
  const struct Pid sandbox_exec_pid = {.pid = 2, .pidversion = 3};
  const struct Program sandbox_exec_prog = {
      .executable = "/usr/bin/sandbox-exec",
      .arguments = {"sandbox-exec", "-f", "/path/to/policy.sb", "/usr/bin/ls"},
      .code_signing = kSandboxExecCS,
  };
  auto forked = *self.tree->Get(fork_pid);
  self.tree->HandleExec(event_id++, *forked, sandbox_exec_pid, sandbox_exec_prog, cred);

  // Verify pending annotation on sandbox-exec process.
  auto sandbox_proc = *self.tree->Get(sandbox_exec_pid);
  auto pending_opt = self.tree->GetAnnotation<SandboxExecAnnotator>(*sandbox_proc);
  XCTAssertTrue(pending_opt.has_value());
  XCTAssertTrue((*pending_opt)->info().has_value());
  XCTAssertEqual((*pending_opt)->info()->status, SandboxPolicyStatus::kPending);
  XCTAssertEqual((*pending_opt)->info()->profile_path, "/path/to/policy.sb");

  // Proto should return nullopt for pending annotations.
  XCTAssertFalse((*pending_opt)->Proto().has_value());

  // PID 2.3: exec("/usr/bin/ls") -> PID 2.4 (sandbox-exec replaces itself)
  const struct Pid target_pid = {.pid = 2, .pidversion = 4};
  const struct Program target_prog = {
      .executable = "/usr/bin/ls",
      .arguments = {"/usr/bin/ls"},
  };
  self.tree->HandleExec(event_id++, *sandbox_proc, target_pid, target_prog, cred);

  // Verify confirmed annotation on target process.
  auto target_proc = *self.tree->Get(target_pid);
  auto confirmed_opt = self.tree->GetAnnotation<SandboxExecAnnotator>(*target_proc);
  XCTAssertTrue(confirmed_opt.has_value());
  XCTAssertTrue((*confirmed_opt)->info().has_value());
  XCTAssertEqual((*confirmed_opt)->info()->status, SandboxPolicyStatus::kConfirmed);
  XCTAssertEqual((*confirmed_opt)->info()->profile_path, "/path/to/policy.sb");

  // Proto should return annotations for confirmed status.
  auto proto_opt = (*confirmed_opt)->Proto();
  XCTAssertTrue(proto_opt.has_value());
  XCTAssertTrue(proto_opt->has_sandbox_policy());
  XCTAssertEqual(proto_opt->sandbox_policy().profile_path(), "/path/to/policy.sb");
}

// Test: confirmed annotation propagates to forked children.
- (void)testAnnotationPropagatesForkToChildren {
  uint64_t event_id = 1;

  // Set up sandbox-exec -> target.
  const struct Pid fork_pid = {.pid = 2, .pidversion = 2};
  self.tree->HandleFork(event_id++, *self.initProc, fork_pid);

  const struct Pid sandbox_exec_pid = {.pid = 2, .pidversion = 3};
  const struct Program sandbox_exec_prog = {
      .executable = "/usr/bin/sandbox-exec",
      .arguments = {"sandbox-exec", "-f", "/policy.sb", "/usr/bin/ls"},
      .code_signing = kSandboxExecCS,
  };
  auto forked = *self.tree->Get(fork_pid);
  self.tree->HandleExec(event_id++, *forked, sandbox_exec_pid, sandbox_exec_prog, cred);

  const struct Pid target_pid = {.pid = 2, .pidversion = 4};
  const struct Program target_prog = {
      .executable = "/usr/bin/ls",
      .arguments = {"/usr/bin/ls"},
  };
  auto sandbox_proc = *self.tree->Get(sandbox_exec_pid);
  self.tree->HandleExec(event_id++, *sandbox_proc, target_pid, target_prog, cred);

  // Fork a child from the sandboxed target.
  auto target_proc = *self.tree->Get(target_pid);
  const struct Pid child_pid = {.pid = 3, .pidversion = 3};
  self.tree->HandleFork(event_id++, *target_proc, child_pid);

  // Child should inherit the confirmed annotation.
  auto child_proc = *self.tree->Get(child_pid);
  auto child_opt = self.tree->GetAnnotation<SandboxExecAnnotator>(*child_proc);
  XCTAssertTrue(child_opt.has_value());
  XCTAssertTrue((*child_opt)->info().has_value());
  XCTAssertEqual((*child_opt)->info()->status, SandboxPolicyStatus::kConfirmed);
}

// Test: confirmed annotation propagates through exec in children.
- (void)testAnnotationPropagatesExecToChildren {
  uint64_t event_id = 1;

  // Set up sandbox-exec -> target.
  const struct Pid fork_pid = {.pid = 2, .pidversion = 2};
  self.tree->HandleFork(event_id++, *self.initProc, fork_pid);

  const struct Pid sandbox_exec_pid = {.pid = 2, .pidversion = 3};
  const struct Program sandbox_exec_prog = {
      .executable = "/usr/bin/sandbox-exec",
      .arguments = {"sandbox-exec", "-f", "/policy.sb", "/usr/bin/sh"},
      .code_signing = kSandboxExecCS,
  };
  auto forked = *self.tree->Get(fork_pid);
  self.tree->HandleExec(event_id++, *forked, sandbox_exec_pid, sandbox_exec_prog, cred);

  const struct Pid target_pid = {.pid = 2, .pidversion = 4};
  const struct Program target_prog = {
      .executable = "/bin/sh",
      .arguments = {"/bin/sh"},
  };
  auto sandbox_proc = *self.tree->Get(sandbox_exec_pid);
  self.tree->HandleExec(event_id++, *sandbox_proc, target_pid, target_prog, cred);

  // Target forks a child, child execs another binary.
  auto target_proc = *self.tree->Get(target_pid);
  const struct Pid child_fork_pid = {.pid = 3, .pidversion = 3};
  self.tree->HandleFork(event_id++, *target_proc, child_fork_pid);

  const struct Pid child_exec_pid = {.pid = 3, .pidversion = 4};
  const struct Program child_prog = {
      .executable = "/usr/bin/grep",
      .arguments = {"/usr/bin/grep", "foo"},
  };
  auto child_fork = *self.tree->Get(child_fork_pid);
  self.tree->HandleExec(event_id++, *child_fork, child_exec_pid, child_prog, cred);

  // The exec'd child should still have the annotation.
  auto child_exec = *self.tree->Get(child_exec_pid);
  auto child_opt = self.tree->GetAnnotation<SandboxExecAnnotator>(*child_exec);
  XCTAssertTrue(child_opt.has_value());
  XCTAssertEqual((*child_opt)->info()->status, SandboxPolicyStatus::kConfirmed);
}

// Test: pending annotation does NOT propagate to forked children.
- (void)testPendingDoesNotPropagateToFork {
  uint64_t event_id = 1;

  const struct Pid fork_pid = {.pid = 2, .pidversion = 2};
  self.tree->HandleFork(event_id++, *self.initProc, fork_pid);

  const struct Pid sandbox_exec_pid = {.pid = 2, .pidversion = 3};
  const struct Program sandbox_exec_prog = {
      .executable = "/usr/bin/sandbox-exec",
      .arguments = {"sandbox-exec", "-f", "/policy.sb", "/usr/bin/ls"},
      .code_signing = kSandboxExecCS,
  };
  auto forked = *self.tree->Get(fork_pid);
  self.tree->HandleExec(event_id++, *forked, sandbox_exec_pid, sandbox_exec_prog, cred);

  // Fork from the sandbox-exec process (before it execs the target).
  // This is unusual but should be handled.
  auto sandbox_proc = *self.tree->Get(sandbox_exec_pid);
  const struct Pid child_pid = {.pid = 3, .pidversion = 3};
  self.tree->HandleFork(event_id++, *sandbox_proc, child_pid);

  // Child should NOT have the pending annotation.
  auto child_proc = *self.tree->Get(child_pid);
  auto child_opt = self.tree->GetAnnotation<SandboxExecAnnotator>(*child_proc);
  XCTAssertFalse(child_opt.has_value());
}

// Test: PID reuse does not misattribute annotations.
- (void)testPidReuseDoesNotMisattribute {
  uint64_t event_id = 1;

  // Create sandbox-exec on PID 2.
  const struct Pid fork_pid = {.pid = 2, .pidversion = 2};
  self.tree->HandleFork(event_id++, *self.initProc, fork_pid);

  const struct Pid sandbox_exec_pid = {.pid = 2, .pidversion = 3};
  const struct Program sandbox_exec_prog = {
      .executable = "/usr/bin/sandbox-exec",
      .arguments = {"sandbox-exec", "-f", "/policy.sb", "/usr/bin/ls"},
      .code_signing = kSandboxExecCS,
  };
  auto forked = *self.tree->Get(fork_pid);
  self.tree->HandleExec(event_id++, *forked, sandbox_exec_pid, sandbox_exec_prog, cred);

  // sandbox-exec process exits.
  auto sandbox_proc = *self.tree->Get(sandbox_exec_pid);
  self.tree->HandleExit(event_id++, *sandbox_proc);

  // New process on PID 2 with different pidversion (PID reuse).
  const struct Pid new_fork_pid = {.pid = 2, .pidversion = 5};
  self.tree->HandleFork(event_id++, *self.initProc, new_fork_pid);

  const struct Pid new_exec_pid = {.pid = 2, .pidversion = 6};
  const struct Program new_prog = {
      .executable = "/usr/bin/cat",
      .arguments = {"/usr/bin/cat", "/dev/null"},
  };
  auto new_forked = *self.tree->Get(new_fork_pid);
  self.tree->HandleExec(event_id++, *new_forked, new_exec_pid, new_prog, cred);

  // The new process should NOT have a sandbox annotation.
  auto new_proc = *self.tree->Get(new_exec_pid);
  auto annotation = self.tree->GetAnnotation<SandboxExecAnnotator>(*new_proc);
  XCTAssertFalse(annotation.has_value());
}

// Test: nested sandbox-exec picks up the new profile, not the stale one.
- (void)testNestedSandboxExecUsesNewProfile {
  uint64_t event_id = 1;

  // fork -> sandbox-exec -f /outer.sb /usr/bin/sandbox-exec
  const struct Pid fork_pid = {.pid = 2, .pidversion = 2};
  self.tree->HandleFork(event_id++, *self.initProc, fork_pid);

  const struct Pid outer_sandbox_pid = {.pid = 2, .pidversion = 3};
  const struct Program outer_sandbox_prog = {
      .executable = "/usr/bin/sandbox-exec",
      .arguments = {"sandbox-exec", "-f", "/outer.sb", "/usr/bin/sandbox-exec"},
      .code_signing = kSandboxExecCS,
  };
  auto forked = *self.tree->Get(fork_pid);
  self.tree->HandleExec(event_id++, *forked, outer_sandbox_pid, outer_sandbox_prog, cred);

  // Confirm outer: exec target
  const struct Pid outer_target_pid = {.pid = 2, .pidversion = 4};
  const struct Program outer_target_prog = {
      .executable = "/usr/bin/sandbox-exec",
      .arguments = {"sandbox-exec", "-f", "/inner.sb", "/usr/bin/ls"},
      .code_signing = kSandboxExecCS,
  };
  auto outer_sandbox = *self.tree->Get(outer_sandbox_pid);
  self.tree->HandleExec(event_id++, *outer_sandbox, outer_target_pid, outer_target_prog, cred);

  // The annotation should be pending with the INNER profile, not the outer.
  auto proc = *self.tree->Get(outer_target_pid);
  auto opt = self.tree->GetAnnotation<SandboxExecAnnotator>(*proc);
  XCTAssertTrue(opt.has_value());
  XCTAssertTrue((*opt)->info().has_value());
  XCTAssertEqual((*opt)->info()->status, SandboxPolicyStatus::kPending);
  XCTAssertEqual((*opt)->info()->profile_path, "/inner.sb");

  // Now exec the final target — should confirm /inner.sb.
  const struct Pid inner_target_pid = {.pid = 2, .pidversion = 5};
  const struct Program inner_target_prog = {
      .executable = "/usr/bin/ls",
      .arguments = {"/usr/bin/ls"},
  };
  self.tree->HandleExec(event_id++, *proc, inner_target_pid, inner_target_prog, cred);

  auto final_proc = *self.tree->Get(inner_target_pid);
  auto final_opt = self.tree->GetAnnotation<SandboxExecAnnotator>(*final_proc);
  XCTAssertTrue(final_opt.has_value());
  XCTAssertEqual((*final_opt)->info()->status, SandboxPolicyStatus::kConfirmed);
  XCTAssertEqual((*final_opt)->info()->profile_path, "/inner.sb");
}

// Test: ExportAnnotations includes sandbox_policy.
- (void)testExportAnnotations {
  uint64_t event_id = 1;

  const struct Pid fork_pid = {.pid = 2, .pidversion = 2};
  self.tree->HandleFork(event_id++, *self.initProc, fork_pid);

  const struct Pid sandbox_exec_pid = {.pid = 2, .pidversion = 3};
  const struct Program sandbox_exec_prog = {
      .executable = "/usr/bin/sandbox-exec",
      .arguments = {"sandbox-exec", "-f", "/etc/sandbox/agent.sb", "/usr/bin/agent"},
      .code_signing = kSandboxExecCS,
  };
  auto forked = *self.tree->Get(fork_pid);
  self.tree->HandleExec(event_id++, *forked, sandbox_exec_pid, sandbox_exec_prog, cred);

  const struct Pid target_pid = {.pid = 2, .pidversion = 4};
  const struct Program target_prog = {
      .executable = "/usr/bin/agent",
      .arguments = {"/usr/bin/agent"},
  };
  auto sandbox_proc = *self.tree->Get(sandbox_exec_pid);
  self.tree->HandleExec(event_id++, *sandbox_proc, target_pid, target_prog, cred);

  // ExportAnnotations should include the sandbox_policy.
  auto exported = self.tree->ExportAnnotations(target_pid);
  XCTAssertTrue(exported.has_value());
  XCTAssertTrue(exported->has_sandbox_policy());
  XCTAssertEqual(exported->sandbox_policy().profile_path(), "/etc/sandbox/agent.sb");
}

@end
