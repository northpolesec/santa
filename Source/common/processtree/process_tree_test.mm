/// Copyright 2023 Google LLC
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
#import <XCTest/XCTest.h>

#include <Kernel/kern/cs_blobs.h>
#include <bsm/libbsm.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "Source/common/processtree/annotations/annotator.h"
#include "Source/common/processtree/process.h"
#include "Source/common/processtree/process_tree_test_helpers.h"
#include "absl/functional/function_ref.h"
#include "absl/synchronization/mutex.h"

namespace ptpb = ::santa::pb::v1::process_tree;

namespace santa::santad::process_tree {

static constexpr std::string_view kAnnotatedExecutable = "/usr/bin/login";

class TestAnnotator : public Annotator {
 public:
  TestAnnotator() {}
  void AnnotateFork(ProcessTree& tree, const Process& parent, const Process& child) override;
  void AnnotateExec(ProcessTree& tree, const Process& orig_process,
                    const Process& new_process) override;
  std::optional<::ptpb::Annotations> Proto() const override;
};

void TestAnnotator::AnnotateFork(ProcessTree& tree, const Process& parent, const Process& child) {
  // "Base case". Propagate existing annotations down to descendants.
  if (auto annotation = tree.GetAnnotation<TestAnnotator>(parent)) {
    tree.AnnotateProcess(child, std::move(*annotation));
  }
}

void TestAnnotator::AnnotateExec(ProcessTree& tree, const Process& orig_process,
                                 const Process& new_process) {
  if (auto annotation = tree.GetAnnotation<TestAnnotator>(orig_process)) {
    tree.AnnotateProcess(new_process, std::move(*annotation));
    return;
  }

  if (new_process.program_->executable == kAnnotatedExecutable) {
    tree.AnnotateProcess(new_process, std::make_shared<TestAnnotator>());
  }
}

std::optional<::ptpb::Annotations> TestAnnotator::Proto() const {
  return std::nullopt;
}

// An annotator that contributes names to the tree's annotation index and
// propagates to every descendant. Lets the index be exercised without pulling
// the CEL annotator (and its dependencies) into this test.
class IndexedTestAnnotator : public Annotator {
 public:
  explicit IndexedTestAnnotator(std::vector<std::string> names) : names_(std::move(names)) {}

  void AnnotateFork(ProcessTree&, const Process&, const Process&) override {}
  void AnnotateExec(ProcessTree&, const Process&, const Process&) override {}

  // Inheritance is driven by the tree under its write lock, as the CEL
  // annotator's is. A fresh object per descendant (rather than
  // PropagatesWholly sharing) keeps each carrier independently countable.
  std::shared_ptr<const Annotator> Propagate(bool) const override {
    return std::make_shared<const IndexedTestAnnotator>(names_);
  }

  void ForEachIndexedName(absl::FunctionRef<void(std::string_view)> f) const override {
    for (const std::string& name : names_) {
      f(name);
    }
  }

  std::optional<::ptpb::Annotations> Proto() const override { return std::nullopt; }

 private:
  std::vector<std::string> names_;
};

// Counts AnnotateExec invocations through a shared counter. Annotators run only
// after a novel StepLocked, so the count reflects how many times an exec was
// actually applied (as opposed to deduped).
class ExecCountingAnnotator : public Annotator {
 public:
  explicit ExecCountingAnnotator(std::shared_ptr<int> exec_count)
      : exec_count_(std::move(exec_count)) {}
  void AnnotateFork(ProcessTree&, const Process&, const Process&) override {}
  void AnnotateExec(ProcessTree&, const Process&, const Process&) override { ++(*exec_count_); }
  std::optional<::ptpb::Annotations> Proto() const override { return std::nullopt; }

 private:
  std::shared_ptr<int> exec_count_;
};
}  // namespace santa::santad::process_tree

using namespace santa::santad::process_tree;

@interface ProcessTreeTest : XCTestCase
@property std::shared_ptr<ProcessTreeTestPeer> tree;
@property std::shared_ptr<const Process> initProc;
@end

@implementation ProcessTreeTest

- (void)setUp {
  std::vector<std::unique_ptr<Annotator>> annotators{};
  self.tree = std::make_shared<ProcessTreeTestPeer>(std::move(annotators));
  self.initProc = self.tree->InsertInit();
}

- (void)testSimpleOps {
  uint64_t event_id = 1;
  // PID 1.1: fork() -> PID 2.2
  const struct Pid child_pid = {.pid = 2, .pidversion = 2};
  self.tree->HandleFork(event_id++, self.initProc, child_pid);

  auto child_opt = self.tree->Get(child_pid);
  XCTAssertTrue(child_opt.has_value());
  std::shared_ptr<const Process> child = *child_opt;
  XCTAssertEqual(child->pid_, child_pid);
  XCTAssertEqual(child->program_, self.initProc->program_);
  XCTAssertEqual(child->effective_cred_, self.initProc->effective_cred_);
  XCTAssertEqual(self.tree->GetParent(*child), self.initProc);

  // PID 2.2: exec("/bin/bash") -> PID 2.3
  const struct Pid child_exec_pid = {.pid = 2, .pidversion = 3};
  const struct Program child_exec_prog = {.executable = "/bin/bash",
                                          .arguments = {"/bin/bash", "-i"}};
  self.tree->HandleExec(event_id++, *child, child_exec_pid, child_exec_prog,
                        child->effective_cred_);

  child_opt = self.tree->Get(child_exec_pid);
  XCTAssertTrue(child_opt.has_value());
  child = *child_opt;
  XCTAssertEqual(child->pid_, child_exec_pid);
  XCTAssertEqual(*child->program_, child_exec_prog);
  XCTAssertEqual(child->effective_cred_, self.initProc->effective_cred_);
}

// A given exec is delivered to every tree-aware client, so HandleExec sees the
// same exec (identical EventKey) more than once. A duplicate delivery must be
// deduped: the exec is applied — and thus annotated — exactly once, with the
// program unchanged. StepLocked is the authoritative dedup gate. (Callers skip
// the build for known duplicates up front via GetExecActor; see the adapter.)
- (void)testDuplicateExecDeliveryIsIdempotent {
  auto exec_count = std::make_shared<int>(0);
  std::vector<std::unique_ptr<Annotator>> annotators{};
  annotators.emplace_back(std::make_unique<ExecCountingAnnotator>(exec_count));
  auto tree = std::make_shared<ProcessTreeTestPeer>(std::move(annotators));
  auto init = tree->InsertInit();

  uint64_t event_id = 1;
  const struct Pid child_pid = {.pid = 2, .pidversion = 2};
  tree->HandleFork(event_id++, init, child_pid);
  auto child = *tree->Get(child_pid);

  const struct Pid exec_pid = {.pid = 2, .pidversion = 3};
  const struct Program prog = {.executable = "/bin/bash", .arguments = {"/bin/bash", "-i"}};
  const uint64_t exec_ts = event_id++;

  // Deliver the same exec (identical EventKey) twice.
  tree->HandleExec(exec_ts, *child, exec_pid, prog, child->effective_cred_);
  tree->HandleExec(exec_ts, *child, exec_pid, prog, child->effective_cred_);

  // The duplicate is deduped: the exec passes through StepLocked and is applied
  // (and annotated) exactly once, not merely coalesced by the first-wins insert.
  XCTAssertEqual(*exec_count, 1);

  auto post = tree->Get(exec_pid);
  XCTAssertTrue(post.has_value());
  XCTAssertEqual(*(*post)->program_, prog);  // program intact, not corrupted
  // Applied once and reachable to init.
  auto slice = tree->RootSlice(*post);
  XCTAssertEqual(slice.size(), 2u);  // [exec, init]
  XCTAssertEqual(slice.back(), init);
}

// GetExecActor lets the ES adapter learn, under one reader lock, whether an exec
// was already recorded and (if not) fetch the execing process. already_seen must
// flip for exactly the identity HandleExec dedups on; proc resolves the actor on
// the not-seen path and is suppressed once the exec is seen.
- (void)testGetExecActor {
  uint64_t event_id = 1;
  const struct Pid child_pid = {.pid = 2, .pidversion = 2};
  self.tree->HandleFork(event_id++, self.initProc, child_pid);
  auto child = *self.tree->Get(child_pid);

  const struct Pid exec_pid = {.pid = 2, .pidversion = 3};
  const struct Program prog = {.executable = "/bin/bash", .arguments = {}};
  const uint64_t exec_ts = 100;

  // Before the exec: not seen, and the actor (child) resolves.
  auto before = self.tree->GetExecActor(exec_ts, child_pid, exec_pid);
  XCTAssertFalse(before.already_seen);
  XCTAssertTrue(before.proc.has_value());
  XCTAssertEqual(*before.proc, child);

  self.tree->HandleExec(exec_ts, *child, exec_pid, prog, child->effective_cred_);

  // After: the exact identity is seen, and proc is suppressed on the seen path.
  auto after = self.tree->GetExecActor(exec_ts, child_pid, exec_pid);
  XCTAssertTrue(after.already_seen);
  XCTAssertFalse(after.proc.has_value());

  // A different timestamp or target is a distinct, still-unseen event.
  XCTAssertFalse(self.tree->GetExecActor(exec_ts + 1, child_pid, exec_pid).already_seen);
  XCTAssertFalse(self.tree->GetExecActor(exec_ts, child_pid, child_pid).already_seen);
}

// We can't test the full backfill process, as retrieving information on
// processes (with task_name_for_pid) requires privileges.
// Test what we can by LoadPID'ing ourselves.
- (void)testLoadPID {
  auto proc = LoadPID(getpid()).value();

  audit_token_t self_tok;
  mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
  XCTAssertEqual(task_info(mach_task_self(), TASK_AUDIT_TOKEN, (task_info_t)&self_tok, &count),
                 KERN_SUCCESS);

  XCTAssertEqual(proc.pid.pid, audit_token_to_pid(self_tok));
  XCTAssertEqual(proc.pid.pidversion, audit_token_to_pidversion(self_tok));

  XCTAssertEqual(proc.cred.uid, geteuid());
  XCTAssertEqual(proc.cred.gid, getegid());

  auto program = proc.program;
  [[[NSProcessInfo processInfo] arguments]
      enumerateObjectsUsingBlock:^(NSString* _Nonnull obj, NSUInteger idx, BOOL* _Nonnull stop) {
        XCTAssertEqualObjects(@(program->arguments[idx].c_str()), obj);
        if (idx == 0) {
          XCTAssertEqualObjects(@(program->executable.c_str()), obj);
        }
      }];

  // The backfill path stores cdhash as raw bytes, not a hex string. The test
  // binary is code signed, so its cdhash is present and exactly CS_CDHASH_LEN.
  if (program->code_signing.has_value() && !program->code_signing->cdhash.empty()) {
    XCTAssertEqual(program->code_signing->cdhash.size(), (size_t)CS_CDHASH_LEN);
  }
}

- (void)testAnnotation {
  std::vector<std::unique_ptr<Annotator>> annotators{};
  annotators.emplace_back(std::make_unique<TestAnnotator>());
  self.tree = std::make_shared<ProcessTreeTestPeer>(std::move(annotators));
  self.initProc = self.tree->InsertInit();

  uint64_t event_id = 1;
  const struct Cred cred = {.uid = 0, .gid = 0};

  // PID 1.1: fork() -> PID 2.2
  const struct Pid login_pid = {.pid = 2, .pidversion = 2};
  self.tree->HandleFork(event_id++, self.initProc, login_pid);

  // PID 2.2: exec("/usr/bin/login") -> PID 2.3
  const struct Pid login_exec_pid = {.pid = 2, .pidversion = 3};
  const struct Program login_prog = {.executable = std::string(kAnnotatedExecutable),
                                     .arguments = {}};
  auto login = *self.tree->Get(login_pid);
  self.tree->HandleExec(event_id++, *login, login_exec_pid, login_prog, cred);

  // Ensure we have an annotation on login itself...
  login = *self.tree->Get(login_exec_pid);
  auto annotation = self.tree->GetAnnotation<TestAnnotator>(*login);
  XCTAssertTrue(annotation.has_value());

  // PID 2.3: fork() -> PID 3.3
  const struct Pid shell_pid = {.pid = 3, .pidversion = 3};
  self.tree->HandleFork(event_id++, login, shell_pid);
  // PID 3.3: exec("/bin/zsh") -> PID 3.4
  const struct Pid shell_exec_pid = {.pid = 3, .pidversion = 4};
  const struct Program shell_prog = {.executable = "/bin/zsh", .arguments = {}};
  auto shell = *self.tree->Get(shell_pid);
  self.tree->HandleExec(event_id++, *shell, shell_exec_pid, shell_prog, cred);

  // ... and also ensure we have an annotation on the descendant zsh.
  shell = *self.tree->Get(shell_exec_pid);
  annotation = self.tree->GetAnnotation<TestAnnotator>(*shell);
  XCTAssertTrue(annotation.has_value());
}

- (void)testUpdateAnnotation {
  auto proc = self.initProc;
  auto first = std::make_shared<TestAnnotator>();
  auto second = std::make_shared<TestAnnotator>();

  self.tree->AnnotateProcess(*proc, first);
  XCTAssertEqual(*self.tree->GetAnnotation<TestAnnotator>(*proc), first);

  // AnnotateProcess is first-wins...
  self.tree->AnnotateProcess(*proc, second);
  XCTAssertEqual(*self.tree->GetAnnotation<TestAnnotator>(*proc), first);

  // ...while UpdateAnnotation sees the current value and replaces it.
  const TestAnnotator* seen = nullptr;
  self.tree->UpdateAnnotation<TestAnnotator>(
      proc->pid_, [&](const TestAnnotator* current) -> std::shared_ptr<const TestAnnotator> {
        seen = current;
        return second;
      });
  XCTAssertEqual(seen, first.get());
  XCTAssertEqual(*self.tree->GetAnnotation<TestAnnotator>(*proc), second);

  // Returning nullptr leaves the existing annotation in place.
  self.tree->UpdateAnnotation<TestAnnotator>(
      proc->pid_,
      [](const TestAnnotator*) -> std::shared_ptr<const TestAnnotator> { return nullptr; });
  XCTAssertEqual(*self.tree->GetAnnotation<TestAnnotator>(*proc), second);

  // The by-pid lookup resolves the process and reads its annotation in one
  // acquisition; it must agree with the by-handle overload.
  XCTAssertEqual(*self.tree->GetAnnotation<TestAnnotator>(proc->pid_), second);
  XCTAssertFalse(
      self.tree->GetAnnotation<TestAnnotator>((struct Pid){.pid = 999, .pidversion = 999})
          .has_value());
}

- (void)testCreateTreeRejectsDuplicateAnnotatorClasses {
  std::vector<std::unique_ptr<Annotator>> annotators;
  annotators.emplace_back(std::make_unique<TestAnnotator>());
  annotators.emplace_back(std::make_unique<TestAnnotator>());

  auto tree = CreateTree(std::move(annotators));
  XCTAssertFalse(tree.ok());
  XCTAssertEqual(tree.status().code(), absl::StatusCode::kInvalidArgument);
}

- (void)testCreateTreeAcceptsDistinctAnnotatorClasses {
  std::vector<std::unique_ptr<Annotator>> annotators;
  annotators.emplace_back(std::make_unique<TestAnnotator>());
  annotators.emplace_back(std::make_unique<ExecCountingAnnotator>(std::make_shared<int>(0)));

  // Regression: the duplicate check used to run typeid on the unique_ptr, which
  // is the same static type for every element, so any two annotators collided.
  auto tree = CreateTree(std::move(annotators));
  if (!tree.ok()) {
    // Backfill can fail for reasons unrelated to the check; what must not
    // happen is being rejected as duplicates.
    XCTAssertNotEqual(tree.status().code(), absl::StatusCode::kInvalidArgument);
  }
}

// RetainProcess can only bump a pid that is in the tree, so a ProcessToken must
// remember what it retained rather than what it asked for. Otherwise a pid that
// was absent at retain time and inserted by another client before the token
// dies gets a decrement that pairs with no increment -- enough to erase a
// process a different, still-live token is holding.
- (void)testTokenDoesNotReleaseWhatItNeverRetained {
  // grace=1 so one later event is enough to drain.
  std::vector<std::unique_ptr<Annotator>> annotators{};
  auto tree = std::make_shared<ProcessTreeTestPeer>(std::move(annotators), 1);
  auto init = tree->InsertInit();
  const struct Pid p = {.pid = 2, .pidversion = 2};
  const struct Pid other = {.pid = 3, .pidversion = 3};

  // Token A asks for P before P exists.
  auto tokenA = std::make_unique<ProcessToken>(tree, PidList{p});

  // Another ingestion thread inserts P, and token B legitimately retains it.
  tree->HandleFork(10, init, p);
  XCTAssertTrue(tree->Get(p).has_value());
  auto tokenB = std::make_unique<ProcessToken>(tree, PidList{p});

  // P exits. B holds it, so it is tombstoned rather than erased.
  tree->HandleExit(11, **tree->Get(p));
  tree->HandleFork(100, init, other);  // advances latest_ts_ so DrainRemovals runs
  XCTAssertTrue(tree->Get(p).has_value());

  // A goes away. It never retained P, so this must not touch P's count.
  tokenA.reset();
  XCTAssertTrue(tree->Get(p).has_value(),
                @"token A released a process it never retained, erasing it under token B");

  // B is the only real holder, so its release is what reaps P.
  tokenB.reset();
  XCTAssertFalse(tree->Get(p).has_value());
}

- (void)testCleanup {
  // Removal is time-based: an exited process is retained until removal_grace_ticks
  // have elapsed past its exit (measured by the newest timestamp seen), so a
  // reordered straggler cannot reference it after it is reaped. Inject a small
  // grace so tiny synthetic timestamps exercise the reaping boundary.
  std::vector<std::unique_ptr<Annotator>> annotators{};
  auto tree = std::make_shared<ProcessTreeTestPeer>(std::move(annotators),
                                                    /*removal_grace_ticks=*/10);
  auto init = tree->InsertInit();

  uint64_t event_id = 1;
  const struct Pid child_pid = {.pid = 2, .pidversion = 2};
  tree->HandleFork(event_id++, init, child_pid);  // ts=1
  auto child = *tree->Get(child_pid);
  tree->HandleExit(event_id++, *child);  // ts=2: scheduled for removal

  // Still present immediately after exit (well within the grace).
  XCTAssertTrue(tree->Get(child_pid).has_value());

  // Step forward but stay within the grace (latest_ts - grace <= 2).
  struct Pid churn_pid = {.pid = 3, .pidversion = 3};
  for (int i = 0; i < 10; i++) {  // ts=3..12 -> latest=12, cutoff=2
    tree->HandleFork(event_id++, init, churn_pid);
    churn_pid.pid++;
  }
  XCTAssertTrue(tree->Get(child_pid).has_value());

  // Step past the grace (latest_ts - grace > 2): the exited child is reaped.
  for (int i = 0; i < 5; i++) {  // ts=13..17 -> cutoff reaches 7 > 2
    tree->HandleFork(event_id++, init, churn_pid);
    churn_pid.pid++;
  }
  XCTAssertFalse(tree->Get(child_pid).has_value());
}

- (void)testRefcountCleanup {
  std::vector<std::unique_ptr<Annotator>> annotators{};
  auto tree = std::make_shared<ProcessTreeTestPeer>(std::move(annotators),
                                                    /*removal_grace_ticks=*/10);
  auto init = tree->InsertInit();

  uint64_t event_id = 1;
  const struct Pid child_pid = {.pid = 2, .pidversion = 2};
  {
    tree->HandleFork(event_id++, init, child_pid);
    auto child = *tree->Get(child_pid);
    tree->HandleExit(event_id++, *child);
  }

  {
    auto child = tree->Get(child_pid);
    XCTAssertTrue(child.has_value());
    PidList pids = {(*child)->pid_};
    (void)tree->RetainProcess(pids);
  }

  // Even stepping well past the grace, the retained child stays reachable
  // (tombstoned, not erased).
  struct Pid churn_pid = {.pid = 100, .pidversion = 100};
  for (int i = 0; i < 100; i++) {
    tree->HandleFork(event_id++, init, churn_pid);
    churn_pid.pid++;
    churn_pid.pidversion++;
    auto child = tree->Get(child_pid);
    XCTAssertTrue(child.has_value());
  }

  // But when released (refcnt -> 0 while tombstoned)...
  {
    auto child = tree->Get(child_pid);
    XCTAssertTrue(child.has_value());
    PidList pids = {(*child)->pid_};
    tree->ReleaseProcess(pids);
  }

  // ... it is removed.
  {
    auto child = tree->Get(child_pid);
    XCTAssertFalse(child.has_value());
  }
}

// Regression: ReleaseProcess collects erase candidates under a reader lock,
// then re-verifies under the exclusive lock before erasing. If a retain lands
// in that window, the re-verify must see it and skip the erase.
- (void)testReleaseRaceRetainInWindowSkipsErase {
  std::vector<std::unique_ptr<Annotator>> annotators{};
  auto tree = std::make_shared<ProcessTreeTestPeer>(std::move(annotators),
                                                    /*removal_grace_ticks=*/10);
  auto init = tree->InsertInit();

  uint64_t event_id = 1;
  const struct Pid child_pid = {.pid = 2, .pidversion = 2};
  {
    tree->HandleFork(event_id++, init, child_pid);
    auto child = *tree->Get(child_pid);
    tree->HandleExit(event_id++, *child);
  }

  {
    auto child = tree->Get(child_pid);
    XCTAssertTrue(child.has_value());
    PidList pids = {(*child)->pid_};
    (void)tree->RetainProcess(pids);
  }

  struct Pid churn_pid = {.pid = 100, .pidversion = 100};
  for (int i = 0; i < 100; i++) {
    tree->HandleFork(event_id++, init, churn_pid);
    churn_pid.pid++;
    churn_pid.pidversion++;
    auto child = tree->Get(child_pid);
    XCTAssertTrue(child.has_value());
  }

  PidList pids = {child_pid};
  int fired = 0;
  tree->SetOnReleaseCollectedForTest([&] {
    fired++;
    (void)tree->RetainProcess(pids);
  });
  tree->ReleaseProcess(pids);
  XCTAssertEqual(fired, 1);
  // The re-verify must observe the resurrection and skip the erase.
  XCTAssertTrue(tree->Get(child_pid).has_value());

  // Releasing the resurrected retain erases it.
  tree->SetOnReleaseCollectedForTest(nullptr);
  tree->ReleaseProcess(pids);
  XCTAssertFalse(tree->Get(child_pid).has_value());
}

// Regression: if a concurrent releaser erases the entry first, the outer
// release's re-verify must find it gone and skip gracefully rather than
// double-erasing or crashing.
- (void)testReleaseRaceConcurrentEraseIsSafe {
  std::vector<std::unique_ptr<Annotator>> annotators{};
  auto tree = std::make_shared<ProcessTreeTestPeer>(std::move(annotators),
                                                    /*removal_grace_ticks=*/10);
  auto init = tree->InsertInit();

  uint64_t event_id = 1;
  const struct Pid child_pid = {.pid = 2, .pidversion = 2};
  {
    tree->HandleFork(event_id++, init, child_pid);
    auto child = *tree->Get(child_pid);
    tree->HandleExit(event_id++, *child);
  }

  {
    auto child = tree->Get(child_pid);
    XCTAssertTrue(child.has_value());
    PidList pids = {(*child)->pid_};
    (void)tree->RetainProcess(pids);
  }

  struct Pid churn_pid = {.pid = 100, .pidversion = 100};
  for (int i = 0; i < 100; i++) {
    tree->HandleFork(event_id++, init, churn_pid);
    churn_pid.pid++;
    churn_pid.pidversion++;
    auto child = tree->Get(child_pid);
    XCTAssertTrue(child.has_value());
  }

  PidList pids = {child_pid};
  int fired = 0;
  tree->SetOnReleaseCollectedForTest([&] {
    // The nested ReleaseProcess re-enters this seam; only act on the first fire.
    if (++fired > 1) return;
    (void)tree->RetainProcess(pids);
    tree->ReleaseProcess(pids);
  });
  tree->ReleaseProcess(pids);
  XCTAssertEqual(fired, 2);
  XCTAssertFalse(tree->Get(child_pid).has_value());
}

// Regression: if the entry is erased and a fresh process re-inserted under the
// same pid within the window, the outer release's re-verify must not erase the
// newcomer. tombstoned_ is the only conjunct that distinguishes it from the
// stale entry it replaced (refcnt is 0 either way).
- (void)testReleaseRaceReinsertInWindowKeepsFreshProcess {
  std::vector<std::unique_ptr<Annotator>> annotators{};
  auto tree = std::make_shared<ProcessTreeTestPeer>(std::move(annotators),
                                                    /*removal_grace_ticks=*/10);
  auto init = tree->InsertInit();

  uint64_t event_id = 1;
  const struct Pid child_pid = {.pid = 2, .pidversion = 2};
  {
    tree->HandleFork(event_id++, init, child_pid);
    auto child = *tree->Get(child_pid);
    tree->HandleExit(event_id++, *child);
  }

  {
    auto child = tree->Get(child_pid);
    XCTAssertTrue(child.has_value());
    PidList pids = {(*child)->pid_};
    (void)tree->RetainProcess(pids);
  }

  struct Pid churn_pid = {.pid = 100, .pidversion = 100};
  for (int i = 0; i < 100; i++) {
    tree->HandleFork(event_id++, init, churn_pid);
    churn_pid.pid++;
    churn_pid.pidversion++;
    auto child = tree->Get(child_pid);
    XCTAssertTrue(child.has_value());
  }

  PidList pids = {child_pid};
  int fired = 0;
  tree->SetOnReleaseCollectedForTest([&] {
    // The nested ReleaseProcess re-enters this seam; only act on the first fire.
    if (++fired > 1) return;
    (void)tree->RetainProcess(pids);
    tree->ReleaseProcess(pids);
    tree->HandleFork(event_id++, init, child_pid);
  });
  tree->ReleaseProcess(pids);
  XCTAssertEqual(fired, 2);
  // The outer re-verify must not erase the freshly re-inserted process.
  XCTAssertTrue(tree->Get(child_pid).has_value());
}

// Regression: reaping must be a per-entry decision keyed on each removal's own
// timestamp, independent of the order removals were scheduled in. ES delivers
// events out of mach_time order, so a still-within-grace removal can sit AHEAD
// of an already-expired one in the pending set. A reaper that stops at the first
// not-yet-expired entry (e.g. a naive front-popping deque) would leak the
// expired entry behind it; the reaper must consider every pending removal (or be
// ordered by timestamp, as a min-heap is).
- (void)testOutOfOrderRemovalsReapedByOwnTimestamp {
  std::vector<std::unique_ptr<Annotator>> annotators{};
  auto tree = std::make_shared<ProcessTreeTestPeer>(std::move(annotators),
                                                    /*removal_grace_ticks=*/10);
  auto init = tree->InsertInit();

  // Survivor: forked at ts=50, exits at ts=100. Its removal is scheduled FIRST,
  // at the newest timestamp seen, so it stays within the grace (cutoff = 90).
  const struct Pid survivor_pid = {.pid = 2, .pidversion = 2};
  tree->HandleFork(50, init, survivor_pid);
  auto survivor = *tree->Get(survivor_pid);
  tree->HandleExit(100, *survivor);  // schedules survivor@100, latest_ts=100

  // Reaped: a reordered straggler forked/exited in the past. Its removal is
  // scheduled SECOND (behind the survivor) but at an old timestamp (20 < 90), so
  // it is already expired the moment it is scheduled.
  const struct Pid reaped_pid = {.pid = 3, .pidversion = 3};
  tree->HandleFork(10, init, reaped_pid);  // novel out-of-order fork, tracked
  auto reaped = *tree->Get(reaped_pid);
  tree->HandleExit(20, *reaped);  // schedules reaped@20 -> already expired

  // The expired straggler is reaped even though a not-yet-expired removal sits
  // ahead of it; the survivor (still within grace) is untouched.
  XCTAssertFalse(tree->Get(reaped_pid).has_value());
  XCTAssertTrue(tree->Get(survivor_pid).has_value());
}

// Regression: ES does not guarantee global mach_time ordering across threads or
// clients, so a genuinely-novel fork/exec can arrive stamped "in the past". The
// tree must still track it. Pre-fix, Step dropped such events as "too old",
// which left the process (and thus CEL `ancestors`) missing under load.
- (void)testOutOfOrderEventsNotDropped {
  uint64_t base = 1000000;

  // Advance the dedup/ordering state well forward with monotonic events.
  struct Pid churn_pid = {.pid = 100, .pidversion = 100};
  for (int i = 0; i < 200; i++) {
    self.tree->HandleFork(base + i, self.initProc, churn_pid);
    churn_pid.pid++;
    churn_pid.pidversion++;
  }

  // A novel fork stamped far behind the newest timestamp seen (reordered straggler).
  const struct Pid late_child_pid = {.pid = 2, .pidversion = 2};
  self.tree->HandleFork(base - 500, self.initProc, late_child_pid);

  auto late_child_opt = self.tree->Get(late_child_pid);
  XCTAssertTrue(late_child_opt.has_value());
  XCTAssertEqual(self.tree->GetParent(**late_child_opt), self.initProc);

  // A novel exec, also stamped in the past, transforms that child.
  std::shared_ptr<const Process> late_child = *late_child_opt;
  const struct Pid late_exec_pid = {.pid = 2, .pidversion = 3};
  const struct Program late_prog = {.executable = "/bin/bash", .arguments = {"/bin/bash"}};
  self.tree->HandleExec(base - 400, *late_child, late_exec_pid, late_prog,
                        late_child->effective_cred_);

  auto late_exec_opt = self.tree->Get(late_exec_pid);
  XCTAssertTrue(late_exec_opt.has_value());
  XCTAssertEqual(*(*late_exec_opt)->program_, late_prog);

  // Ancestry (what CEL `ancestors` walks) is intact up to init.
  auto slice = self.tree->RootSlice(*late_exec_opt);
  XCTAssertEqual(slice.size(), 2u);  // [late_exec, init]
  XCTAssertEqual(slice.back(), self.initProc);
}

// Regression: mach_time has ~41 ns granularity on Apple Silicon and the counter
// is system-wide, so two DISTINCT events on different cores within one tick get
// the same stamp. Deduping on bare mach_time would drop the second as a
// "duplicate"; the dedup key must include the event's identity so both apply.
- (void)testSameMachTimeDistinctEventsBothApplied {
  // Two distinct forks stamped with the SAME mach_time (a ~41 ns collision).
  uint64_t ts = 1000;
  const struct Pid a = {.pid = 2, .pidversion = 2};
  const struct Pid b = {.pid = 3, .pidversion = 3};
  self.tree->HandleFork(ts, self.initProc, a);
  self.tree->HandleFork(ts, self.initProc, b);  // same ts, different child

  XCTAssertTrue(self.tree->Get(a).has_value());
  XCTAssertTrue(self.tree->Get(b).has_value());  // the discriminating assertion
}

// Regression: dedup (claiming an event as "seen") and the corresponding tree
// mutation must be one atomic critical section. The same kernel event is
// delivered to multiple ES clients; once one client claims it, another client
// skips it as a duplicate. If the claim and the map insert were separate lock
// holds, the winning client could pause between them while the skipping client
// (or any reader) observed a missing node. Here the producer pauses INSIDE the
// critical section (holding mtx_) right after claiming a fork; a reader must
// block until the insert is visible, so it can never see the child as absent.
- (void)testConcurrentClaimIsAtomicWithApply {
  std::vector<std::unique_ptr<Annotator>> annotators{};
  auto tree = std::make_shared<ProcessTreeTestPeer>(std::move(annotators));
  auto init = tree->InsertInit();
  const struct Pid child_pid = {.pid = 2, .pidversion = 2};

  std::mutex m;
  std::condition_variable cv;
  bool claimed = false;
  bool release = false;
  std::atomic<bool> readerFinished{false};
  std::atomic<bool> readerSawChild{false};

  bool hookFired = false;
  tree->SetOnEventClaimedForTest([&] {
    // Runs on the producer thread, holding mtx_, just after the claim.
    if (hookFired) return;  // interpose only on the first claim
    hookFired = true;
    {
      std::lock_guard<std::mutex> lk(m);
      claimed = true;
    }
    cv.notify_all();
    std::unique_lock<std::mutex> lk(m);
    cv.wait(lk, [&] { return release; });  // hold mtx_ until released
  });

  // Producer claims the fork and pauses inside the critical section (mtx_ held).
  std::thread producer([&] { tree->HandleFork(1, init, child_pid); });
  {
    std::unique_lock<std::mutex> lk(m);
    // Bounded wait: if StepLocked ever wrongly rejected this novel fork the hook
    // never fires, so fail loudly instead of hanging the suite. The producer has
    // already returned in that case (HandleFork didn't block), so joining is safe.
    if (!cv.wait_for(lk, std::chrono::seconds(5), [&] { return claimed; })) {
      lk.unlock();
      producer.join();
      XCTFail(@"producer never claimed the fork (novel event wrongly deduped?)");
      return;
    }
  }

  // Reader tries to read the child while the producer holds mtx_. With atomic
  // claim+apply the reader MUST block until the insert becomes visible.
  std::thread reader([&] {
    bool present = tree->Get(child_pid).has_value();
    readerSawChild = present;
    readerFinished = true;
  });

  // The reader cannot finish while the producer holds the lock. If it does, the
  // insert was not atomic with the claim (the regression this guards).
  std::this_thread::sleep_for(std::chrono::milliseconds(200));
  XCTAssertFalse(readerFinished.load(),
                 @"reader observed the tree mid-apply — claim/insert not atomic");

  // Release the producer; the reader then observes the fully-applied child.
  {
    std::lock_guard<std::mutex> lk(m);
    release = true;
  }
  cv.notify_all();

  producer.join();
  reader.join();
  XCTAssertTrue(readerFinished.load());
  XCTAssertTrue(readerSawChild.load());  // never saw "absent"
}

- (void)testAnnotationIndexTracksLiveCarriers {
  std::vector<std::unique_ptr<Annotator>> annotators{};
  auto tree = std::make_shared<ProcessTreeTestPeer>(std::move(annotators),
                                                    /*removal_grace_ticks=*/10);
  auto init = tree->InsertInit();
  uint64_t event_id = 1;

  XCTAssertFalse(tree->AnnotationExists("MARK"));

  const struct Pid child_pid = {.pid = 2, .pidversion = 1};
  tree->HandleFork(event_id++, init, child_pid);
  auto child = *tree->Get(child_pid);
  tree->AnnotateProcess(*child,
                        std::make_shared<IndexedTestAnnotator>(std::vector<std::string>{"MARK"}));
  XCTAssertTrue(tree->AnnotationExists("MARK"));

  // A fork of the carrier inherits the annotation: two carriers now.
  const struct Pid grandchild_pid = {.pid = 3, .pidversion = 1};
  tree->HandleFork(event_id++, child, grandchild_pid);
  auto grandchild = *tree->Get(grandchild_pid);
  XCTAssertTrue(tree->AnnotationExists("MARK"));

  // One carrier exiting is not enough.
  tree->HandleExit(event_id++, *child);
  XCTAssertTrue(tree->AnnotationExists("MARK"));

  // The last carrier exiting drops the name immediately -- not when the
  // process is eventually reaped. A dead process must not keep authorizing
  // execs through the removal grace.
  tree->HandleExit(event_id++, *grandchild);
  XCTAssertFalse(tree->AnnotationExists("MARK"));
  XCTAssertTrue(tree->Get(grandchild_pid).has_value());
}

- (void)testAnnotationIndexFollowsExec {
  std::vector<std::unique_ptr<Annotator>> annotators{};
  auto tree = std::make_shared<ProcessTreeTestPeer>(std::move(annotators),
                                                    /*removal_grace_ticks=*/10);
  auto init = tree->InsertInit();
  uint64_t event_id = 1;

  const struct Pid pre_exec = {.pid = 2, .pidversion = 1};
  tree->HandleFork(event_id++, init, pre_exec);
  tree->AnnotateProcess(**tree->Get(pre_exec),
                        std::make_shared<IndexedTestAnnotator>(std::vector<std::string>{"MARK"}));
  XCTAssertTrue(tree->AnnotationExists("MARK"));

  const struct Pid post_exec = {.pid = 2, .pidversion = 2};
  tree->HandleExec(event_id++, **tree->Get(pre_exec), post_exec,
                   (struct Program){.executable = "/bin/after", .arguments = {}},
                   (struct Cred){.uid = 0, .gid = 0});

  // The pre-exec process was retired and the post-exec one inherited the name,
  // so the count is 1 either side of the exec, not 2.
  XCTAssertTrue(tree->AnnotationExists("MARK"));
  tree->HandleExit(event_id++, **tree->Get(post_exec));
  XCTAssertFalse(tree->AnnotationExists("MARK"));
}

- (void)testAnnotationIndexDoesNotDriftOnDuplicateDelivery {
  std::vector<std::unique_ptr<Annotator>> annotators{};
  auto tree = std::make_shared<ProcessTreeTestPeer>(std::move(annotators),
                                                    /*removal_grace_ticks=*/10);
  auto init = tree->InsertInit();

  tree->AnnotateProcess(*init,
                        std::make_shared<IndexedTestAnnotator>(std::vector<std::string>{"MARK"}));

  // The same fork delivered twice (every tree-aware client informs the tree).
  // The second is an exact duplicate, which the dedup gate rejects outright.
  const struct Pid child_pid = {.pid = 2, .pidversion = 1};
  tree->HandleFork(1, init, child_pid);
  tree->HandleFork(1, init, child_pid);
  // A third delivery carrying a DIFFERENT timestamp is novel to the dedup gate
  // and gets all the way to the insert, where it loses the first-wins emplace.
  // This is the case the "index only the winner" guard exists for.
  tree->HandleFork(2, init, child_pid);
  auto child = *tree->Get(child_pid);

  // The same exit delivered twice.
  tree->HandleExit(3, *child);
  tree->HandleExit(3, *child);
  tree->HandleExit(4, *init);

  // Two carriers, each retired once however many times the events arrived.
  XCTAssertFalse(tree->AnnotationExists("MARK"));
}

- (void)testAnnotationIndexFollowsUpdateAnnotation {
  std::vector<std::unique_ptr<Annotator>> annotators{};
  auto tree = std::make_shared<ProcessTreeTestPeer>(std::move(annotators));
  auto init = tree->InsertInit();

  tree->AnnotateProcess(*init,
                        std::make_shared<IndexedTestAnnotator>(std::vector<std::string>{"A"}));
  XCTAssertTrue(tree->AnnotationExists("A"));
  XCTAssertFalse(tree->AnnotationExists("B"));

  tree->UpdateAnnotation<IndexedTestAnnotator>(
      init->pid_, [](const IndexedTestAnnotator*) -> std::shared_ptr<const IndexedTestAnnotator> {
        return std::make_shared<const IndexedTestAnnotator>(std::vector<std::string>{"B"});
      });
  XCTAssertFalse(tree->AnnotationExists("A"));
  XCTAssertTrue(tree->AnnotationExists("B"));

  // Returning nullptr leaves the annotation, and the index, alone.
  tree->UpdateAnnotation<IndexedTestAnnotator>(
      init->pid_, [](const IndexedTestAnnotator*) -> std::shared_ptr<const IndexedTestAnnotator> {
        return nullptr;
      });
  XCTAssertTrue(tree->AnnotationExists("B"));
}

- (void)testAnnotationIndexIgnoresRetiredProcesses {
  std::vector<std::unique_ptr<Annotator>> annotators{};
  auto tree = std::make_shared<ProcessTreeTestPeer>(std::move(annotators),
                                                    /*removal_grace_ticks=*/10);
  auto init = tree->InsertInit();
  uint64_t event_id = 1;

  const struct Pid child_pid = {.pid = 2, .pidversion = 1};
  tree->HandleFork(event_id++, init, child_pid);
  auto child = *tree->Get(child_pid);
  tree->AnnotateProcess(*child,
                        std::make_shared<IndexedTestAnnotator>(std::vector<std::string>{"MARK"}));
  tree->HandleExit(event_id++, *child);
  XCTAssertFalse(tree->AnnotationExists("MARK"));

  // Annotating a retired process must not put anything in the index, even
  // though the process is still in map_ for the removal grace. Use a second
  // process that was never annotated, so the annotation really is inserted
  // and it is the retired check -- not the first-wins emplace -- being tested.
  const struct Pid late_pid = {.pid = 3, .pidversion = 1};
  tree->HandleFork(event_id++, init, late_pid);
  auto late = *tree->Get(late_pid);
  tree->HandleExit(event_id++, *late);
  tree->AnnotateProcess(*late,
                        std::make_shared<IndexedTestAnnotator>(std::vector<std::string>{"LATE"}));
  XCTAssertFalse(tree->AnnotationExists("MARK"));
  XCTAssertFalse(tree->AnnotationExists("LATE"));

  // Churn past the grace so the retired process is actually reaped. The reap
  // must not decrement a second time (which would wrap the unsigned count and
  // make the name exist forever).
  struct Pid churn_pid = {.pid = 10, .pidversion = 1};
  for (int i = 0; i < 20; i++) {
    tree->HandleFork(event_id++, init, churn_pid);
    churn_pid.pid++;
  }
  XCTAssertFalse(tree->Get(child_pid).has_value());
  XCTAssertFalse(tree->AnnotationExists("MARK"));
}

- (void)testAnnotationIndexSurvivesReapOfOneCarrier {
  std::vector<std::unique_ptr<Annotator>> annotators{};
  auto tree = std::make_shared<ProcessTreeTestPeer>(std::move(annotators),
                                                    /*removal_grace_ticks=*/10);
  auto init = tree->InsertInit();
  uint64_t event_id = 1;

  // Two independent carriers of the same name. init is deliberately NOT
  // annotated, so the count is exactly 2.
  const struct Pid first_pid = {.pid = 2, .pidversion = 1};
  const struct Pid second_pid = {.pid = 3, .pidversion = 1};
  tree->HandleFork(event_id++, init, first_pid);
  tree->HandleFork(event_id++, init, second_pid);
  tree->AnnotateProcess(**tree->Get(first_pid),
                        std::make_shared<IndexedTestAnnotator>(std::vector<std::string>{"MARK"}));
  tree->AnnotateProcess(**tree->Get(second_pid),
                        std::make_shared<IndexedTestAnnotator>(std::vector<std::string>{"MARK"}));

  // The first carrier exits -- retired from the index at once -- and is then
  // reaped once the grace elapses. The reap must NOT decrement a second time:
  // the count is 1, not 0, so a stray decrement would erase a name the second
  // carrier is still holding. This is what Process::indexed_ prevents.
  tree->HandleExit(event_id++, **tree->Get(first_pid));
  struct Pid churn_pid = {.pid = 10, .pidversion = 1};
  for (int i = 0; i < 20; i++) {
    tree->HandleFork(event_id++, init, churn_pid);
    churn_pid.pid++;
  }

  XCTAssertFalse(tree->Get(first_pid).has_value());
  XCTAssertTrue(tree->AnnotationExists("MARK"));
}

- (void)testHandleExecDeniedRetiresTargetAndRevivesActor {
  std::vector<std::unique_ptr<Annotator>> annotators{};
  auto tree = std::make_shared<ProcessTreeTestPeer>(std::move(annotators),
                                                    /*removal_grace_ticks=*/10);
  auto init = tree->InsertInit();
  uint64_t event_id = 1;

  const struct Pid actor_pid = {.pid = 2, .pidversion = 1};
  tree->HandleFork(event_id++, init, actor_pid);
  tree->AnnotateProcess(**tree->Get(actor_pid),
                        std::make_shared<IndexedTestAnnotator>(std::vector<std::string>{"MARK"}));
  XCTAssertTrue(tree->AnnotationExists("MARK"));

  // The exec is folded in at AUTH time: the actor is retired and the target
  // published, inheriting the name. One carrier either side of the exec.
  const struct Pid target_pid = {.pid = 2, .pidversion = 2};
  // One timestamp for the exec and for the denial that answers it, as in
  // production: both come from the same AUTH_EXEC message's mach_time, and
  // the revival is keyed on that match (see HandleExecDenied).
  const uint64_t exec_ts = event_id++;
  tree->HandleExec(exec_ts, **tree->Get(actor_pid), target_pid,
                   (struct Program){.executable = "/bin/blocked", .arguments = {}},
                   (struct Cred){.uid = 0, .gid = 0});
  XCTAssertTrue(tree->AnnotationExists("MARK"));

  // DENY: the target is retired (dropped from the index at once, as an exit
  // does, while the node lingers in map_ for the grace) and the actor is
  // revived, so the one surviving carrier is the actor.
  tree->HandleExecDenied(exec_ts, actor_pid, target_pid);
  XCTAssertTrue(tree->AnnotationExists("MARK"));
  XCTAssertTrue(tree->Get(target_pid).has_value());

  // Idempotent: a repeat must not double-decrement the target (which would
  // wrap the unsigned count) nor double-index the actor (which would leave it
  // pinned after it finally exits).
  tree->HandleExecDenied(exec_ts, actor_pid, target_pid);
  XCTAssertTrue(tree->AnnotationExists("MARK"));

  // Pids the tree has never seen are a no-op, not a crash: the authorizer can
  // deny an exec the tree never recorded (e.g. the actor was unknown, so
  // HandleExec bailed before the insert).
  tree->HandleExecDenied(event_id++, (struct Pid){.pid = 998, .pidversion = 7},
                         (struct Pid){.pid = 999, .pidversion = 7});
  XCTAssertTrue(tree->AnnotationExists("MARK"));

  // Churn past the grace. The phantom target is reaped; the actor -- still
  // running, since its execve failed -- is not, and still carries the name.
  struct Pid churn_pid = {.pid = 10, .pidversion = 1};
  for (int i = 0; i < 20; i++) {
    tree->HandleFork(event_id++, init, churn_pid);
    churn_pid.pid++;
  }
  XCTAssertFalse(tree->Get(target_pid).has_value());
  XCTAssertTrue(tree->Get(actor_pid).has_value());
  XCTAssertTrue(tree->AnnotationExists("MARK"));

  // And when the actor really does exit, it retires and is reaped normally --
  // reviving it did not make it unreapable.
  tree->HandleExit(event_id++, **tree->Get(actor_pid));
  XCTAssertFalse(tree->AnnotationExists("MARK"));
  for (int i = 0; i < 20; i++) {
    tree->HandleFork(event_id++, init, churn_pid);
    churn_pid.pid++;
  }
  XCTAssertFalse(tree->Get(actor_pid).has_value());
}

// Regression: a DENIED exec must not pin the annotations its target inherited.
// Santa informs the tree at AUTH_EXEC -- before it decides -- so the target
// pidversion is published and indexed even when the answer is DENY and that
// process therefore never comes into existence. No NOTIFY_EXEC and no
// NOTIFY_EXIT ever arrive for it, so without the target half of
// HandleExecDenied nothing would ever retire it and annotation_exists() would
// answer true for the life of santad -- permanently allowlisting every rule
// gated on it.
- (void)testDeniedExecDoesNotPinAnnotation {
  std::vector<std::unique_ptr<Annotator>> annotators{};
  auto tree = std::make_shared<ProcessTreeTestPeer>(std::move(annotators),
                                                    /*removal_grace_ticks=*/10);
  auto init = tree->InsertInit();
  uint64_t event_id = 1;

  // A tool is running and a rule stamps it with a fork-and-exec annotation.
  const struct Pid tool_pid = {.pid = 4521, .pidversion = 18734};
  tree->HandleFork(event_id++, init, tool_pid);
  auto tool = *tree->Get(tool_pid);
  tree->AnnotateProcess(
      *tool, std::make_shared<IndexedTestAnnotator>(std::vector<std::string>{"claude-code"}));
  XCTAssertTrue(tree->AnnotationExists("claude-code"));

  // Something under it forks; the child inherits the name.
  const struct Pid forked_pid = {.pid = 9000, .pidversion = 1};
  tree->HandleFork(event_id++, tool, forked_pid);
  auto forked = *tree->Get(forked_pid);
  XCTAssertTrue(tree->AnnotationExists("claude-code"));

  // The child tries to exec a blocked binary. The tree is told at AUTH time,
  // so the target is published -- inheriting the name -- before any decision.
  const struct Pid denied_pid = {.pid = 9000, .pidversion = 2};
  const uint64_t exec_ts = event_id++;
  tree->HandleExec(exec_ts, *forked, denied_pid,
                   (struct Program){.executable = "/bin/blocked", .arguments = {}},
                   (struct Cred){.uid = 0, .gid = 0});
  XCTAssertTrue(tree->Get(denied_pid).has_value());

  // Santa DENIES, answering the same AUTH_EXEC and so carrying the same
  // timestamp. 9000.2 never exists; 9000.1 goes on running. Without this call
  // the phantom holds its +1 forever and every assertion below flips.
  tree->HandleExecDenied(exec_ts, forked_pid, denied_pid);

  // The exec having failed, the forking process runs on and later exits, then
  // so does the annotated tool. Nothing carrying the name is alive any more.
  tree->HandleExit(event_id++, *forked);
  tree->HandleExit(event_id++, *tool);
  XCTAssertFalse(tree->AnnotationExists("claude-code"));

  // ...and it stays gone once everything is reaped.
  struct Pid churn_pid = {.pid = 10, .pidversion = 1};
  for (int i = 0; i < 20; i++) {
    tree->HandleFork(event_id++, init, churn_pid);
    churn_pid.pid++;
  }
  XCTAssertFalse(tree->Get(denied_pid).has_value());
  XCTAssertFalse(tree->AnnotationExists("claude-code"));
}

// Mirror regression: the annotated process attempts the blocked exec itself.
// HandleExec retires the actor at AUTH time, so without the actor half of
// HandleExecDenied annotation_exists() goes FALSE while claude-code is still
// running -- a false negative in an authorization gate -- and the live process
// is evicted from the tree once the grace elapses.
- (void)testDeniedExecKeepsAnnotatedActorAlive {
  std::vector<std::unique_ptr<Annotator>> annotators{};
  auto tree = std::make_shared<ProcessTreeTestPeer>(std::move(annotators),
                                                    /*removal_grace_ticks=*/10);
  auto init = tree->InsertInit();
  uint64_t event_id = 1;

  const struct Pid tool_pid = {.pid = 4521, .pidversion = 18734};
  tree->HandleFork(event_id++, init, tool_pid);
  tree->AnnotateProcess(**tree->Get(tool_pid), std::make_shared<IndexedTestAnnotator>(
                                                   std::vector<std::string>{"claude-code"}));
  XCTAssertTrue(tree->AnnotationExists("claude-code"));

  // The tool itself tries to exec a blocked binary.
  const struct Pid denied_pid = {.pid = 4521, .pidversion = 18735};
  const uint64_t exec_ts = event_id++;
  tree->HandleExec(exec_ts, **tree->Get(tool_pid), denied_pid,
                   (struct Program){.executable = "/bin/blocked", .arguments = {}},
                   (struct Cred){.uid = 0, .gid = 0});
  tree->HandleExecDenied(exec_ts, tool_pid, denied_pid);

  // execve returned EPERM; the tool is running its old image. The gate must
  // still be open, and must stay open past the grace -- re-indexing alone
  // would not do that, since DrainRemovals unindexes again at the erase site.
  XCTAssertTrue(tree->AnnotationExists("claude-code"));
  struct Pid churn_pid = {.pid = 10, .pidversion = 1};
  for (int i = 0; i < 20; i++) {
    tree->HandleFork(event_id++, init, churn_pid);
    churn_pid.pid++;
  }
  auto tool = tree->Get(tool_pid);
  XCTAssertTrue(tool.has_value());
  XCTAssertTrue(tree->AnnotationExists("claude-code"));
  if (!tool) {
    // Bail rather than dereference an empty optional: the rest of this test
    // only makes sense if the tool survived.
    return;
  }

  // A fork of the surviving tool still inherits the annotation, i.e. it was
  // revived as a real carrier and not just patched into the index.
  const struct Pid grandchild_pid = {.pid = 7777, .pidversion = 1};
  tree->HandleFork(event_id++, *tool, grandchild_pid);
  tree->HandleExit(event_id++, **tree->Get(tool_pid));
  XCTAssertTrue(tree->AnnotationExists("claude-code"));
  tree->HandleExit(event_id++, **tree->Get(grandchild_pid));
  XCTAssertFalse(tree->AnnotationExists("claude-code"));
}

// A revived process that later genuinely exits must be reaped on ITS OWN
// deadline, not on the stale deadline of the cancelled removal still sitting
// in remove_at_ (a priority_queue cannot have an entry extracted). Hence
// Process::removal_ts_: only the entry matching the most recent schedule
// reaps.
- (void)testRevivedActorReapedOnRealExitDeadline {
  std::vector<std::unique_ptr<Annotator>> annotators{};
  auto tree = std::make_shared<ProcessTreeTestPeer>(std::move(annotators),
                                                    /*removal_grace_ticks=*/10);
  auto init = tree->InsertInit();

  const struct Pid actor_pid = {.pid = 2, .pidversion = 1};
  const struct Pid target_pid = {.pid = 2, .pidversion = 2};
  tree->HandleFork(1, init, actor_pid);
  // Schedules actor@5 and publishes the target...
  tree->HandleExec(5, **tree->Get(actor_pid), target_pid,
                   (struct Program){.executable = "/bin/blocked", .arguments = {}},
                   (struct Cred){.uid = 0, .gid = 0});
  // ...denied, so actor@5 is cancelled (the entry stays in the queue) and
  // target@5 is scheduled.
  tree->HandleExecDenied(5, actor_pid, target_pid);
  // The actor runs on and exits at 6: actor@6, which is now the only schedule
  // that counts.
  tree->HandleExit(6, **tree->Get(actor_pid));

  // cutoff = 16 - 10 = 6. The stale actor@5 and the target@5 entries expire;
  // actor@6 does not. The actor must survive this drain -- reaping it here
  // would be reaping it on a deadline that was cancelled.
  struct Pid churn_pid = {.pid = 10, .pidversion = 1};
  tree->HandleFork(16, init, churn_pid);
  XCTAssertTrue(tree->Get(actor_pid).has_value());
  XCTAssertFalse(tree->Get(target_pid).has_value());

  // cutoff = 17 - 10 = 7: actor@6 expires and the actor is reaped normally.
  churn_pid.pid++;
  tree->HandleFork(17, init, churn_pid);
  XCTAssertFalse(tree->Get(actor_pid).has_value());
}

// The actor cannot exit voluntarily while blocked in the ES auth wait, but it
// can be killed from outside (^C in the spawning shell, a watchdog, a process
// group teardown), and an AUTH_EXEC can be pending for seconds. Its
// NOTIFY_EXIT reaches the tree through a different client on a different
// queue, so it can be processed BEFORE the denial. Reviving unconditionally
// then would put a dead process back in the index with its removal cancelled,
// and nothing would ever schedule it again -- StepLocked drops the duplicate
// exit -- re-creating the pinned-annotation bug through a narrower door.
- (void)testDeniedExecDoesNotReviveAKilledActor {
  std::vector<std::unique_ptr<Annotator>> annotators{};
  auto tree = std::make_shared<ProcessTreeTestPeer>(std::move(annotators),
                                                    /*removal_grace_ticks=*/10);
  auto init = tree->InsertInit();

  const struct Pid actor_pid = {.pid = 2, .pidversion = 1};
  const struct Pid target_pid = {.pid = 2, .pidversion = 2};
  tree->HandleFork(1, init, actor_pid);
  tree->AnnotateProcess(**tree->Get(actor_pid),
                        std::make_shared<IndexedTestAnnotator>(std::vector<std::string>{"MARK"}));

  // AUTH_EXEC at 100: the actor is retired and scheduled at 100, and the
  // target is published carrying the inherited name.
  tree->HandleExec(100, **tree->Get(actor_pid), target_pid,
                   (struct Program){.executable = "/bin/blocked", .arguments = {}},
                   (struct Cred){.uid = 0, .gid = 0});
  XCTAssertTrue(tree->AnnotationExists("MARK"));

  // The actor is killed while it waits, and its exit is processed first,
  // re-scheduling it at 150.
  tree->HandleExit(150, **tree->Get(actor_pid));

  // Only now does the denial land, still carrying the AUTH_EXEC's timestamp.
  // The target is retired as always; the actor must NOT come back, because
  // the removal pending on it is the exit's, not the one this denial
  // cancels.
  tree->HandleExecDenied(100, actor_pid, target_pid);
  XCTAssertFalse(tree->AnnotationExists("MARK"));
  XCTAssertFalse(tree->Get(target_pid).has_value());

  // ...and the exit's own removal still stands, so the dead actor is reaped
  // rather than left in map_ forever with nothing to schedule it again.
  struct Pid churn_pid = {.pid = 10, .pidversion = 1};
  for (int i = 0; i < 20; i++) {
    tree->HandleFork(160 + i, init, churn_pid);
    churn_pid.pid++;
  }
  XCTAssertFalse(tree->Get(actor_pid).has_value());
  XCTAssertFalse(tree->AnnotationExists("MARK"));
}

// The authorizer answers ES before it unwinds (see
// SNTEndpointSecurityAuthorizer), which leaves a window in which the released
// actor can exec again before the denial reaches the tree. That is a pure tree
// property, so it is modelled here rather than through a seam in the
// authorizer: a late denial for the FIRST exec must not revive an actor the
// SECOND exec has already legitimately retired, and must not disturb the
// second exec's target.
- (void)testLateDenialDoesNotUndoARaceWinningReExec {
  std::vector<std::unique_ptr<Annotator>> annotators{};
  auto tree = std::make_shared<ProcessTreeTestPeer>(std::move(annotators),
                                                    /*removal_grace_ticks=*/10);
  auto init = tree->InsertInit();

  const struct Pid actor_pid = {.pid = 2, .pidversion = 1};
  const struct Pid denied_pid = {.pid = 2, .pidversion = 2};
  const struct Pid second_pid = {.pid = 2, .pidversion = 3};
  tree->HandleFork(1, init, actor_pid);
  tree->AnnotateProcess(**tree->Get(actor_pid),
                        std::make_shared<IndexedTestAnnotator>(std::vector<std::string>{"MARK"}));

  // AUTH_EXEC #1 at 100: the actor is retired and scheduled at 100.
  tree->HandleExec(100, **tree->Get(actor_pid), denied_pid,
                   (struct Program){.executable = "/bin/blocked", .arguments = {}},
                   (struct Cred){.uid = 0, .gid = 0});

  // The DENY response has gone out; the actor is running again and execs
  // something else at 110, which re-schedules it at 110.
  tree->HandleExec(110, **tree->Get(actor_pid), second_pid,
                   (struct Program){.executable = "/bin/allowed", .arguments = {}},
                   (struct Cred){.uid = 0, .gid = 0});

  // Only now does the unwind for the FIRST exec land, still stamped 100.
  tree->HandleExecDenied(100, actor_pid, denied_pid);

  // The second exec's target is untouched and still carries the name.
  XCTAssertTrue(tree->Get(second_pid).has_value());
  XCTAssertTrue(tree->AnnotationExists("MARK"));

  // Past the grace: the phantom first target is reaped, the actor is reaped on
  // the SECOND exec's schedule (the late denial must not have cancelled it),
  // and the live process is still there and still answering.
  struct Pid churn_pid = {.pid = 10, .pidversion = 1};
  for (int i = 0; i < 20; i++) {
    tree->HandleFork(120 + i, init, churn_pid);
    churn_pid.pid++;
  }
  XCTAssertFalse(tree->Get(denied_pid).has_value());
  XCTAssertFalse(tree->Get(actor_pid).has_value());
  XCTAssertTrue(tree->Get(second_pid).has_value());
  XCTAssertTrue(tree->AnnotationExists("MARK"));
}

// The authorization deadline can outlast the removal grace, so DrainRemovals
// may already have tombstoned the actor by the time the deny arrives -- it is
// retained for the duration of message processing (the event's ProcessToken),
// so the reap turns into a tombstone rather than an erase. Reviving must clear
// tombstoned_ as well, or ReleaseProcess erases the live process the instant
// that token dies.
- (void)testRevivedActorSurvivesTombstoneAndRelease {
  std::vector<std::unique_ptr<Annotator>> annotators{};
  auto tree = std::make_shared<ProcessTreeTestPeer>(std::move(annotators),
                                                    /*removal_grace_ticks=*/10);
  auto init = tree->InsertInit();

  const struct Pid actor_pid = {.pid = 2, .pidversion = 1};
  const struct Pid target_pid = {.pid = 2, .pidversion = 2};
  tree->HandleFork(1, init, actor_pid);
  tree->AnnotateProcess(**tree->Get(actor_pid),
                        std::make_shared<IndexedTestAnnotator>(std::vector<std::string>{"MARK"}));

  // Stand in for the ProcessToken the tree-aware client holds for the whole
  // of message handling. Production creates that token after
  // InformFromESEvent, so it holds the actor AND the target; retaining here,
  // before HandleExec publishes the target, holds only the actor. That is all
  // this test needs -- the actor's refcount is what turns its reap into a
  // tombstone below.
  PidList retained = tree->RetainProcess(PidList{actor_pid, target_pid});
  XCTAssertEqual(retained.size(), 1u);

  tree->HandleExec(5, **tree->Get(actor_pid), target_pid,
                   (struct Program){.executable = "/bin/blocked", .arguments = {}},
                   (struct Cred){.uid = 0, .gid = 0});

  // The decision takes longer than the grace: the actor's removal comes due
  // while it is still retained, so it is tombstoned rather than erased.
  struct Pid churn_pid = {.pid = 10, .pidversion = 1};
  for (int i = 0; i < 20; i++) {
    tree->HandleFork(20 + i, init, churn_pid);
    churn_pid.pid++;
  }
  XCTAssertTrue(tree->Get(actor_pid).has_value());

  // Now the deny lands -- late, but still carrying the AUTH_EXEC's own
  // timestamp, which is what the revival is keyed on -- and the actor is
  // revived...
  tree->HandleExecDenied(5, actor_pid, target_pid);
  XCTAssertTrue(tree->AnnotationExists("MARK"));

  // ...and the event finishes, dropping the retain. A still-tombstoned
  // process would be erased right here.
  tree->ReleaseProcess(retained);
  XCTAssertTrue(tree->Get(actor_pid).has_value());
  XCTAssertTrue(tree->AnnotationExists("MARK"));
}

// One exec schedules the actor twice: the Authorizer sees it as AUTH_EXEC and
// again as NOTIFY_EXEC, with different mach_times, and both are novel to the
// dedup gate. When the exec is allowed, the actor must still be reaped -- the
// removal_ts_ match must not leave the superseded entry as the only one that
// ever matched.
- (void)testAllowedExecWithBothDeliveriesStillReapsActor {
  std::vector<std::unique_ptr<Annotator>> annotators{};
  auto tree = std::make_shared<ProcessTreeTestPeer>(std::move(annotators),
                                                    /*removal_grace_ticks=*/10);
  auto init = tree->InsertInit();

  const struct Pid actor_pid = {.pid = 2, .pidversion = 1};
  const struct Pid target_pid = {.pid = 2, .pidversion = 2};
  tree->HandleFork(1, init, actor_pid);

  tree->HandleExec(5, **tree->Get(actor_pid), target_pid,
                   (struct Program){.executable = "/bin/after", .arguments = {}},
                   (struct Cred){.uid = 0, .gid = 0});
  // Same exec, redelivered as NOTIFY_EXEC with a later stamp: novel to the
  // dedup gate, loses the first-wins insert, schedules the actor a second
  // time.
  tree->HandleExec(6, **tree->Get(actor_pid), target_pid,
                   (struct Program){.executable = "/bin/after", .arguments = {}},
                   (struct Cred){.uid = 0, .gid = 0});

  struct Pid churn_pid = {.pid = 10, .pidversion = 1};
  for (int i = 0; i < 20; i++) {
    tree->HandleFork(10 + i, init, churn_pid);
    churn_pid.pid++;
  }
  XCTAssertFalse(tree->Get(actor_pid).has_value());
  XCTAssertTrue(tree->Get(target_pid).has_value());
}

@end
