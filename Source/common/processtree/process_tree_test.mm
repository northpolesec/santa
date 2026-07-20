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
#include <thread>

#include "Source/common/processtree/annotations/annotator.h"
#include "Source/common/processtree/process.h"
#include "Source/common/processtree/process_tree_test_helpers.h"
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
  self.tree->HandleFork(event_id++, *self.initProc, child_pid);

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
  self.tree->HandleFork(event_id++, *self.initProc, login_pid);

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
  self.tree->HandleFork(event_id++, *login, shell_pid);
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
  tree->HandleFork(event_id++, *init, child_pid);  // ts=1
  auto child = *tree->Get(child_pid);
  tree->HandleExit(event_id++, *child);  // ts=2: scheduled for removal

  // Still present immediately after exit (well within the grace).
  XCTAssertTrue(tree->Get(child_pid).has_value());

  // Step forward but stay within the grace (latest_ts - grace <= 2).
  struct Pid churn_pid = {.pid = 3, .pidversion = 3};
  for (int i = 0; i < 10; i++) {  // ts=3..12 -> latest=12, cutoff=2
    tree->HandleFork(event_id++, *init, churn_pid);
    churn_pid.pid++;
  }
  XCTAssertTrue(tree->Get(child_pid).has_value());

  // Step past the grace (latest_ts - grace > 2): the exited child is reaped.
  for (int i = 0; i < 5; i++) {  // ts=13..17 -> cutoff reaches 7 > 2
    tree->HandleFork(event_id++, *init, churn_pid);
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
    tree->HandleFork(event_id++, *init, child_pid);
    auto child = *tree->Get(child_pid);
    tree->HandleExit(event_id++, *child);
  }

  {
    auto child = tree->Get(child_pid);
    XCTAssertTrue(child.has_value());
    PidList pids = {(*child)->pid_};
    tree->RetainProcess(pids);
  }

  // Even stepping well past the grace, the retained child stays reachable
  // (tombstoned, not erased).
  struct Pid churn_pid = {.pid = 100, .pidversion = 100};
  for (int i = 0; i < 100; i++) {
    tree->HandleFork(event_id++, *init, churn_pid);
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
    tree->HandleFork(event_id++, *init, child_pid);
    auto child = *tree->Get(child_pid);
    tree->HandleExit(event_id++, *child);
  }

  {
    auto child = tree->Get(child_pid);
    XCTAssertTrue(child.has_value());
    PidList pids = {(*child)->pid_};
    tree->RetainProcess(pids);
  }

  struct Pid churn_pid = {.pid = 100, .pidversion = 100};
  for (int i = 0; i < 100; i++) {
    tree->HandleFork(event_id++, *init, churn_pid);
    churn_pid.pid++;
    churn_pid.pidversion++;
    auto child = tree->Get(child_pid);
    XCTAssertTrue(child.has_value());
  }

  PidList pids = {child_pid};
  int fired = 0;
  tree->SetOnReleaseCollectedForTest([&] {
    fired++;
    tree->RetainProcess(pids);
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
    tree->HandleFork(event_id++, *init, child_pid);
    auto child = *tree->Get(child_pid);
    tree->HandleExit(event_id++, *child);
  }

  {
    auto child = tree->Get(child_pid);
    XCTAssertTrue(child.has_value());
    PidList pids = {(*child)->pid_};
    tree->RetainProcess(pids);
  }

  struct Pid churn_pid = {.pid = 100, .pidversion = 100};
  for (int i = 0; i < 100; i++) {
    tree->HandleFork(event_id++, *init, churn_pid);
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
    tree->RetainProcess(pids);
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
    tree->HandleFork(event_id++, *init, child_pid);
    auto child = *tree->Get(child_pid);
    tree->HandleExit(event_id++, *child);
  }

  {
    auto child = tree->Get(child_pid);
    XCTAssertTrue(child.has_value());
    PidList pids = {(*child)->pid_};
    tree->RetainProcess(pids);
  }

  struct Pid churn_pid = {.pid = 100, .pidversion = 100};
  for (int i = 0; i < 100; i++) {
    tree->HandleFork(event_id++, *init, churn_pid);
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
    tree->RetainProcess(pids);
    tree->ReleaseProcess(pids);
    tree->HandleFork(event_id++, *init, child_pid);
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
  tree->HandleFork(50, *init, survivor_pid);
  auto survivor = *tree->Get(survivor_pid);
  tree->HandleExit(100, *survivor);  // schedules survivor@100, latest_ts=100

  // Reaped: a reordered straggler forked/exited in the past. Its removal is
  // scheduled SECOND (behind the survivor) but at an old timestamp (20 < 90), so
  // it is already expired the moment it is scheduled.
  const struct Pid reaped_pid = {.pid = 3, .pidversion = 3};
  tree->HandleFork(10, *init, reaped_pid);  // novel out-of-order fork, tracked
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
    self.tree->HandleFork(base + i, *self.initProc, churn_pid);
    churn_pid.pid++;
    churn_pid.pidversion++;
  }

  // A novel fork stamped far behind the newest timestamp seen (reordered straggler).
  const struct Pid late_child_pid = {.pid = 2, .pidversion = 2};
  self.tree->HandleFork(base - 500, *self.initProc, late_child_pid);

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
  self.tree->HandleFork(ts, *self.initProc, a);
  self.tree->HandleFork(ts, *self.initProc, b);  // same ts, different child

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
  std::thread producer([&] { tree->HandleFork(1, *init, child_pid); });
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

@end
