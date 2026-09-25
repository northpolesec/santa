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

#include <string>

#include "Source/common/processtree/annotations/cel.h"
#include "Source/common/processtree/process.h"
#include "Source/common/processtree/process_tree.pb.h"
#include "Source/common/processtree/process_tree_test_helpers.h"

using namespace santa::santad::process_tree;

namespace {
constexpr CELAnnotator::Entry kNone = {.fork = false, .exec = false};
constexpr CELAnnotator::Entry kForkOnly = {.fork = true, .exec = false};
constexpr CELAnnotator::Entry kExecOnly = {.fork = false, .exec = true};
constexpr CELAnnotator::Entry kForkAndExec = {.fork = true, .exec = true};
}  // namespace

@interface CELAnnotatorTest : XCTestCase
@property std::shared_ptr<ProcessTreeTestPeer> tree;
@property std::shared_ptr<const Process> initProc;
@property uint64_t eventID;
@end

@implementation CELAnnotatorTest

- (void)setUp {
  // Deliberately no registered annotators: CEL annotations inherit through
  // Annotator::Propagate, which the tree drives under its write lock, so this
  // is the production configuration.
  self.tree = std::make_shared<ProcessTreeTestPeer>(std::vector<std::unique_ptr<Annotator>>{});
  self.initProc = self.tree->InsertInit();
  self.eventID = 1;
}

// fork() `parent` to `pid`.`pidver`, returning the child.
- (std::shared_ptr<const Process>)fork:(std::shared_ptr<const Process>)parent
                                    to:(pid_t)pid
                                   ver:(uint64_t)pidver {
  const struct Pid child_pid = {.pid = pid, .pidversion = pidver};
  self.tree->HandleFork(self.eventID++, parent, child_pid);
  return *self.tree->Get(child_pid);
}

// exec() `proc` to the same pid at `pidver`, returning the post-exec process.
- (std::shared_ptr<const Process>)exec:(std::shared_ptr<const Process>)proc
                                   ver:(uint64_t)pidver
                                  path:(const std::string&)path {
  const struct Pid exec_pid = {.pid = proc->pid_.pid, .pidversion = pidver};
  const struct Program prog = {.executable = path, .arguments = {}};
  self.tree->HandleExec(self.eventID++, *proc, exec_pid, prog, {.uid = 0, .gid = 0});
  return *self.tree->Get(exec_pid);
}

- (BOOL)has:(const std::string&)name on:(const std::shared_ptr<const Process>&)proc {
  auto annotation = self.tree->GetAnnotation<CELAnnotator>(*proc);
  return annotation && *annotation && (*annotation)->Has(name);
}

// Walks init -> fork -> exec -> fork -> exec, annotating the first exec'd
// process, and reports which of the two descendants ended up with the
// annotation.
- (void)runPropagation:(CELAnnotator::Entry)entry
              selfExec:(BOOL*)selfExec
             forkChild:(BOOL*)forkChild
             execChild:(BOOL*)execChild {
  auto tool = [self exec:[self fork:self.initProc to:2 ver:2] ver:3 path:"/usr/bin/tool"];
  AddCELAnnotation(*self.tree, tool->pid_, "MARK", entry);
  XCTAssertTrue([self has:"MARK" on:tool], "annotation missing on the process it was added to");

  // The tool re-execs itself: same pid, new pidversion.
  *selfExec = [self has:"MARK" on:[self exec:tool ver:4 path:"/usr/bin/tool2"]];

  auto child = [self fork:tool to:3 ver:3];
  *forkChild = [self has:"MARK" on:child];
  *execChild = [self has:"MARK" on:[self exec:child ver:4 path:"/bin/zsh"]];
}

- (void)testPropagationNone {
  BOOL selfExec, forkChild, execChild;
  [self runPropagation:kNone selfExec:&selfExec forkChild:&forkChild execChild:&execChild];
  XCTAssertFalse(selfExec);
  XCTAssertFalse(forkChild);
  XCTAssertFalse(execChild);
}

- (void)testPropagationForkOnly {
  BOOL selfExec, forkChild, execChild;
  [self runPropagation:kForkOnly selfExec:&selfExec forkChild:&forkChild execChild:&execChild];
  XCTAssertFalse(selfExec);
  XCTAssertTrue(forkChild);
  // The forked child had it, but exec drops it: this is why FORK_ONLY is not
  // observable from a CEL exec rule.
  XCTAssertFalse(execChild);
}

- (void)testPropagationExecOnly {
  BOOL selfExec, forkChild, execChild;
  [self runPropagation:kExecOnly selfExec:&selfExec forkChild:&forkChild execChild:&execChild];
  XCTAssertTrue(selfExec);
  XCTAssertFalse(forkChild);
  XCTAssertFalse(execChild);
}

- (void)testPropagationForkAndExec {
  BOOL selfExec, forkChild, execChild;
  [self runPropagation:kForkAndExec selfExec:&selfExec forkChild:&forkChild execChild:&execChild];
  XCTAssertTrue(selfExec);
  XCTAssertTrue(forkChild);
  XCTAssertTrue(execChild);
}

- (void)testMultipleAnnotationsWithDifferentPropagation {
  auto tool = [self exec:[self fork:self.initProc to:2 ver:2] ver:3 path:"/usr/bin/tool"];
  AddCELAnnotation(*self.tree, tool->pid_, "STICKY", kForkAndExec);
  AddCELAnnotation(*self.tree, tool->pid_, "LOCAL", kNone);
  XCTAssertTrue([self has:"STICKY" on:tool]);
  XCTAssertTrue([self has:"LOCAL" on:tool]);

  auto child = [self exec:[self fork:tool to:3 ver:3] ver:4 path:"/bin/zsh"];
  XCTAssertTrue([self has:"STICKY" on:child]);
  XCTAssertFalse([self has:"LOCAL" on:child]);
}

- (void)testReAddUpdatesPropagation {
  auto tool = [self exec:[self fork:self.initProc to:2 ver:2] ver:3 path:"/usr/bin/tool"];
  AddCELAnnotation(*self.tree, tool->pid_, "MARK", kNone);
  AddCELAnnotation(*self.tree, tool->pid_, "MARK", kForkAndExec);

  auto child = [self exec:[self fork:tool to:3 ver:3] ver:4 path:"/bin/zsh"];
  XCTAssertTrue([self has:"MARK" on:child]);
}

// A descendant that inherits an annotation unchanged shares the ancestor's
// object rather than an equal copy, which is what keeps an allocation out of
// the critical section that publishes it.
- (void)testWhollyPropagatedAnnotationIsSharedNotCopied {
  auto tool = [self exec:[self fork:self.initProc to:2 ver:2] ver:3 path:"/usr/bin/tool"];
  AddCELAnnotation(*self.tree, tool->pid_, "STICKY", kForkAndExec);
  auto toolAnnotation = self.tree->GetAnnotation<CELAnnotator>(*tool);
  XCTAssertTrue(toolAnnotation.has_value());

  auto child = [self fork:tool to:3 ver:3];
  auto childAnnotation = self.tree->GetAnnotation<CELAnnotator>(*child);
  XCTAssertTrue(childAnnotation.has_value());
  XCTAssertEqual(*childAnnotation, *toolAnnotation);

  // ...and across an exec too.
  auto grandchild = [self exec:child ver:4 path:"/bin/zsh"];
  auto grandchildAnnotation = self.tree->GetAnnotation<CELAnnotator>(*grandchild);
  XCTAssertTrue(grandchildAnnotation.has_value());
  XCTAssertEqual(*grandchildAnnotation, *toolAnnotation);
}

// The sharing above is only safe because annotations are immutable: adding to a
// descendant must build it a new object, never write through the one its
// ancestors are still pointing at.
- (void)testAddingToADescendantDoesNotTouchTheAncestor {
  auto tool = [self exec:[self fork:self.initProc to:2 ver:2] ver:3 path:"/usr/bin/tool"];
  AddCELAnnotation(*self.tree, tool->pid_, "PARENT-MARK", kForkAndExec);

  auto child = [self fork:tool to:3 ver:3];
  // Precondition: the child is sharing the parent's object at this point.
  XCTAssertEqual(*self.tree->GetAnnotation<CELAnnotator>(*child),
                 *self.tree->GetAnnotation<CELAnnotator>(*tool));

  AddCELAnnotation(*self.tree, child->pid_, "CHILD-MARK", kForkAndExec);

  // The child gained the new name...
  XCTAssertTrue([self has:"PARENT-MARK" on:child]);
  XCTAssertTrue([self has:"CHILD-MARK" on:child]);

  // ...and the parent is untouched, both in content and in identity.
  XCTAssertTrue([self has:"PARENT-MARK" on:tool]);
  XCTAssertFalse([self has:"CHILD-MARK" on:tool]);
  XCTAssertEqual((*self.tree->GetAnnotation<CELAnnotator>(*tool))->entries().size(), 1u);
  XCTAssertNotEqual(*self.tree->GetAnnotation<CELAnnotator>(*child),
                    *self.tree->GetAnnotation<CELAnnotator>(*tool));

  // A sibling forked before the child's add is likewise unaffected.
  auto sibling = [self fork:tool to:4 ver:4];
  XCTAssertTrue([self has:"PARENT-MARK" on:sibling]);
  XCTAssertFalse([self has:"CHILD-MARK" on:sibling]);
}

// A mixed set cannot be shared: the descendant needs the filtered subset, so
// the tree has to fall back to Propagate().
- (void)testPartiallyPropagatedAnnotationIsCopied {
  auto tool = [self exec:[self fork:self.initProc to:2 ver:2] ver:3 path:"/usr/bin/tool"];
  AddCELAnnotation(*self.tree, tool->pid_, "STICKY", kForkAndExec);
  AddCELAnnotation(*self.tree, tool->pid_, "LOCAL", kNone);

  auto child = [self fork:tool to:3 ver:3];
  XCTAssertNotEqual(*self.tree->GetAnnotation<CELAnnotator>(*child),
                    *self.tree->GetAnnotation<CELAnnotator>(*tool));
  XCTAssertTrue([self has:"STICKY" on:child]);
  XCTAssertFalse([self has:"LOCAL" on:child]);
}

- (void)testLimits {
  auto tool = [self exec:[self fork:self.initProc to:2 ver:2] ver:3 path:"/usr/bin/tool"];

  AddCELAnnotation(*self.tree, tool->pid_, "", kForkAndExec);
  XCTAssertFalse([self has:"" on:tool]);

  std::string tooLong(CELAnnotator::kMaxNameLength + 1, 'x');
  AddCELAnnotation(*self.tree, tool->pid_, tooLong, kForkAndExec);
  XCTAssertFalse([self has:tooLong on:tool]);

  // Reachable from a rule such as add_annotation(args[1], ...) with crafted argv.
  AddCELAnnotation(*self.tree, tool->pid_, "\xff\xfe", kForkAndExec);
  XCTAssertFalse([self has:"\xff\xfe" on:tool]);

  for (size_t i = 0; i < CELAnnotator::kMaxEntries; i++) {
    AddCELAnnotation(*self.tree, tool->pid_, "MARK" + std::to_string(i), kForkAndExec);
  }
  XCTAssertTrue([self has:"MARK0" on:tool]);
  XCTAssertTrue([self has:"MARK" + std::to_string(CELAnnotator::kMaxEntries - 1) on:tool]);

  AddCELAnnotation(*self.tree, tool->pid_, "OVERFLOW", kForkAndExec);
  XCTAssertFalse([self has:"OVERFLOW" on:tool]);

  // An existing name can still be updated once the map is full.
  AddCELAnnotation(*self.tree, tool->pid_, "MARK0", kNone);
  XCTAssertTrue([self has:"MARK0" on:tool]);
}

- (void)testProto {
  auto tool = [self exec:[self fork:self.initProc to:2 ver:2] ver:3 path:"/usr/bin/tool"];
  AddCELAnnotation(*self.tree, tool->pid_, "ZEBRA", kForkAndExec);
  AddCELAnnotation(*self.tree, tool->pid_, "ALPHA", kNone);

  auto annotations = self.tree->ExportAnnotations(tool->pid_);
  XCTAssertTrue(annotations.has_value());
  XCTAssertEqual(annotations->cel_size(), 2);
  XCTAssertEqual(annotations->cel(0), "ALPHA");
  XCTAssertEqual(annotations->cel(1), "ZEBRA");
}

- (void)testNoAnnotationsExportsNothing {
  auto tool = [self exec:[self fork:self.initProc to:2 ver:2] ver:3 path:"/usr/bin/tool"];
  XCTAssertFalse(self.tree->ExportAnnotations(tool->pid_).has_value());
}

@end
