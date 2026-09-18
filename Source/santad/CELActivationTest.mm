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

#import "Source/santad/CELActivation.h"

#import <EndpointSecurity/EndpointSecurity.h>
#import <Foundation/Foundation.h>
#include <Kernel/kern/cs_blobs.h>
#import <XCTest/XCTest.h>

#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "Source/common/TestUtils.h"
#include "Source/common/cel/Activation.h"
#include "Source/common/cel/CELProtoTraits.h"
#include "Source/common/cel/Evaluator.h"
#include "Source/common/es/Message.h"
#include "Source/common/es/MockEndpointSecurityAPI.h"
#include "Source/common/processtree/SNTEndpointSecurityAdapter.h"
#include "Source/common/processtree/annotations/cel.h"
#include "Source/common/processtree/process.h"
#include "Source/common/processtree/process_tree_test_helpers.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"

using santa::Message;
using santa::santad::process_tree::CELAnnotator;
using santa::santad::process_tree::CodeSigningInfo;
using santa::santad::process_tree::Cred;
using santa::santad::process_tree::Pid;
using santa::santad::process_tree::ProcessTreeTestPeer;
using santa::santad::process_tree::Program;

namespace {

// Lowercase-hex encode without going through the code under test.
std::string HexEncode(const std::string& bytes) {
  static const char kHexDigits[] = "0123456789abcdef";
  std::string hex(bytes.size() * 2, '\0');
  for (size_t i = 0; i < bytes.size(); i++) {
    uint8_t b = static_cast<uint8_t>(bytes[i]);
    hex[2 * i] = kHexDigits[b >> 4];
    hex[2 * i + 1] = kHexDigits[b & 0x0f];
  }
  return hex;
}

// A distinctive CS_CDHASH_LEN-byte raw cdhash.
std::string MakeRawCDHash() {
  std::string raw(CS_CDHASH_LEN, '\0');
  for (size_t i = 0; i < raw.size(); i++) {
    raw[i] = static_cast<char>(0xA0 + i);
  }
  return raw;
}

}  // namespace

@interface CELActivationTest : XCTestCase
@end

@implementation CELActivationTest

// The process tree stores cdhash as raw bytes, but CEL exposes it as a hex
// string. CreateCELActivationBlock must hex-encode at the boundary so existing
// `ancestors[...].cdhash` rules keep matching.
- (void)testAncestorCDHashExposedAsHex {
  auto tree = std::make_shared<ProcessTreeTestPeer>(
      std::vector<std::unique_ptr<santa::santad::process_tree::Annotator>>{});
  auto init = tree->InsertInit();

  // Parent P: fork from init, then exec a code-signed binary whose cdhash is
  // stored as raw bytes (the new tree representation).
  Pid pPid = {.pid = 20, .pidversion = 1};
  tree->HandleFork(1, init, pPid);

  std::string rawCdhash = MakeRawCDHash();
  std::string expectedHex = HexEncode(rawCdhash);

  CodeSigningInfo cs;
  cs.cdhash = rawCdhash;
  cs.signing_id = "com.example.parent";
  cs.team_id = "TEAMID1234";
  cs.is_platform_binary = false;
  Pid pExecPid = {.pid = 20, .pidversion = 2};
  Program prog = {.executable = "/bin/parent", .arguments = {"/bin/parent"}, .code_signing = cs};
  tree->HandleExec(2, **tree->Get(pPid), pExecPid, prog, (Cred){.uid = 0, .gid = 0});

  // A child exec whose parent is P-after-exec drives the ancestors walk.
  es_file_t childFile = MakeESFile("/bin/child");
  es_process_t childProc = MakeESProcess(&childFile, MakeAuditToken(30, 1), MakeAuditToken(20, 2));
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_EXEC, &childProc);

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsRetainReleaseMessage();

  Message msg(mockESApi, &esMsg);
  ActivationCallbackBlock block = santa::CreateCELActivationBlock(
      msg, /*signingID=*/nil, /*teamID=*/nil, /*isPlatformBinary=*/NO, /*signingTime=*/nil,
      /*secureSigningTime=*/nil, /*entitlements=*/nil, tree);

  std::unique_ptr<::google::api::expr::runtime::BaseActivation> base = block(/*useV2=*/true);
  // block(useV2=true) always builds a concrete Activation<true>, so this
  // downcast is safe; the evaluator needs the concrete type.
  auto* activation = static_cast<santa::cel::Activation<true>*>(base.get());

  auto evaluator = santa::cel::Evaluator<true>::Create();
  XCTAssertTrue(evaluator.ok());

  std::string expr = "ancestors.exists(a, a.cdhash == '" + expectedHex + "')";
  auto result = evaluator.value()->CompileAndEvaluate(expr, *activation);
  XCTAssertTrue(result.ok());
  XCTAssertEqual(result.value().value, santa::cel::CELProtoTraits<true>::ReturnValue::ALLOWLIST);
}

// The exec ingest path (InformFromESEvent) must store the ES cdhash as raw
// bytes in the tree, not a hex string.
- (void)testExecIngestStoresRawCDHash {
  auto tree = std::make_shared<ProcessTreeTestPeer>(
      std::vector<std::unique_ptr<santa::santad::process_tree::Annotator>>{});
  auto init = tree->InsertInit();

  // Execing process E, forked from init and present in the tree.
  Pid ePid = {.pid = 10, .pidversion = 1};
  tree->HandleFork(1, init, ePid);

  es_file_t procFile = MakeESFile("/bin/e");
  es_process_t proc = MakeESProcess(&procFile, MakeAuditToken(10, 1), MakeAuditToken(1, 1));
  es_file_t targetFile = MakeESFile("/bin/t");
  es_process_t targetProc =
      MakeESProcess(&targetFile, MakeAuditToken(10, 2), MakeAuditToken(10, 1));
  targetProc.codesigning_flags = CS_SIGNED | CS_VALID;

  std::string rawCdhash = MakeRawCDHash();
  std::memcpy(targetProc.cdhash, rawCdhash.data(), CS_CDHASH_LEN);

  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_EXEC, &proc);
  esMsg.mach_time = 100;
  esMsg.event.exec.target = &targetProc;

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsRetainReleaseMessage();
  EXPECT_CALL(*mockESApi, ExecArgCount).WillRepeatedly(testing::Return(0));

  {
    Message msg(mockESApi, &esMsg);
    santa::santad::process_tree::InformFromESEvent(*tree, msg);
  }

  auto execd = tree->Get((Pid){.pid = 10, .pidversion = 2});
  XCTAssertTrue(execd.has_value());
  XCTAssertTrue((*execd)->program_->code_signing.has_value());
  const std::string& stored = (*execd)->program_->code_signing->cdhash;
  XCTAssertEqual(stored.size(), (size_t)CS_CDHASH_LEN);
  XCTAssertEqual(0, std::memcmp(stored.data(), rawCdhash.data(), CS_CDHASH_LEN));
}

// CreateCELActivationBlock hands `now` on to the activation it builds, which is
// what lets santad hold every window evaluation to the minimum believable time.
- (void)testCreateCELActivationBlockForwardsTheClock {
  es_file_t file = MakeESFile("/bin/ls");
  es_process_t proc = MakeESProcess(&file, MakeAuditToken(10, 1), MakeAuditToken(1, 1));
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_EXEC, &proc);

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsRetainReleaseMessage();
  Message msg(mockESApi, &esMsg);

  absl::Time provided;
  std::string parseErr;
  XCTAssertTrue(absl::ParseTime(absl::RFC3339_full, "2026-01-07T12:00:00Z", &provided, &parseErr));

  auto evaluator = santa::cel::Evaluator<true>::Create();
  XCTAssertTrue(evaluator.ok());

  ActivationCallbackBlock block = santa::CreateCELActivationBlock(
      msg, /*signingID=*/nil, /*teamID=*/nil, /*isPlatformBinary=*/NO, /*signingTime=*/nil,
      /*secureSigningTime=*/nil, /*entitlements=*/nil, /*processTree=*/nullptr,
      [provided] { return provided; });
  std::unique_ptr<::google::api::expr::runtime::BaseActivation> base = block(/*useV2=*/true);
  // block(useV2=true) always builds a concrete Activation<true>, and the
  // evaluator needs the concrete type.
  auto* activation = static_cast<santa::cel::Activation<true>*>(base.get());

  auto result = evaluator.value()->CompileAndEvaluate("now() == timestamp('2026-01-07T12:00:00Z')",
                                                      *activation);
  XCTAssertTrue(result.ok());
  XCTAssertEqual(result.value().value, santa::cel::CELProtoTraits<true>::ReturnValue::ALLOWLIST);
}

// add_annotation() and has_annotation() end to end against a real process tree:
// a rule on the tool stamps the annotation, and a fallback on a descendant's
// exec sees it. This is the ancestor-walk replacement the functions exist for.
- (void)testAnnotationsAcrossTheProcessTree {
  using ReturnValue = santa::cel::CELProtoTraits<true>::ReturnValue;

  // No registered annotators: CEL annotations inherit through
  // Annotator::Propagate, under the tree's write lock.
  auto tree = std::make_shared<ProcessTreeTestPeer>(
      std::vector<std::unique_ptr<santa::santad::process_tree::Annotator>>{});
  auto init = tree->InsertInit();

  const Cred cred = {.uid = 0, .gid = 0};
  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsRetainReleaseMessage();

  // An AUTH_EXEC activation for the process at `target`, which is what the
  // annotation hooks resolve against.
  auto evaluate = [&](Pid target, santa::cel::Evaluator<true>* evaluator, absl::string_view expr) {
    es_file_t procFile = MakeESFile("/bin/parent");
    es_process_t proc = MakeESProcess(&procFile, MakeAuditToken(1, 1), MakeAuditToken(1, 1));
    es_file_t targetFile = MakeESFile("/bin/target");
    es_process_t targetProc = MakeESProcess(
        &targetFile, MakeAuditToken(target.pid, (int)target.pidversion), MakeAuditToken(1, 1));
    es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_EXEC, &proc);
    esMsg.event.exec.target = &targetProc;

    Message msg(mockESApi, &esMsg);
    ActivationCallbackBlock block = santa::CreateCELActivationBlock(
        msg, /*signingID=*/nil, /*teamID=*/nil, /*isPlatformBinary=*/NO, /*signingTime=*/nil,
        /*secureSigningTime=*/nil, /*entitlements=*/nil, tree);
    std::unique_ptr<::google::api::expr::runtime::BaseActivation> base = block(/*useV2=*/true);
    return evaluator->CompileAndEvaluate(expr,
                                         *static_cast<santa::cel::Activation<true>*>(base.get()));
  };

  auto ruleEvaluator = santa::cel::Evaluator<true>::Create();
  XCTAssertTrue(ruleEvaluator.ok());
  auto fallbackEvaluator = santa::cel::Evaluator<true>::Create(/*allowUnspecified=*/true);
  XCTAssertTrue(fallbackEvaluator.ok());

  // The tool: init forks to 20.1, which execs to 20.2.
  Pid toolPid = {.pid = 20, .pidversion = 2};
  tree->HandleFork(1, init, (Pid){.pid = 20, .pidversion = 1});
  tree->HandleExec(2, **tree->Get((Pid){.pid = 20, .pidversion = 1}), toolPid,
                   (Program){.executable = "/bin/tool", .arguments = {}}, cred);

  {
    auto result = evaluate(toolPid, ruleEvaluator.value().get(),
                           "add_annotation('BAZEL-CALL', FORK_AND_EXEC, ALLOWLIST)");
    XCTAssertTrue(result.ok());
    XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
    // Otherwise the next exec of the same binary would skip the stamp entirely.
    XCTAssertFalse(result.value().cacheable);
  }

  auto annotation = tree->GetAnnotation<CELAnnotator>(**tree->Get(toolPid));
  XCTAssertTrue(annotation.has_value());
  XCTAssertTrue((*annotation)->Has("BAZEL-CALL"));

  // A descendant: the tool forks to 30.1, which execs to 30.2.
  Pid childPid = {.pid = 30, .pidversion = 2};
  tree->HandleFork(3, *tree->Get(toolPid), (Pid){.pid = 30, .pidversion = 1});
  tree->HandleExec(4, **tree->Get((Pid){.pid = 30, .pidversion = 1}), childPid,
                   (Program){.executable = "/bin/child", .arguments = {}}, cred);

  {
    auto result = evaluate(childPid, fallbackEvaluator.value().get(),
                           "has_annotation('BAZEL-CALL') ? ALLOWLIST_COMPILER : UNSPECIFIED");
    XCTAssertTrue(result.ok());
    XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST_COMPILER);
    XCTAssertFalse(result.value().cacheable);
  }

  // An unrelated process gets no decision from the same fallback.
  Pid strangerPid = {.pid = 40, .pidversion = 1};
  tree->HandleFork(5, init, strangerPid);
  {
    auto result = evaluate(strangerPid, fallbackEvaluator.value().get(),
                           "has_annotation('BAZEL-CALL') ? ALLOWLIST_COMPILER : UNSPECIFIED");
    XCTAssertTrue(result.ok());
    XCTAssertEqual(result.value().value, ReturnValue::UNSPECIFIED);
  }
}

@end
