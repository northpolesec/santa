/// Copyright 2022 Google Inc. All rights reserved.
/// Copyright 2024 North Pole Security, Inc.
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

#import "Source/santad/SNTCompilerController.h"

#include <EndpointSecurity/EndpointSecurity.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <sys/clonefile.h>
#include <sys/stat.h>

#include <memory>

#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTFileInfo.h"
#import "Source/common/SNTRule.h"
#include "Source/common/String.h"
#include "Source/common/TelemetryEventMap.h"
#include "Source/common/TestUtils.h"
#include "Source/common/es/Message.h"
#include "Source/common/es/MockEndpointSecurityAPI.h"
#import "Source/santad/DataLayer/SNTRuleTable.h"
#include "Source/santad/Logs/EndpointSecurity/Logger.h"
#include "Source/santad/PendingExecCoordinator.h"
#import "Source/santad/SNTDatabaseController.h"
#import "Source/santad/SNTDecisionCache.h"

using santa::Logger;
using santa::Message;
using santa::PendingExecCoordinator;

static const pid_t PID_MAX = 99999;

@interface SNTCompilerController (Testing)
- (BOOL)isCompiler:(const audit_token_t&)tok;
- (SNTCachedDecision*)saveFakeDecision:(SNTFileInfo*)fileInfo;
- (void)removeFakeDecision:(SNTCachedDecision*)fakeDecision;
- (void)createTransitiveRule:(const Message&)esMsg
                      target:(SNTFileInfo*)targetFile
                      logger:(std::shared_ptr<Logger>)logger;
@end

@interface SNTCompilerControllerTest : XCTestCase
@property id mockDecisionCache;
@property audit_token_t tok1;
@property audit_token_t tok2;
@property audit_token_t tokNegativePid;
@property audit_token_t tokLargePid;
@end

@implementation SNTCompilerControllerTest

- (void)setUp {
  self.mockDecisionCache = OCMClassMock([SNTDecisionCache class]);
  OCMStub([self.mockDecisionCache sharedCache]).andReturn(self.mockDecisionCache);

  self.tok1 = MakeAuditToken(12, 11);
  self.tok2 = MakeAuditToken(34, 22);
  self.tokNegativePid = MakeAuditToken(-1, 33);
  self.tokLargePid = MakeAuditToken(PID_MAX + 1, 44);
}

- (void)tearDown {
  [self.mockDecisionCache stopMocking];
}

- (void)testIsCompiler {
  SNTCompilerController* cc = [[SNTCompilerController alloc] init];

  // Ensure invalid PIDs are handled
  XCTAssertFalse([cc isCompiler:self.tokNegativePid]);
  XCTAssertFalse([cc isCompiler:self.tokLargePid]);

  // Items in the compiler control cache are initially false
  XCTAssertFalse([cc isCompiler:self.tok1]);

  // Start tracking a process as a compiler
  [cc setProcess:self.tok1 isCompiler:true];
  XCTAssertTrue([cc isCompiler:self.tok1]);

  // Stop tracking a process as a compiler
  [cc setProcess:self.tok1 isCompiler:false];
  XCTAssertFalse([cc isCompiler:self.tok1]);
}

- (void)testIsCompilerChecksPidversion {
  SNTCompilerController* cc = [[SNTCompilerController alloc] init];

  // Register PID 12 with pidversion 11
  audit_token_t compilerTok = MakeAuditToken(12, 11);
  [cc setProcess:compilerTok isCompiler:true];
  XCTAssertTrue([cc isCompiler:compilerTok]);

  // Same PID, different pidversion (e.g. PID reuse after a missed EXIT, or the
  // process's pre-exec incarnation) is not the marked compiler.
  audit_token_t reusedTok = MakeAuditToken(12, 99);
  XCTAssertFalse([cc isCompiler:reusedTok]);

  // The mismatched check must not have cleared the mark: the original instance is
  // still recognized.
  XCTAssertTrue([cc isCompiler:compilerTok]);

  // Negative pidversion should work normally
  audit_token_t negPidverTok = MakeAuditToken(50, -1);
  [cc setProcess:negPidverTok isCompiler:true];
  XCTAssertTrue([cc isCompiler:negPidverTok]);

  // Same PID, different negative pidversion
  audit_token_t differentNegPidverTok = MakeAuditToken(50, -2);
  XCTAssertFalse([cc isCompiler:differentNegPidverTok]);

  // Again, the mark survives the mismatched check.
  XCTAssertTrue([cc isCompiler:negPidverTok]);
}

// Regression test for the transitive-allowlisting failure where a compiler's mark
// was destroyed before its own output close could be processed.
//
// A compiler is marked using the pidversion value the process has *after* its
// execve. The same PID also emits NOTIFY events from its pre-exec incarnation (the
// forked-but-not-yet-exec'd parent image), which carry an earlier pidversion. Those
// events are delivered on a separate, lower-priority notify client and can be
// processed *after* the mark is set. An isCompiler: check for the earlier
// pidversion must return NO without disturbing the mark; otherwise the compiler's
// real output close finds no mark and no transitive rule is created.
- (void)testIsCompilerMismatchDoesNotClearMark {
  SNTCompilerController* cc = [[SNTCompilerController alloc] init];

  // Compiler marked at its post-exec pidversion.
  audit_token_t markTok = MakeAuditToken(12, 100);
  [cc setProcess:markTok isCompiler:true];
  XCTAssertTrue([cc isCompiler:markTok]);

  // A close from the same PID's pre-exec incarnation (earlier pidversion) is not the
  // marked compiler, so it returns NO.
  audit_token_t preExecTok = MakeAuditToken(12, 99);
  XCTAssertFalse([cc isCompiler:preExecTok]);

  // Crucially, that mismatched check must not have cleared the mark: the compiler's
  // own subsequent events must still be recognized so its output gets a rule.
  XCTAssertTrue([cc isCompiler:markTok]);
}

- (void)testIsCompilerPidversionZeroEdgeCase {
  SNTCompilerController* cc = [[SNTCompilerController alloc] init];

  // Pidversion 0 is indistinguishable from "no compiler" — this is a known
  // false negative that requires ~2^32 forks to trigger. Verify the behavior.
  audit_token_t zeroPidverTok = MakeAuditToken(42, 0);
  [cc setProcess:zeroPidverTok isCompiler:true];
  XCTAssertFalse([cc isCompiler:zeroPidverTok]);
}

- (void)testSetProcessIsCompiler {
  SNTCompilerController* cc = [[SNTCompilerController alloc] init];

  // Ensure invalid PIDs are handled
  XCTAssertNoThrow([cc setProcess:self.tokNegativePid isCompiler:true]);
  XCTAssertNoThrow([cc setProcess:self.tokLargePid isCompiler:true]);

  // Ensure test tokens are initially false
  XCTAssertFalse([cc isCompiler:self.tok1]);
  XCTAssertFalse([cc isCompiler:self.tok2]);

  // Start tracking one of the toks
  [cc setProcess:self.tok1 isCompiler:true];
  XCTAssertTrue([cc isCompiler:self.tok1]);
  XCTAssertFalse([cc isCompiler:self.tok2]);

  // Start tracking both toks
  [cc setProcess:self.tok2 isCompiler:true];
  XCTAssertTrue([cc isCompiler:self.tok1]);
  XCTAssertTrue([cc isCompiler:self.tok2]);

  // Stop tracking one of the toks
  [cc setProcess:self.tok1 isCompiler:false];
  XCTAssertFalse([cc isCompiler:self.tok1]);
  XCTAssertTrue([cc isCompiler:self.tok2]);
}

- (void)testSaveFakeDecision {
  SantaVnode vnode{
      .fsid = 12,
      .fileid = 34,
  };
  SNTCachedDecision* existing = [[SNTCachedDecision alloc] initWithVnode:vnode];
  OCMStub([self.mockDecisionCache cachedDecisionForVnode:vnode]).andReturn(existing);

  OCMExpect([self.mockDecisionCache
                    cacheDecision:[OCMArg checkWithBlock:^BOOL(SNTCachedDecision* cd) {
                      return cd.vnodeId == vnode &&
                             cd.decision == SNTEventStateAllowPendingTransitive &&
                             [cd.sha256 isEqualToString:@"pending"];
                    }]
                replacingDecision:existing])
      .andReturn(YES);

  id mockFileInfo = OCMClassMock([SNTFileInfo class]);
  OCMStub([mockFileInfo vnode]).andReturn(vnode);

  SNTCompilerController* cc = [[SNTCompilerController alloc] init];
  SNTCachedDecision* fake = [cc saveFakeDecision:mockFileInfo];

  XCTAssertTrue(OCMVerifyAll(self.mockDecisionCache), "Unable to verify all expectations");
  XCTAssertEqual(fake.decision, SNTEventStateAllowPendingTransitive);
}

// The decision of an execution held for a transitive rule is left in place, so
// the Recorder keeps leaving that execution's logging to the hold.
- (void)testSaveFakeDecisionKeepsHeldDecision {
  SantaVnode vnode{
      .fsid = 12,
      .fileid = 34,
  };
  SNTCachedDecision* held = [[SNTCachedDecision alloc] initWithVnode:vnode];
  held.heldForTransitiveRule = YES;
  OCMStub([self.mockDecisionCache cachedDecisionForVnode:vnode]).andReturn(held);
  OCMReject([self.mockDecisionCache cacheDecision:OCMOCK_ANY replacingDecision:OCMOCK_ANY]);
  OCMReject([self.mockDecisionCache cacheDecision:OCMOCK_ANY]);

  id mockFileInfo = OCMClassMock([SNTFileInfo class]);
  OCMStub([mockFileInfo vnode]).andReturn(vnode);

  SNTCompilerController* cc = [[SNTCompilerController alloc] init];
  XCTAssertNil([cc saveFakeDecision:mockFileInfo]);
  OCMVerifyAll(self.mockDecisionCache);
}

- (void)testRemoveFakeDecision {
  SNTCachedDecision* fake = [[SNTCachedDecision alloc] init];
  OCMExpect([self.mockDecisionCache forgetCachedDecision:fake]);

  SNTCompilerController* cc = [[SNTCompilerController alloc] init];
  [cc removeFakeDecision:fake];

  XCTAssertTrue(OCMVerifyAll(self.mockDecisionCache), "Unable to verify all expectations");

  // Nothing was cached, so nothing is forgotten.
  OCMReject([self.mockDecisionCache forgetCachedDecision:OCMOCK_ANY]);
  [cc removeFakeDecision:nil];
  OCMVerifyAll(self.mockDecisionCache);
}

// Marking a compiler, and clearing that mark, is compiler activity. Clearing the
// slot of a process that was never a compiler, which every process exit does, is
// not.
- (void)testReportsCompilerActivity {
  auto coord = std::make_shared<PendingExecCoordinator>(/*window_ms=*/150);
  SNTCompilerController* cc = [[SNTCompilerController alloc] initWithPendingExecCoordinator:coord];

  [cc setProcess:self.tok1 isCompiler:false];
  XCTAssertFalse(coord->CompilerActiveRecently());

  // A compiler stays active however long it runs.
  [cc setProcess:self.tok1 isCompiler:true];
  [NSThread sleepForTimeInterval:0.25];
  XCTAssertTrue(coord->CompilerActiveRecently());

  // Its exit is activity too, which then lapses.
  [cc setProcess:self.tok1 isCompiler:false];
  XCTAssertTrue(coord->CompilerActiveRecently());
  [NSThread sleepForTimeInterval:0.25];
  XCTAssertFalse(coord->CompilerActiveRecently());

  // Clearing the slot again, as any later exit at that pid does, is not.
  [cc setProcess:self.tok1 isCompiler:false];
  XCTAssertFalse(coord->CompilerActiveRecently());
}

// Committing a transitive rule wakes an execution held for that content only.
- (void)testCreatingTransitiveRuleWakesWaiterForItsHash {
  id mockRuleTable = OCMClassMock([SNTRuleTable class]);
  OCMStub([mockRuleTable executionRuleForIdentifiers:(struct RuleIdentifiers){}])
      .ignoringNonObjectArgs()
      .andReturn(nil);
  OCMStub([mockRuleTable addExecutionRules:OCMOCK_ANY ruleCleanup:SNTRuleCleanupNone errors:nil])
      .ignoringNonObjectArgs()
      .andReturn(YES);
  id mockDatabaseController = OCMClassMock([SNTDatabaseController class]);
  OCMStub([mockDatabaseController ruleTable]).andReturn(mockRuleTable);

  NSString* sha256 = @"0000000000000000000000000000000000000000000000000000000000000001";
  id mockFileInfo = OCMClassMock([SNTFileInfo class]);
  OCMStub([mockFileInfo isExecutable]).andReturn(YES);
  OCMStub([mockFileInfo SHA256]).andReturn(sha256);
  OCMStub([mockFileInfo path]).andReturn(@"/tmp/out");

  auto coord = std::make_shared<PendingExecCoordinator>();
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  __block bool woken = false;
  coord->Wait(santa::NSStringToUTF8String(sha256), 5000, ^(bool ruleCreated) {
    woken = ruleCreated;
    dispatch_semaphore_signal(sema);
  });
  __block bool otherWoken = true;
  coord->Wait("other content", 100, ^(bool ruleCreated) {
    otherWoken = ruleCreated;
    dispatch_semaphore_signal(sema);
  });

  es_file_t file = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&file);
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_CLOSE, &proc);
  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsRetainReleaseMessage();
  auto logger = std::make_shared<Logger>(nullptr, nil, santa::TelemetryEvent::kNone, 0, 0, 0,
                                         nullptr, nullptr);

  SNTCompilerController* cc = [[SNTCompilerController alloc] initWithPendingExecCoordinator:coord];
  {
    Message msg(mockESApi, &esMsg);
    [cc createTransitiveRule:msg target:mockFileInfo logger:logger];
  }

  dispatch_time_t deadline = dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC);
  XCTAssertEqual(dispatch_semaphore_wait(sema, deadline), 0);
  XCTAssertEqual(dispatch_semaphore_wait(sema, deadline), 0);
  XCTAssertTrue(woken);
  XCTAssertFalse(otherWoken);

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
  [mockDatabaseController stopMocking];
  [mockRuleTable stopMocking];
  [mockFileInfo stopMocking];
}

- (void)testHandleEventWithLogger {
  es_file_t file = MakeESFile("foo");
  es_file_t ignoredFile = MakeESFile("/dev/bar");
  es_file_t normalFile = MakeESFile("bar");
  SantaVnode vnodeNormal = SantaVnode::VnodeForFile(&normalFile);
  audit_token_t compilerTok = MakeAuditToken(12, 34);
  audit_token_t notCompilerTok = MakeAuditToken(56, 78);
  es_process_t compilerProc = MakeESProcess(&file, compilerTok, {});
  es_process_t notCompilerProc = MakeESProcess(&file, notCompilerTok, {});
  es_message_t esMsg;

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsRetainReleaseMessage();

  SNTCompilerController* cc = [[SNTCompilerController alloc] init];

  // Mark a process as a compiler for use with these tests.
  [cc setProcess:compilerTok isCompiler:true];

  // Ensure unhandled event types return appropriately
  {
    esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_FORK, &notCompilerProc);
    Message msg(mockESApi, &esMsg);
    XCTAssertFalse([cc handleEvent:msg withLogger:nullptr]);
  }

  // Ensure non-compiler process events return false
  {
    esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_CLOSE, &notCompilerProc);
    Message msg(mockESApi, &esMsg);
    XCTAssertFalse([cc handleEvent:msg withLogger:nullptr]);
  }
  {
    esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_RENAME, &notCompilerProc);
    Message msg(mockESApi, &esMsg);
    XCTAssertFalse([cc handleEvent:msg withLogger:nullptr]);
  }
  {
    esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_CLONE, &notCompilerProc);
    Message msg(mockESApi, &esMsg);
    XCTAssertFalse([cc handleEvent:msg withLogger:nullptr]);
  }

  // Ensure compiler process events are only handled with non-ignored paths
  {
    esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_CLOSE, &compilerProc);
    esMsg.event.close.target = &ignoredFile;
    Message msg(mockESApi, &esMsg);
    XCTAssertFalse([cc handleEvent:msg withLogger:nullptr]);
  }
  {
    esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_RENAME, &compilerProc);
    esMsg.event.rename.source = &ignoredFile;
    Message msg(mockESApi, &esMsg);
    XCTAssertFalse([cc handleEvent:msg withLogger:nullptr]);
  }
  {
    esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_CLONE, &compilerProc);
    esMsg.event.clone.source = &ignoredFile;
    Message msg(mockESApi, &esMsg);
    XCTAssertFalse([cc handleEvent:msg withLogger:nullptr]);
  }

  // Ensure EXIT events stop tracking the process as a compiler
  {
    esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_EXIT, &compilerProc);
    Message msg(mockESApi, &esMsg);

    id mockCompilerController = OCMPartialMock(cc);
    OCMExpect([mockCompilerController setProcess:compilerProc.audit_token isCompiler:false]);

    XCTAssertTrue([cc handleEvent:msg withLogger:nullptr]);

    XCTAssertTrue(OCMVerifyAll(mockCompilerController), "Unable to verify all expectations");
    [mockCompilerController stopMocking];
  }

  // Ensure transitive rules are created when the given event is handled
  {
    esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_CLOSE, &compilerProc);
    esMsg.event.close.target = &normalFile;
    Message msg(mockESApi, &esMsg);

    id mockCompilerController = OCMPartialMock(cc);
    id mockFileInfo = OCMClassMock([SNTFileInfo class]);
    OCMStub([mockFileInfo alloc]).andReturn(mockFileInfo);
    OCMStub([mockFileInfo initWithEndpointSecurityFile:&normalFile error:[OCMArg anyObjectRef]])
        .ignoringNonObjectArgs()
        .andReturn(mockFileInfo);
    OCMStub([mockFileInfo vnode]).andReturn(vnodeNormal);

    OCMExpect([mockCompilerController
                  createTransitiveRule:msg
                                target:[OCMArg checkWithBlock:^BOOL(SNTFileInfo* fi) {
                                  return fi.vnode.fsid == normalFile.stat.st_dev &&
                                         fi.vnode.fileid == normalFile.stat.st_ino;
                                }]
                                logger:nullptr])
        .ignoringNonObjectArgs();

    XCTAssertTrue([cc handleEvent:msg withLogger:nullptr]);

    XCTAssertTrue(OCMVerifyAll(mockCompilerController), "Unable to verify all expectations");
    [mockCompilerController stopMocking];
    [mockFileInfo stopMocking];
  }
  // Ensure transitive rules are created for CLONE events from the source path
  {
    esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_CLONE, &compilerProc);
    esMsg.event.clone.source = &normalFile;
    Message msg(mockESApi, &esMsg);

    id mockCompilerController = OCMPartialMock(cc);
    id mockFileInfo = OCMClassMock([SNTFileInfo class]);
    OCMStub([mockFileInfo alloc]).andReturn(mockFileInfo);
    OCMStub([mockFileInfo initWithEndpointSecurityFile:&normalFile error:[OCMArg anyObjectRef]])
        .ignoringNonObjectArgs()
        .andReturn(mockFileInfo);
    OCMStub([mockFileInfo vnode]).andReturn(vnodeNormal);

    OCMExpect([mockCompilerController
                  createTransitiveRule:msg
                                target:[OCMArg checkWithBlock:^BOOL(SNTFileInfo* fi) {
                                  return fi.vnode.fsid == normalFile.stat.st_dev &&
                                         fi.vnode.fileid == normalFile.stat.st_ino;
                                }]
                                logger:nullptr])
        .ignoringNonObjectArgs();

    XCTAssertTrue([cc handleEvent:msg withLogger:nullptr]);

    XCTAssertTrue(OCMVerifyAll(mockCompilerController), "Unable to verify all expectations");
    [mockCompilerController stopMocking];
    [mockFileInfo stopMocking];
  }
}

- (void)testTransitiveRuleIsNotCreatedWhenIdentityIsUnconfirmed {
  // A transitive rule names a file by content hash, so it must not be written
  // from an unconfirmed read.
  es_file_t file = MakeESFile("foo");
  es_file_t normalFile = MakeESFile("bar");
  audit_token_t compilerTok = MakeAuditToken(12, 34);
  es_process_t compilerProc = MakeESProcess(&file, compilerTok, {});

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsRetainReleaseMessage();

  SNTCompilerController* cc = [[SNTCompilerController alloc] init];
  [cc setProcess:compilerTok isCompiler:true];

  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_CLOSE, &compilerProc);
  esMsg.event.close.target = &normalFile;
  Message msg(mockESApi, &esMsg);

  id mockCompilerController = OCMPartialMock(cc);
  id mockFileInfo = OCMClassMock([SNTFileInfo class]);
  OCMStub([mockFileInfo alloc]).andReturn(mockFileInfo);
  OCMStub([mockFileInfo initWithEndpointSecurityFile:&normalFile error:[OCMArg anyObjectRef]])
      .ignoringNonObjectArgs()
      .andReturn(mockFileInfo);
  OCMStub([mockFileInfo identityVerification]).andReturn(SNTFileInfoIdentityMismatch);

  OCMReject([mockCompilerController createTransitiveRule:msg target:OCMOCK_ANY logger:nullptr])
      .ignoringNonObjectArgs();

  XCTAssertFalse([cc handleEvent:msg withLogger:nullptr]);

  XCTAssertTrue(OCMVerifyAll(mockCompilerController), "Unable to verify all expectations");
  [mockCompilerController stopMocking];
  [mockFileInfo stopMocking];
}

#pragma mark RENAME and CLONE target resolution

- (NSString*)makeTempDir {
  NSString* dir = [NSTemporaryDirectory()
      stringByAppendingPathComponent:[NSString stringWithFormat:@"cc-rename-%@",
                                                                [[NSUUID UUID] UUIDString]]];
  XCTAssertTrue([[NSFileManager defaultManager] createDirectoryAtPath:dir
                                          withIntermediateDirectories:YES
                                                           attributes:nil
                                                                error:nil]);
  return dir;
}

- (struct stat)writeFile:(NSString*)path size:(NSUInteger)size fill:(uint8_t)fill {
  NSMutableData* data = [NSMutableData dataWithLength:size];
  memset(data.mutableBytes, fill, size);
  XCTAssertTrue([data writeToFile:path atomically:NO]);
  struct stat sb;
  XCTAssertEqual(stat(path.UTF8String, &sb), 0);
  return sb;
}

// Delivers `esMsg` from a compiler process and returns the file a transitive rule would be
// created for, or nil if none would be.
- (SNTFileInfo*)transitiveTargetForCompilerMessage:(es_message_t)esMsg {
  es_file_t procFile = MakeESFile("foo");
  audit_token_t compilerTok = MakeAuditToken(12, 34);
  es_process_t compilerProc = MakeESProcess(&procFile, compilerTok, {});
  esMsg.process = &compilerProc;

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsRetainReleaseMessage();

  SNTCompilerController* cc = [[SNTCompilerController alloc] init];
  [cc setProcess:compilerTok isCompiler:true];
  Message msg(mockESApi, &esMsg);

  __block SNTFileInfo* target;
  id mockCompilerController = OCMPartialMock(cc);
  OCMStub([mockCompilerController
              createTransitiveRule:msg
                            target:[OCMArg checkWithBlock:^BOOL(SNTFileInfo* fi) {
                              target = fi;
                              return YES;
                            }]
                            logger:nullptr])
      .ignoringNonObjectArgs();

  [cc handleEvent:msg withLogger:nullptr];

  [mockCompilerController stopMocking];
  return target;
}

// RENAME of `source` (described by `sourceStat`) to `dest`. `existingDestStat` describes the
// file `dest` replaced, or is NULL if `dest` was a new path.
- (SNTFileInfo*)transitiveTargetForRenameOf:(NSString*)source
                                       stat:(struct stat)sourceStat
                                         to:(NSString*)dest
                           existingDestStat:(const struct stat*)existingDestStat {
  es_file_t sourceFile = MakeESFile(source.UTF8String, sourceStat);
  es_file_t existingFile;
  es_file_t destDir;
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_RENAME, nullptr);
  esMsg.event.rename.source = &sourceFile;
  if (existingDestStat) {
    existingFile = MakeESFile(dest.UTF8String, *existingDestStat);
    esMsg.event.rename.destination_type = ES_DESTINATION_TYPE_EXISTING_FILE;
    esMsg.event.rename.destination.existing_file = &existingFile;
  } else {
    destDir = MakeESFile(dest.stringByDeletingLastPathComponent.UTF8String);
    esMsg.event.rename.destination_type = ES_DESTINATION_TYPE_NEW_PATH;
    esMsg.event.rename.destination.new_path.dir = &destDir;
    esMsg.event.rename.destination.new_path.filename =
        MakeESStringToken(dest.lastPathComponent.UTF8String);
  }
  return [self transitiveTargetForCompilerMessage:esMsg];
}

// CLONE of `source` (described by `sourceStat`) to the new path `dest`.
- (SNTFileInfo*)transitiveTargetForCloneOf:(NSString*)source
                                      stat:(struct stat)sourceStat
                                        to:(NSString*)dest {
  es_file_t sourceFile = MakeESFile(source.UTF8String, sourceStat);
  es_file_t destDir = MakeESFile(dest.stringByDeletingLastPathComponent.UTF8String);
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_CLONE, nullptr);
  esMsg.event.clone.source = &sourceFile;
  esMsg.event.clone.target_dir = &destDir;
  esMsg.event.clone.target_name = MakeESStringToken(dest.lastPathComponent.UTF8String);
  return [self transitiveTargetForCompilerMessage:esMsg];
}

- (void)testRenameHandledBeforeCompletionUsesSource {
  NSString* dir = [self makeTempDir];
  NSString* source = [dir stringByAppendingPathComponent:@"out.tmp"];
  NSString* dest = [dir stringByAppendingPathComponent:@"out"];
  struct stat sourceStat = [self writeFile:source size:1024 fill:'a'];
  struct stat destStat = [self writeFile:dest size:10024 fill:'b'];
  NSString* expected = [[SNTFileInfo alloc] initWithPath:source].SHA256;

  // The rename has not happened yet, so the source path still names the renamed file.
  SNTFileInfo* target = [self transitiveTargetForRenameOf:source
                                                     stat:sourceStat
                                                       to:dest
                                         existingDestStat:&destStat];

  XCTAssertEqualObjects(target.path, source);
  XCTAssertEqualObjects(target.SHA256, expected);
  [[NSFileManager defaultManager] removeItemAtPath:dir error:nil];
}

- (void)testRenameOverLargerExistingFileHashesRenamedFile {
  NSString* dir = [self makeTempDir];
  NSString* source = [dir stringByAppendingPathComponent:@"out.tmp"];
  NSString* dest = [dir stringByAppendingPathComponent:@"out"];
  struct stat sourceStat = [self writeFile:source size:1024 fill:'a'];
  struct stat destStat = [self writeFile:dest size:10024 fill:'b'];
  NSString* expected = [[SNTFileInfo alloc] initWithPath:source].SHA256;
  XCTAssertEqual(rename(source.UTF8String, dest.UTF8String), 0);

  // The replaced file's stat is larger than the renamed file. It must not be used to read
  // the file now at `dest`.
  SNTFileInfo* target = [self transitiveTargetForRenameOf:source
                                                     stat:sourceStat
                                                       to:dest
                                         existingDestStat:&destStat];

  XCTAssertEqualObjects(target.path, dest);
  XCTAssertEqual(target.identityVerification, SNTFileInfoIdentityVerified);
  XCTAssertEqualObjects(target.SHA256, expected);
  [[NSFileManager defaultManager] removeItemAtPath:dir error:nil];
}

- (void)testRenameToNewPathHashesRenamedFile {
  NSString* dir = [self makeTempDir];
  NSString* source = [dir stringByAppendingPathComponent:@"out.tmp"];
  NSString* dest = [dir stringByAppendingPathComponent:@"out"];
  struct stat sourceStat = [self writeFile:source size:1024 fill:'a'];
  NSString* expected = [[SNTFileInfo alloc] initWithPath:source].SHA256;
  XCTAssertEqual(rename(source.UTF8String, dest.UTF8String), 0);

  SNTFileInfo* target = [self transitiveTargetForRenameOf:source
                                                     stat:sourceStat
                                                       to:dest
                                         existingDestStat:NULL];

  XCTAssertEqualObjects(target.path, dest);
  XCTAssertEqualObjects(target.SHA256, expected);
  [[NSFileManager defaultManager] removeItemAtPath:dir error:nil];
}

- (void)testRenameSwapHashesRenamedFile {
  NSString* dir = [self makeTempDir];
  NSString* source = [dir stringByAppendingPathComponent:@"out.tmp"];
  NSString* dest = [dir stringByAppendingPathComponent:@"out"];
  struct stat sourceStat = [self writeFile:source size:1024 fill:'a'];
  struct stat destStat = [self writeFile:dest size:1024 fill:'b'];
  NSString* expected = [[SNTFileInfo alloc] initWithPath:source].SHA256;
  XCTAssertEqual(renamex_np(source.UTF8String, dest.UTF8String, RENAME_SWAP), 0);

  // After a swap the source path exists but holds the other file.
  SNTFileInfo* target = [self transitiveTargetForRenameOf:source
                                                     stat:sourceStat
                                                       to:dest
                                         existingDestStat:&destStat];

  XCTAssertEqualObjects(target.path, dest);
  XCTAssertEqualObjects(target.SHA256, expected);
  [[NSFileManager defaultManager] removeItemAtPath:dir error:nil];
}

- (void)testRenameCreatesNoRuleWhenRenamedFileWasReplaced {
  NSString* dir = [self makeTempDir];
  NSString* source = [dir stringByAppendingPathComponent:@"out.tmp"];
  NSString* dest = [dir stringByAppendingPathComponent:@"out"];
  NSString* other = [dir stringByAppendingPathComponent:@"other"];
  struct stat sourceStat = [self writeFile:source size:1024 fill:'a'];
  XCTAssertEqual(rename(source.UTF8String, dest.UTF8String), 0);

  // The file at `dest` is no longer the renamed file.
  [self writeFile:other size:1024 fill:'c'];
  XCTAssertEqual(rename(other.UTF8String, dest.UTF8String), 0);

  XCTAssertNil([self transitiveTargetForRenameOf:source
                                            stat:sourceStat
                                              to:dest
                                existingDestStat:NULL]);
  [[NSFileManager defaultManager] removeItemAtPath:dir error:nil];
}

- (void)testCloneFallsBackToTargetWhenSourceIsGone {
  NSString* dir = [self makeTempDir];
  NSString* source = [dir stringByAppendingPathComponent:@"cached"];
  NSString* dest = [dir stringByAppendingPathComponent:@"out"];
  struct stat sourceStat = [self writeFile:source size:1024 fill:'a'];
  NSString* expected = [[SNTFileInfo alloc] initWithPath:source].SHA256;
  XCTAssertEqual(clonefile(source.UTF8String, dest.UTF8String, 0), 0);
  XCTAssertEqual(unlink(source.UTF8String), 0);

  SNTFileInfo* target = [self transitiveTargetForCloneOf:source stat:sourceStat to:dest];

  XCTAssertEqualObjects(target.path, dest);
  XCTAssertEqualObjects(target.SHA256, expected);
  [[NSFileManager defaultManager] removeItemAtPath:dir error:nil];
}

- (void)testCloneCreatesNoRuleWhenTargetSizeDiffersFromSource {
  NSString* dir = [self makeTempDir];
  NSString* source = [dir stringByAppendingPathComponent:@"cached"];
  NSString* dest = [dir stringByAppendingPathComponent:@"out"];
  struct stat sourceStat = [self writeFile:source size:1024 fill:'a'];
  XCTAssertEqual(clonefile(source.UTF8String, dest.UTF8String, 0), 0);
  XCTAssertEqual(unlink(source.UTF8String), 0);

  // The file at `dest` is no longer the clone.
  XCTAssertEqual(unlink(dest.UTF8String), 0);
  [self writeFile:dest size:10024 fill:'c'];

  XCTAssertNil([self transitiveTargetForCloneOf:source stat:sourceStat to:dest]);
  [[NSFileManager defaultManager] removeItemAtPath:dir error:nil];
}

@end
