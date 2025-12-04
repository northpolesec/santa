/// Copyright 2025 North Pole Security, Inc.
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

/// This utility is used to generate a plist containing SNTStoredEvent objects.
/// The output can be used to update test input files, e.g.for "event upload" testing.
///
/// To run:
///   bazel run //Testing/OneOffs:stored_event_generator
///
/// This will put output in `/tmp/stored_event_archive.plist`
///
/// To convert the output to xml format for the sync tests:
///   plutil -convert xml1 -o my.plist /tmp/stored_event_archive.plist

#include <Foundation/Foundation.h>

#include <Kernel/kern/cs_blobs.h>

#include <cstdlib>

#include "Source/common/MOLCodesignChecker.h"
#include "Source/common/SNTCommonEnums.h"
#include "Source/common/SNTFileInfo.h"
#include "Source/common/SNTStoredExecutionEvent.h"
#include "Source/common/SNTStoredFileAccessEvent.h"
#include "Source/common/SNTStoredTemporaryMonitorModeAuditEvent.h"

static NSString *const kOutputPath = @"/tmp/stored_event_archive.plist";

void AddStoredExecutionEvents(NSMutableArray<SNTStoredEvent *> *storedEvents) {
  NSError *err;
  SNTFileInfo *fi = [[SNTFileInfo alloc] initWithPath:@"/usr/bin/yes" error:&err];
  if (!fi) {
    NSLog(@"Failed to grab file info for \"yes\": %@", err);
    exit(EXIT_FAILURE);
  }

  SNTStoredExecutionEvent *event = [[SNTStoredExecutionEvent alloc] initWithFileInfo:fi];
  event.occurrenceDate = [NSDate dateWithTimeIntervalSince1970:1751111111];
  event.needsBundleHash = NO;
  event.codesigningFlags = CS_PLATFORM_BINARY | CS_SIGNED | CS_HARD | CS_KILL | CS_VALID;
  event.signingStatus = SNTSigningStatusProduction;
  event.executingUser = @"foo";
  event.decision = SNTEventStateAllowSigningID;
  event.loggedInUsers = @[ @"foo", @"bar" ];
  event.currentSessions = @[ @"nobody@console" ];
  event.pid = @(2222);
  event.ppid = @(1);
  event.parentName = @"launchd";
  event.entitlements = @{@"ent1" : @"val1"};
  event.secureSigningTime = [NSDate dateWithTimeIntervalSince1970:1751421846];
  event.signingTime = [NSDate dateWithTimeIntervalSince1970:1751335446];
  [storedEvents addObject:event];

  fi = [[SNTFileInfo alloc] initWithPath:@"/Applications/Santa.app/Contents/MacOS/Santa"
                                   error:&err];
  if (!fi) {
    NSLog(@"Failed to grab file info for \"Santa\": %@", err);
    exit(EXIT_FAILURE);
  }

  event = [[SNTStoredExecutionEvent alloc] initWithFileInfo:fi];
  event.occurrenceDate = [NSDate dateWithTimeIntervalSince1970:1752222222];
  event.needsBundleHash = NO;
  event.codesigningFlags = CS_SIGNED | CS_HARD | CS_KILL | CS_VALID;
  event.signingStatus = SNTSigningStatusDevelopment;
  event.executingUser = @"foo2";
  event.decision = SNTEventStateAllowTeamID;
  event.loggedInUsers = @[ @"foo2", @"bar2" ];
  event.currentSessions = @[ @"nobody2@console" ];
  event.pid = @(3333);
  event.ppid = @(1111);
  event.parentName = @"init";
  event.entitlements = @{@"ent1" : @"val1", @"ent2" : @"val2"};
  event.secureSigningTime = [NSDate dateWithTimeIntervalSince1970:1748829846];
  event.signingTime = [NSDate dateWithTimeIntervalSince1970:1748743446];

  [storedEvents addObject:event];
}

void AddStoredFileAccessEvents(NSMutableArray<SNTStoredEvent *> *storedEvents) {
  NSError *err;
  SNTFileInfo *fi = [[SNTFileInfo alloc] initWithPath:@"/bin/mkdir" error:&err];
  if (!fi) {
    NSLog(@"Failed to grab file info for \"mkdir\": %@", err);
    exit(EXIT_FAILURE);
  }

  MOLCodesignChecker *csc = [fi codesignCheckerWithError:&err];
  if (!csc) {
    NSLog(@"Failed to grab codesign info for \"mkdir\": %@", err);
    exit(EXIT_FAILURE);
  }

  SNTStoredFileAccessEvent *faaEvent = [[SNTStoredFileAccessEvent alloc] init];
  faaEvent.occurrenceDate = [NSDate dateWithTimeIntervalSince1970:1753333333];
  faaEvent.ruleName = @"MyRule";
  faaEvent.ruleVersion = @"MyRuleVersion";
  faaEvent.accessedPath = @"/you/are/being/watched";
  faaEvent.decision = FileAccessPolicyDecision::kDenied;
  faaEvent.process.filePath = fi.path;
  faaEvent.process.fileSHA256 = fi.SHA256;
  faaEvent.process.cdhash = csc.cdhash;
  faaEvent.process.signingID = csc.signingID;
  faaEvent.process.signingChain = csc.certificates;
  faaEvent.process.teamID = csc.teamID;
  faaEvent.process.pid = @(123);
  faaEvent.process.executingUser = @"nobody";
  faaEvent.process.parent = [[SNTStoredFileAccessProcess alloc] init];
  faaEvent.process.parent.pid = @(456);

  [storedEvents addObject:faaEvent];
}

void AddStoredTemporaryMonitorModeAuditEvents(NSMutableArray<SNTStoredEvent *> *storedEvents) {
  // Audit event for "enter"
  [storedEvents addObject:[[SNTStoredTemporaryMonitorModeEnterAuditEvent alloc]
                              initWithUUID:@"my_test_enter_uuid"
                                   seconds:123
                                    reason:SNTTemporaryMonitorModeEnterReasonOnDemand]];

  // Audit event for "leave"
  [storedEvents addObject:[[SNTStoredTemporaryMonitorModeLeaveAuditEvent alloc]
                              initWithUUID:@"my_test_leave_uuid"
                                    reason:SNTTemporaryMonitorModeLeaveReasonRevoked]];
}

int main(int argc, const char *argv[]) {
  NSMutableArray<SNTStoredEvent *> *storedEvents = [[NSMutableArray alloc] init];

  AddStoredExecutionEvents(storedEvents);
  AddStoredFileAccessEvents(storedEvents);
  AddStoredTemporaryMonitorModeAuditEvents(storedEvents);

  NSError *err;
  NSData *data = [NSKeyedArchiver archivedDataWithRootObject:storedEvents
                                       requiringSecureCoding:YES
                                                       error:&err];
  if (!data) {
    NSLog(@"Failed to archive stored events: %@", err);
    exit(EXIT_FAILURE);
  }

  if (![data writeToFile:kOutputPath atomically:YES]) {
    NSLog(@"Failed to write archive to disk");
    exit(EXIT_FAILURE);
  }

  NSLog(@"Archived events to file: %@", kOutputPath);

  return 0;
}
