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

#import "src/common/SNTKillCommand.h"

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#include "src/common/CodeSigningIdentifierUtils.h"

@interface SNTKillRequest (Testing)
- (instancetype)initWithUUID:(NSString *)uuid;
@end

@interface SNTKillCommandTest : XCTestCase
@end

@implementation SNTKillCommandTest

- (void)testSNTKillRequestEncodeDecode {
  NSString *uuid = [[NSUUID UUID] UUIDString];
  SNTKillRequest *request = [[SNTKillRequest alloc] initWithUUID:uuid];
  XCTAssertNotNil(request);
  XCTAssertEqualObjects(request.uuid, uuid);

  NSData *archived = [NSKeyedArchiver archivedDataWithRootObject:request
                                           requiringSecureCoding:YES
                                                           error:nil];
  XCTAssertNotNil(archived);

  SNTKillRequest *decoded = [NSKeyedUnarchiver unarchivedObjectOfClass:[SNTKillRequest class]
                                                              fromData:archived
                                                                 error:nil];
  XCTAssertNotNil(decoded);
  XCTAssertEqualObjects(decoded.uuid, uuid);
}

- (void)testSNTKillRequestRunningProcessValidInit {
  NSString *uuid = [[NSUUID UUID] UUIDString];
  NSString *bootUUID = @"2470862D-9913-4B95-A2BB-556EDC163069";
  NSString *bootUUIDWant = [[bootUUID stringByReplacingOccurrencesOfString:@"-"
                                                                withString:@""] lowercaseString];
  int pid = 1234;
  int pidversion = 5678;

  SNTKillRequestRunningProcess *request =
      [[SNTKillRequestRunningProcess alloc] initWithUUID:uuid
                                                     pid:pid
                                              pidversion:pidversion
                                         bootSessionUUID:bootUUID];
  XCTAssertNotNil(request);
  XCTAssertEqualObjects(request.uuid, uuid);
  XCTAssertEqual(request.pid, pid);
  XCTAssertEqual(request.pidversion, pidversion);
  XCTAssertEqualObjects(request.bootSessionUUID, bootUUIDWant);

  // Invalid pid
  request = [[SNTKillRequestRunningProcess alloc] initWithUUID:uuid
                                                           pid:0
                                                    pidversion:pidversion
                                               bootSessionUUID:bootUUID];

  XCTAssertNil(request);

  // Invalid pidversion
  request = [[SNTKillRequestRunningProcess alloc] initWithUUID:uuid
                                                           pid:pid
                                                    pidversion:0
                                               bootSessionUUID:bootUUID];
  XCTAssertNil(request);

  // Invalid boot UUID
  request = [[SNTKillRequestRunningProcess alloc] initWithUUID:uuid
                                                           pid:pid
                                                    pidversion:pidversion
                                               bootSessionUUID:@"not-a-uuid"];
  XCTAssertNil(request);

  // Shortened UUID is valid
  request = [[SNTKillRequestRunningProcess alloc] initWithUUID:uuid
                                                           pid:pid
                                                    pidversion:pidversion
                                               bootSessionUUID:[bootUUIDWant uppercaseString]];
  XCTAssertEqualObjects(request.bootSessionUUID, bootUUIDWant);

  // Encode/Decode
  request = [[SNTKillRequestRunningProcess alloc] initWithUUID:uuid
                                                           pid:pid
                                                    pidversion:pidversion
                                               bootSessionUUID:bootUUID];

  NSData *archived = [NSKeyedArchiver archivedDataWithRootObject:request
                                           requiringSecureCoding:YES
                                                           error:nil];
  XCTAssertNotNil(archived);

  SNTKillRequestRunningProcess *decoded =
      [NSKeyedUnarchiver unarchivedObjectOfClass:[SNTKillRequestRunningProcess class]
                                        fromData:archived
                                           error:nil];
  XCTAssertNotNil(decoded);
  XCTAssertEqualObjects(decoded.uuid, uuid);
  XCTAssertEqual(decoded.pid, pid);
  XCTAssertEqual(decoded.pidversion, pidversion);
  XCTAssertEqualObjects(decoded.bootSessionUUID, bootUUIDWant);
}

- (void)testSNTKillRequestCDHashValidInit {
  NSString *uuid = [[NSUUID UUID] UUIDString];
  NSString *cdhash = @"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0";

  SNTKillRequestCDHash *request = [[SNTKillRequestCDHash alloc] initWithUUID:uuid cdHash:cdhash];
  XCTAssertNotNil(request);
  XCTAssertEqualObjects(request.uuid, uuid);
  XCTAssertEqualObjects(request.cdhash, cdhash);

  // Test various invalid CDHashes
  NSArray *invalidCDHashes = @[
    @"",
    @"not-a-cdhash",
    @"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
    @"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0xxyyzz",
  ];

  for (NSString *invalidCDHash in invalidCDHashes) {
    SNTKillRequestCDHash *request = [[SNTKillRequestCDHash alloc] initWithUUID:uuid
                                                                        cdHash:invalidCDHash];
    XCTAssertNil(request);
  }

  // Encode / Decode {
  request = [[SNTKillRequestCDHash alloc] initWithUUID:uuid cdHash:cdhash];

  NSData *archived = [NSKeyedArchiver archivedDataWithRootObject:request
                                           requiringSecureCoding:YES
                                                           error:nil];
  XCTAssertNotNil(archived);

  SNTKillRequestCDHash *decoded =
      [NSKeyedUnarchiver unarchivedObjectOfClass:[SNTKillRequestCDHash class]
                                        fromData:archived
                                           error:nil];
  XCTAssertNotNil(decoded);
  XCTAssertEqualObjects(decoded.uuid, uuid);
  XCTAssertEqualObjects(decoded.cdhash, cdhash);
}

- (void)testSNTKillRequestSigningID {
  NSString *uuid = [[NSUUID UUID] UUIDString];
  NSString *teamIDsigningID = @"ABCDEFGHIJ:com.example.app";
  NSString *platformSigningID = @"platform:com.example.app";
  NSString *expectedTIDComponent = @"ABCDEFGHIJ";
  NSString *expectedPlatformTIDComponent = @"platform";
  NSString *expectedSIDComponent = @"com.example.app";

  // TeamID
  SNTKillRequestSigningID *request = [[SNTKillRequestSigningID alloc] initWithUUID:uuid
                                                                         signingID:teamIDsigningID];
  XCTAssertNotNil(request);
  XCTAssertEqualObjects(request.uuid, uuid);
  XCTAssertEqualObjects(request.signingID, expectedSIDComponent);
  XCTAssertEqualObjects(request.teamID, expectedTIDComponent);

  // Platform
  request = [[SNTKillRequestSigningID alloc] initWithUUID:uuid signingID:platformSigningID];
  XCTAssertNotNil(request);
  XCTAssertEqualObjects(request.signingID, expectedSIDComponent);
  XCTAssertEqualObjects(request.teamID, expectedPlatformTIDComponent);

  // Weird but valid ones
  NSArray *validSigningIDs = @[
    @"ABCDEFGHIJ:com:",
    @"ABCDEFGHIJ:com:example",
    @"ABCDEFGHIJ::",
    @"platform::",
    @"platform:com:example:with:more:components:",
  ];

  for (NSString *tidSid in validSigningIDs) {
    SNTKillRequestSigningID *request = [[SNTKillRequestSigningID alloc] initWithUUID:uuid
                                                                           signingID:tidSid];
    XCTAssertNotNil(request);
    XCTAssertEqualObjects(request.signingID, santa::SplitSigningID(tidSid).second);
  }

  // Invalid SIDs
  NSArray *invalidSigningIDs = @[
    @"",
    @":",
    @":com.example",
    @"ABCDEFGHIJ:",
    @"ABC:com.example",
  ];

  for (NSString *invalidSigningID in invalidSigningIDs) {
    SNTKillRequestSigningID *request =
        [[SNTKillRequestSigningID alloc] initWithUUID:uuid signingID:invalidSigningID];
    XCTAssertNil(request);
  }

  // Encode / Decode
  request = [[SNTKillRequestSigningID alloc] initWithUUID:uuid signingID:teamIDsigningID];

  NSData *archived = [NSKeyedArchiver archivedDataWithRootObject:request
                                           requiringSecureCoding:YES
                                                           error:nil];
  XCTAssertNotNil(archived);

  SNTKillRequestSigningID *decoded =
      [NSKeyedUnarchiver unarchivedObjectOfClass:[SNTKillRequestSigningID class]
                                        fromData:archived
                                           error:nil];

  XCTAssertNotNil(decoded);
  XCTAssertEqualObjects(decoded.uuid, uuid);
  XCTAssertEqualObjects(decoded.signingID, expectedSIDComponent);
  XCTAssertEqualObjects(decoded.teamID, expectedTIDComponent);
}

- (void)testSNTKillRequestTeamID {
  NSString *uuid = [[NSUUID UUID] UUIDString];
  NSString *teamID = @"ABCDEFGHIJ";

  SNTKillRequestTeamID *request = [[SNTKillRequestTeamID alloc] initWithUUID:uuid teamID:teamID];
  XCTAssertNotNil(request);
  XCTAssertEqualObjects(request.uuid, uuid);
  XCTAssertEqualObjects(request.teamID, teamID);

  // Uppercase values
  NSString *lowercaseTeamID = @"abcdefghij";

  request = [[SNTKillRequestTeamID alloc] initWithUUID:uuid teamID:lowercaseTeamID];
  XCTAssertNotNil(request);
  XCTAssertEqualObjects(request.teamID, teamID);

  // Invalid TIDs
  NSArray *invalidTeamIDs = @[
    @"",
    @"ABCDE",
    @"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    @"ABCD FGHIJ",
    @"ABCD-FGHIJ",
  ];

  for (NSString *invalidTeamID in invalidTeamIDs) {
    SNTKillRequestTeamID *request = [[SNTKillRequestTeamID alloc] initWithUUID:uuid
                                                                        teamID:invalidTeamID];
    XCTAssertNil(request, @"Should return nil for invalid team ID: %@", invalidTeamID);
  }

  // Encode / Decode
  request = [[SNTKillRequestTeamID alloc] initWithUUID:uuid teamID:teamID];
  NSData *archived = [NSKeyedArchiver archivedDataWithRootObject:request
                                           requiringSecureCoding:YES
                                                           error:nil];
  XCTAssertNotNil(archived);

  SNTKillRequestTeamID *decoded =
      [NSKeyedUnarchiver unarchivedObjectOfClass:[SNTKillRequestTeamID class]
                                        fromData:archived
                                           error:nil];
  XCTAssertNotNil(decoded);
  XCTAssertEqualObjects(decoded.uuid, uuid);
  XCTAssertEqualObjects(decoded.teamID, teamID);
}

- (void)testSNTKilledProcess {
  int pid = 1234;
  int pidversion = 5678;
  SNTKilledProcessError error = SNTKilledProcessErrorNone;
  SNTKilledProcess *killedProcess = [[SNTKilledProcess alloc] initWithPid:pid
                                                               pidversion:pidversion
                                                                    error:error];
  XCTAssertNotNil(killedProcess);
  XCTAssertEqual(killedProcess.pid, pid);
  XCTAssertEqual(killedProcess.pidversion, pidversion);
  XCTAssertEqual(killedProcess.error, error);

  // Encode / Decode
  error = SNTKilledProcessErrorNotPermitted;

  killedProcess = [[SNTKilledProcess alloc] initWithPid:pid pidversion:pidversion error:error];
  NSData *archived = [NSKeyedArchiver archivedDataWithRootObject:killedProcess
                                           requiringSecureCoding:YES
                                                           error:nil];
  XCTAssertNotNil(archived);

  SNTKilledProcess *decoded = [NSKeyedUnarchiver unarchivedObjectOfClass:[SNTKilledProcess class]
                                                                fromData:archived
                                                                   error:nil];
  XCTAssertNotNil(decoded);
  XCTAssertEqual(decoded.pid, pid);
  XCTAssertEqual(decoded.pidversion, pidversion);
  XCTAssertEqual(decoded.error, error);
}

- (void)testSNTKillResponseInitWithKilledProcesses {
  SNTKilledProcess *p1 = [[SNTKilledProcess alloc] initWithPid:1234
                                                    pidversion:5678
                                                         error:SNTKilledProcessErrorNone];
  SNTKilledProcess *p2 = [[SNTKilledProcess alloc] initWithPid:9999
                                                    pidversion:1111
                                                         error:SNTKilledProcessErrorNotPermitted];
  NSArray *killedProcesses = @[ p1, p2 ];

  SNTKillResponse *response = [[SNTKillResponse alloc] initWithKilledProcesses:killedProcesses];
  XCTAssertNotNil(response);
  XCTAssertEqual(response.error, SNTKillResponseErrorNone);
  XCTAssertEqual(response.killedProcesses.count, 2);
  XCTAssertEqual(response.killedProcesses[0].pid, 1234);
  XCTAssertEqual(response.killedProcesses[0].pidversion, 5678);
  XCTAssertEqual(response.killedProcesses[0].error, SNTKilledProcessErrorNone);
  XCTAssertEqual(response.killedProcesses[1].pid, 9999);
  XCTAssertEqual(response.killedProcesses[1].pidversion, 1111);
  XCTAssertEqual(response.killedProcesses[1].error, SNTKilledProcessErrorNotPermitted);

  // Init with error
  SNTKillResponseError error = SNTKillResponseErrorListPids;

  response = [[SNTKillResponse alloc] initWithError:error];
  XCTAssertNotNil(response);
  XCTAssertEqual(response.error, error);
  XCTAssertNil(response.killedProcesses);

  // Encode / Decode
  response = [[SNTKillResponse alloc] initWithError:error killedProcesses:killedProcesses];

  NSData *archived = [NSKeyedArchiver archivedDataWithRootObject:response
                                           requiringSecureCoding:YES
                                                           error:nil];
  XCTAssertNotNil(archived);

  SNTKillResponse *decoded = [NSKeyedUnarchiver
      unarchivedObjectOfClasses:[NSSet setWithObjects:[SNTKillResponse class], nil]
                       fromData:archived
                          error:nil];
  XCTAssertNotNil(decoded);
  XCTAssertEqual(decoded.error, error);
  XCTAssertEqual(decoded.killedProcesses.count, 2);
  XCTAssertEqual(decoded.killedProcesses[0].pid, 1234);
  XCTAssertEqual(decoded.killedProcesses[0].pidversion, 5678);
  XCTAssertEqual(decoded.killedProcesses[0].error, SNTKilledProcessErrorNone);
  XCTAssertEqual(decoded.killedProcesses[1].pid, 9999);
  XCTAssertEqual(decoded.killedProcesses[1].pidversion, 1111);
  XCTAssertEqual(decoded.killedProcesses[1].error, SNTKilledProcessErrorNotPermitted);

  // Encode / Decode with nil processes
  error = SNTKillResponseErrorListPids;
  response = [[SNTKillResponse alloc] initWithError:error];

  archived = [NSKeyedArchiver archivedDataWithRootObject:response
                                   requiringSecureCoding:YES
                                                   error:nil];
  XCTAssertNotNil(archived);

  decoded = [NSKeyedUnarchiver unarchivedObjectOfClass:[SNTKillResponse class]
                                              fromData:archived
                                                 error:nil];
  XCTAssertNotNil(decoded);
  XCTAssertEqual(decoded.error, error);
  XCTAssertNil(decoded.killedProcesses);
}

@end
