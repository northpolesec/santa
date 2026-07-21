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
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/santasyncservice/SNTPushNotifications.h"
#import "Source/santasyncservice/SNTSantaCommandHandler.h"
#import "Source/santasyncservice/SNTSyncCommands.h"
#import "Source/santasyncservice/SNTSyncState.h"

static NSString* const kMachineID = @"50C7E1EB-2EF5-42D4-A084-A7966FC45A95";

// Fake sync delegate that replies success to every event upload path.
@interface SNTSyncCommandsFakeSyncDelegate : NSObject <SNTPushNotificationsSyncDelegate>
@property(nonatomic) NSMutableArray<NSString*>* uploadedPaths;
@end

@implementation SNTSyncCommandsFakeSyncDelegate
- (instancetype)init {
  self = [super init];
  if (self) {
    _uploadedPaths = [NSMutableArray array];
  }
  return self;
}
- (void)sync {
}
- (void)syncSecondsFromNow:(uint64_t)seconds {
}
- (void)ruleSync {
}
- (void)ruleSyncSecondsFromNow:(uint64_t)seconds {
}
- (void)preflightSync {
}
- (void)pushNotificationSyncSecondsFromNow:(uint64_t)seconds {
}
- (MOLXPCConnection*)daemonConnection {
  return nil;
}
- (void)eventUploadForPaths:(NSArray<NSString*>*)paths reply:(void (^)(NSError* error))reply {
  [self.uploadedPaths addObjectsFromArray:paths];
  for (NSUInteger i = 0; i < paths.count; i++) {
    reply(nil);
  }
}
@end

@interface SNTSyncCommandsTest : XCTestCase
@property SNTSyncState* syncState;
@property id configMock;
@property SNTSyncCommandsFakeSyncDelegate* fakeSyncDelegate;
@property SNTSyncCommands* stage;
@end

@implementation SNTSyncCommandsTest

- (void)setUp {
  [super setUp];

  self.configMock = OCMClassMock([SNTConfigurator class]);
  OCMStub([self.configMock configurator]).andReturn(self.configMock);
  OCMStub([self.configMock syncEnableProtoTransfer]).andReturn(NO);

  self.syncState = [[SNTSyncState alloc] init];
  self.syncState.session = OCMClassMock([NSURLSession class]);
  self.syncState.syncBaseURL = [NSURL URLWithString:@"https://myserver.local/"];
  self.syncState.machineID = kMachineID;
  self.syncState.isSyncV2 = YES;

  self.fakeSyncDelegate = [[SNTSyncCommandsFakeSyncDelegate alloc] init];
  SNTSantaCommandHandler* handler =
      [[SNTSantaCommandHandler alloc] initWithSyncDelegate:self.fakeSyncDelegate];
  self.stage = [[SNTSyncCommands alloc] initWithState:self.syncState commandHandler:handler];
}

- (void)tearDown {
  [self.configMock stopMocking];
  [super tearDown];
}

#pragma mark Test Helpers

// Stub dataTaskWithRequest:completionHandler: to return `respData` for any
// request that `validateBlock` matches. See SNTSyncTest for the pattern.
- (void)stubRequestBody:(NSData*)respData
               response:(NSURLResponse*)resp
                  error:(NSError*)err
          validateBlock:(BOOL (^)(NSURLRequest* req))validateBlock {
  if (!respData) respData = (NSData*)[NSNull null];
  if (!resp) resp = [self responseWithCode:200];
  if (!err) err = (NSError*)[NSNull null];

  BOOL (^validateBlockWrapper)(id value) = ^BOOL(id value) {
    if (!validateBlock) return YES;
    return validateBlock((NSURLRequest*)value);
  };

  OCMStub([self.syncState.session
      dataTaskWithRequest:[OCMArg checkWithBlock:validateBlockWrapper]
        completionHandler:([OCMArg invokeBlockWithArgs:respData, resp, err, nil])]);
}

- (NSHTTPURLResponse*)responseWithCode:(NSInteger)code {
  return [[NSHTTPURLResponse alloc] initWithURL:[NSURL URLWithString:@"a"]
                                     statusCode:code
                                    HTTPVersion:@"1.1"
                                   headerFields:nil];
}

- (NSDictionary*)dictFromRequest:(NSURLRequest*)request {
  NSData* bod = [request HTTPBody];
  if (bod) return [NSJSONSerialization JSONObjectWithData:bod options:0 error:NULL];
  return nil;
}

- (NSData*)dataFromDict:(NSDictionary*)dict {
  return [NSJSONSerialization dataWithJSONObject:dict options:0 error:NULL];
}

// Returns the result dictionary from a CommandsRequest body, or nil if the
// request carried none. Field names are the proto3 JSON (camelCase) forms.
- (NSDictionary*)resultFromRequest:(NSURLRequest*)request {
  return [self dictFromRequest:request][@"result"];
}

#pragma mark Tests

- (void)testDrainEmptyQueue {
  __block NSUInteger requestCount = 0;
  [self stubRequestBody:[self dataFromDict:@{}]
               response:nil
                  error:nil
          validateBlock:^BOOL(NSURLRequest* req) {
            requestCount++;
            return YES;
          }];

  XCTAssertTrue([self.stage sync]);
  XCTAssertEqual(requestCount, 1u);
  XCTAssertEqual(self.fakeSyncDelegate.uploadedPaths.count, 0u);
}

- (void)testDrainSingleEventUploadCommand {
  // First exchange: no result posted -> server returns one queued command.
  [self
      stubRequestBody:[self dataFromDict:@{
        @"command" :
            @{@"commandId" : @"7", @"eventUpload" : @{@"paths" : @[ @"/Applications/Safari.app" ]}}
      }]
             response:nil
                error:nil
        validateBlock:^BOOL(NSURLRequest* req) {
          NSDictionary* dict = [self dictFromRequest:req];
          if (dict[@"result"]) return NO;
          XCTAssertEqualObjects(dict[@"machineId"], kMachineID);
          return YES;
        }];

  // Second exchange: ack-only DELIVERED result, posted before the upload runs.
  __block NSDictionary* deliveredResult = nil;
  __block NSUInteger pathsUploadedAtAck = NSUIntegerMax;
  [self stubRequestBody:[self dataFromDict:@{}]
               response:nil
                  error:nil
          validateBlock:^BOOL(NSURLRequest* req) {
            NSDictionary* result = [self resultFromRequest:req];
            if (![result[@"hostStatus"] isEqual:@"HOST_STATUS_DELIVERED"]) return NO;
            deliveredResult = result;
            pathsUploadedAtAck = self.fakeSyncDelegate.uploadedPaths.count;
            return YES;
          }];

  // Third exchange: the executed result is posted back -> queue is empty.
  __block NSDictionary* postedResult = nil;
  [self stubRequestBody:[self dataFromDict:@{}]
               response:nil
                  error:nil
          validateBlock:^BOOL(NSURLRequest* req) {
            NSDictionary* result = [self resultFromRequest:req];
            if (![result[@"hostStatus"] isEqual:@"HOST_STATUS_COMPLETE"]) return NO;
            postedResult = result;
            return YES;
          }];

  XCTAssertTrue([self.stage sync]);

  XCTAssertEqualObjects(self.fakeSyncDelegate.uploadedPaths, @[ @"/Applications/Safari.app" ]);
  // The DELIVERED ack carried no payload and preceded the upload.
  XCTAssertEqualObjects(deliveredResult[@"commandId"], @"7");
  XCTAssertNil(deliveredResult[@"eventUpload"]);
  XCTAssertEqual(pathsUploadedAtAck, 0u);
  XCTAssertEqualObjects(postedResult[@"commandId"], @"7");
  XCTAssertNotNil(postedResult[@"eventUpload"]);
}

- (void)testDrainMultipleCommandsSequentially {
  // No result -> command 1.
  [self
      stubRequestBody:[self dataFromDict:@{
        @"command" :
            @{@"commandId" : @"1", @"eventUpload" : @{@"paths" : @[ @"/Applications/Safari.app" ]}}
      }]
             response:nil
                error:nil
        validateBlock:^BOOL(NSURLRequest* req) {
          return [self resultFromRequest:req] == nil;
        }];

  // DELIVERED acks for both commands return no new command.
  __block NSMutableArray<NSString*>* ackedCommandIDs = [NSMutableArray array];
  [self stubRequestBody:[self dataFromDict:@{}]
               response:nil
                  error:nil
          validateBlock:^BOOL(NSURLRequest* req) {
            NSDictionary* result = [self resultFromRequest:req];
            if (![result[@"hostStatus"] isEqual:@"HOST_STATUS_DELIVERED"]) return NO;
            [ackedCommandIDs addObject:result[@"commandId"]];
            return YES;
          }];

  // COMPLETE result for command 1 -> command 2.
  [self stubRequestBody:[self dataFromDict:@{
          @"command" :
              @{@"commandId" : @"2", @"eventUpload" : @{@"paths" : @[ @"/Applications/Mail.app" ]}}
        }]
               response:nil
                  error:nil
          validateBlock:^BOOL(NSURLRequest* req) {
            NSDictionary* result = [self resultFromRequest:req];
            return [result[@"hostStatus"] isEqual:@"HOST_STATUS_COMPLETE"] &&
                   [result[@"commandId"] isEqual:@"1"];
          }];

  // COMPLETE result for command 2 -> queue drained.
  [self stubRequestBody:[self dataFromDict:@{}]
               response:nil
                  error:nil
          validateBlock:^BOOL(NSURLRequest* req) {
            NSDictionary* result = [self resultFromRequest:req];
            return [result[@"hostStatus"] isEqual:@"HOST_STATUS_COMPLETE"] &&
                   [result[@"commandId"] isEqual:@"2"];
          }];

  XCTAssertTrue([self.stage sync]);

  NSArray* expected = @[ @"/Applications/Safari.app", @"/Applications/Mail.app" ];
  XCTAssertEqualObjects(self.fakeSyncDelegate.uploadedPaths, expected,
                        @"Commands should execute serially, in delivery order");
  NSArray* expectedAcks = @[ @"1", @"2" ];
  XCTAssertEqualObjects(ackedCommandIDs, expectedAcks,
                        @"Each event upload should be acked DELIVERED before executing");
}

- (void)testCommandRejectedWhenNotAllowed {
  OCMStub([self.configMock allowedSantaCommands]).andReturn(@[ @"ping" ]);

  [self stubRequestBody:[self dataFromDict:@{
          @"command" : @{@"commandId" : @"5", @"kill" : @{@"team_id" : @"EQHXZ8M8AV"}}
        }]
               response:nil
                  error:nil
          validateBlock:^BOOL(NSURLRequest* req) {
            return [self resultFromRequest:req] == nil;
          }];

  __block NSDictionary* postedResult = nil;
  [self stubRequestBody:[self dataFromDict:@{}]
               response:nil
                  error:nil
          validateBlock:^BOOL(NSURLRequest* req) {
            NSDictionary* result = [self resultFromRequest:req];
            if (!result) return NO;
            postedResult = result;
            return YES;
          }];

  XCTAssertTrue([self.stage sync]);

  XCTAssertEqualObjects(postedResult[@"commandId"], @"5");
  XCTAssertEqualObjects(postedResult[@"hostStatus"], @"HOST_STATUS_REJECTED");
  XCTAssertEqual(self.fakeSyncDelegate.uploadedPaths.count, 0u);
}

- (void)testServerErrorFailsStage {
  // A non-retryable client error fails the stage. The manager treats this as
  // best-effort, so the failure never fails the sync itself.
  [self stubRequestBody:[self dataFromDict:@{}]
               response:[self responseWithCode:400]
                  error:nil
          validateBlock:nil];

  XCTAssertFalse([self.stage sync]);
  XCTAssertEqual(self.fakeSyncDelegate.uploadedPaths.count, 0u);
}

- (void)testDrainStopsAtCommandCap {
  // Server misbehaves and always returns a command. The stage must bail out
  // after its per-sync cap rather than looping forever.
  __block NSUInteger requestCount = 0;
  [self
      stubRequestBody:[self dataFromDict:@{
        @"command" :
            @{@"commandId" : @"1", @"eventUpload" : @{@"paths" : @[ @"/Applications/Safari.app" ]}}
      }]
             response:nil
                error:nil
        validateBlock:^BOOL(NSURLRequest* req) {
          requestCount++;
          return YES;
        }];

  XCTAssertTrue([self.stage sync]);

  // 50 commands executed: one initial fetch plus a DELIVERED ack and a
  // COMPLETE post per command. The stub also returns a command in response to
  // the acks; the stage must ignore ack response contents.
  XCTAssertEqual(self.fakeSyncDelegate.uploadedPaths.count, 50u);
  XCTAssertEqual(requestCount, 101u);
}

- (void)testEventUploadRejectedSkipsDeliveredAck {
  // A command the handler will reject must not be acked DELIVERED first —
  // DELIVERED means "will execute it".
  OCMStub([self.configMock allowedSantaCommands]).andReturn(@[ @"kill" ]);

  [self
      stubRequestBody:[self dataFromDict:@{
        @"command" :
            @{@"commandId" : @"9", @"eventUpload" : @{@"paths" : @[ @"/Applications/Safari.app" ]}}
      }]
             response:nil
                error:nil
        validateBlock:^BOOL(NSURLRequest* req) {
          return [self resultFromRequest:req] == nil;
        }];

  __block NSMutableArray<NSString*>* postedStatuses = [NSMutableArray array];
  [self stubRequestBody:[self dataFromDict:@{}]
               response:nil
                  error:nil
          validateBlock:^BOOL(NSURLRequest* req) {
            NSDictionary* result = [self resultFromRequest:req];
            if (!result) return NO;
            [postedStatuses addObject:result[@"hostStatus"]];
            return YES;
          }];

  XCTAssertTrue([self.stage sync]);

  XCTAssertEqualObjects(postedStatuses, @[ @"HOST_STATUS_REJECTED" ]);
  XCTAssertEqual(self.fakeSyncDelegate.uploadedPaths.count, 0u);
}

- (void)testKillSkipsDeliveredAck {
  // Kill is fast and posts straight to COMPLETE with no DELIVERED ack.
  [self stubRequestBody:[self dataFromDict:@{@"command" : @{@"commandId" : @"3", @"kill" : @{}}}]
               response:nil
                  error:nil
          validateBlock:^BOOL(NSURLRequest* req) {
            return [self resultFromRequest:req] == nil;
          }];

  __block NSMutableArray<NSString*>* postedStatuses = [NSMutableArray array];
  __block NSDictionary* postedResult = nil;
  [self stubRequestBody:[self dataFromDict:@{}]
               response:nil
                  error:nil
          validateBlock:^BOOL(NSURLRequest* req) {
            NSDictionary* result = [self resultFromRequest:req];
            if (!result) return NO;
            [postedStatuses addObject:result[@"hostStatus"]];
            postedResult = result;
            return YES;
          }];

  XCTAssertTrue([self.stage sync]);

  XCTAssertEqualObjects(postedStatuses, @[ @"HOST_STATUS_COMPLETE" ]);
  XCTAssertEqualObjects(postedResult[@"commandId"], @"3");
  XCTAssertNotNil(postedResult[@"kill"]);
}

- (void)testDeliveredAckFailureAbortsDrain {
  // If the DELIVERED ack cannot be posted, the command is never executed and
  // the drain aborts; the command stays queued server-side for the next sync.
  [self
      stubRequestBody:[self dataFromDict:@{
        @"command" :
            @{@"commandId" : @"7", @"eventUpload" : @{@"paths" : @[ @"/Applications/Safari.app" ]}}
      }]
             response:nil
                error:nil
        validateBlock:^BOOL(NSURLRequest* req) {
          return [self resultFromRequest:req] == nil;
        }];

  [self stubRequestBody:[self dataFromDict:@{}]
               response:[self responseWithCode:400]
                  error:nil
          validateBlock:^BOOL(NSURLRequest* req) {
            NSDictionary* result = [self resultFromRequest:req];
            return [result[@"hostStatus"] isEqual:@"HOST_STATUS_DELIVERED"];
          }];

  XCTAssertFalse([self.stage sync]);
  XCTAssertEqual(self.fakeSyncDelegate.uploadedPaths.count, 0u);
}

@end
