/// Copyright 2016 Google Inc. All rights reserved.
/// Copyright 2025 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///    http://www.apache.org/licenses/LICENSE-2.0
///
///    Unless required by applicable law or agreed to in writing, software
///    distributed under the License is distributed on an "AS IS" BASIS,
///    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
///    See the License for the specific language governing permissions and
///    limitations under the License.

#import <Foundation/Foundation.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTRule.h"
#import "Source/common/SNTSIPStatus.h"
#import "Source/common/SNTStoredEvent.h"
#import "Source/common/SNTStoredExecutionEvent.h"
#import "Source/common/SNTStoredFileAccessEvent.h"
#import "Source/common/SNTSyncConstants.h"
#import "Source/common/SNTSystemInfo.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/santasyncservice/SNTSyncEventUpload.h"
#import "Source/santasyncservice/SNTSyncPostflight.h"
#import "Source/santasyncservice/SNTSyncPreflight.h"
#import "Source/santasyncservice/SNTSyncRuleDownload.h"
#import "Source/santasyncservice/SNTSyncStage.h"
#import "Source/santasyncservice/SNTSyncState.h"

// Prevent Zlib compression during testing
@implementation NSData (Zlib)
- (NSData *)zlibCompressed {
  return nil;
}
- (NSData *)gzipCompressed {
  return nil;
}
@end

@interface SNTSyncStage (XSSI)
- (NSData *)stripXssi:(NSData *)data;
@end

@interface SNTSyncTest : XCTestCase
@property SNTSyncState *syncState;
@property id<SNTDaemonControlXPC> daemonConnRop;
@end

@implementation SNTSyncTest

- (void)setUp {
  [super setUp];

  self.syncState = [[SNTSyncState alloc] init];
  self.syncState.daemonConn = OCMClassMock([MOLXPCConnection class]);
  self.daemonConnRop = OCMProtocolMock(@protocol(SNTDaemonControlXPC));
  OCMStub([self.syncState.daemonConn remoteObjectProxy]).andReturn(self.daemonConnRop);
  OCMStub([self.syncState.daemonConn synchronousRemoteObjectProxy]).andReturn(self.daemonConnRop);

  id configMock = OCMClassMock([SNTConfigurator class]);
  OCMStub([configMock configurator]).andReturn(configMock);
  OCMStub([configMock syncEnableProtoTransfer]).andReturn(NO);

  id siMock = OCMClassMock([SNTSystemInfo class]);
  OCMStub([siMock serialNumber]).andReturn(@"QYGF4QM373");
  OCMStub([siMock longHostname]).andReturn(@"full-hostname.example.com");
  OCMStub([siMock osVersion]).andReturn(@"14.5");
  OCMStub([siMock osBuild]).andReturn(@"23F79");
  OCMStub([siMock modelIdentifier]).andReturn(@"MacBookPro18,3");
  OCMStub([siMock santaFullVersion]).andReturn(@"2024.6.655965194");

  id sipMock = OCMClassMock([SNTSIPStatus class]);
  OCMStub([sipMock currentStatus]).andReturn(0x6f);

  self.syncState.session = OCMClassMock([NSURLSession class]);

  self.syncState.syncBaseURL = [NSURL URLWithString:@"https://myserver.local/"];
  self.syncState.machineID = @"50C7E1EB-2EF5-42D4-A084-A7966FC45A95";
  self.syncState.machineOwner = @"username1";
}

#pragma mark Test Helpers

/**
  Stub out dataTaskWithRequest:completionHandler:

  @param respData The HTTP body to return.
  @param resp The NSHTTPURLResponse to return. If nil, a basic 200 response will be sent.
  @param err The error object to return to the handler.
  @param validateBlock Use to validate the request is the one intended to be stubbed.
      Returning NO means this stub is not applied.
*/
- (void)stubRequestBody:(NSData *)respData
               response:(NSURLResponse *)resp
                  error:(NSError *)err
          validateBlock:(BOOL (^)(NSURLRequest *req))validateBlock {
  if (!respData) respData = (NSData *)[NSNull null];
  if (!resp) resp = [self responseWithCode:200 headerDict:nil];
  if (!err) err = (NSError *)[NSNull null];

  // Cast the value into an NSURLRequest to save callers doing it.
  BOOL (^validateBlockWrapper)(id value) = ^BOOL(id value) {
    if (!validateBlock) return YES;
    NSURLRequest *req = (NSURLRequest *)value;
    return validateBlock(req);
  };

  OCMStub([self.syncState.session
      dataTaskWithRequest:[OCMArg checkWithBlock:validateBlockWrapper]
        completionHandler:([OCMArg invokeBlockWithArgs:respData, resp, err, nil])]);
}

/**
  Generate an NSHTTPURLResponse with the provided HTTP status code and header dictionary.

  @param code The HTTP status code for this response
  @param headerDict A dictionary of HTTP headers to add to the response.
  @returns An initialized NSHTTPURLResponse.
*/
- (NSHTTPURLResponse *)responseWithCode:(NSInteger)code headerDict:(NSDictionary *)headerDict {
  return [[NSHTTPURLResponse alloc] initWithURL:[NSURL URLWithString:@"a"]
                                     statusCode:code
                                    HTTPVersion:@"1.1"
                                   headerFields:headerDict];
}

/**
  Parses the JSON dictionary from the HTTP body of a request.

  @param request The request to parse the dictionary from.
  @returns The JSON dictionary or nil if parsing failed.
*/
- (NSDictionary *)dictFromRequest:(NSURLRequest *)request {
  NSData *bod = [request HTTPBody];
  if (bod) return [NSJSONSerialization JSONObjectWithData:bod options:0 error:NULL];
  return nil;
}

/**
  Generate a JSON data body from a dictionary

  @param dict, The dictionary of values
  @return A JSON-encoded representation of the dictionary as NSData
*/
- (NSData *)dataFromDict:(NSDictionary *)dict {
  return [NSJSONSerialization dataWithJSONObject:dict options:0 error:NULL];
}

/**
  Return data from a file in the Resources folder of the test bundle.

  @param file, The name of the file.
  @returns The contents of the named file, or nil.
*/
- (NSData *)dataFromFixture:(NSString *)file {
  NSString *path = [[NSBundle bundleForClass:[self class]] pathForResource:file ofType:nil];
  XCTAssertNotNil(path, @"failed to load testdata: %@", file);
  return [NSData dataWithContentsOfFile:path];
}

- (void)setupDefaultDaemonConnResponses {
  struct RuleCounts ruleCounts = {0};
  OCMStub([self.daemonConnRop
      databaseRuleCounts:([OCMArg invokeBlockWithArgs:OCMOCK_VALUE(ruleCounts), nil])]);
  OCMStub([self.daemonConnRop
      syncTypeRequired:([OCMArg invokeBlockWithArgs:OCMOCK_VALUE(SNTSyncTypeNormal), nil])]);
  OCMStub([self.daemonConnRop
      clientMode:([OCMArg invokeBlockWithArgs:OCMOCK_VALUE(SNTClientModeMonitor), nil])]);
  OCMStub([self.daemonConnRop databaseRulesHash:([OCMArg invokeBlockWithArgs:@"the-hash", nil])]);
}

#pragma mark - SNTSyncStage Tests

- (void)testStripXssi {
  SNTSyncStage *sut = [[SNTSyncStage alloc] initWithState:self.syncState];

  char wantChar[3] = {'"', 'a', '"'};
  NSData *want = [NSData dataWithBytes:wantChar length:3];

  char dOne[8] = {')', ']', '}', '\'', '\n', '"', 'a', '"'};
  XCTAssertEqualObjects([sut stripXssi:[NSData dataWithBytes:dOne length:8]], want, @"");

  char dTwo[6] = {']', ')', '}', '"', 'a', '"'};
  XCTAssertEqualObjects([sut stripXssi:[NSData dataWithBytes:dTwo length:6]], want, @"");

  char dThree[5] = {')', ']', '}', '\'', '\n'};
  XCTAssertEqualObjects([sut stripXssi:[NSData dataWithBytes:dThree length:5]], [NSData data], @"");

  char dFour[3] = {']', ')', '}'};
  XCTAssertEqualObjects([sut stripXssi:[NSData dataWithBytes:dFour length:3]], [NSData data], @"");

  XCTAssertEqualObjects([sut stripXssi:want], want, @"");
}

- (void)testBaseFetchXSRFTokenSuccess {
  // NOTE: This test only works if the other tests don't return a 403 and run before this test.
  // The XSRF fetching code is inside a dispatch_once.

  // Stub initial failing request
  NSURLResponse *resp = [self responseWithCode:403 headerDict:nil];
  [self stubRequestBody:nil
               response:resp
                  error:nil
          validateBlock:^BOOL(NSURLRequest *req) {
            return ([req.URL.absoluteString containsString:@"/a/"] &&
                    ![req valueForHTTPHeaderField:@"X-XSRF-TOKEN"]);
          }];

  // Stub XSRF token request
  resp = [self responseWithCode:200 headerDict:@{@"X-XSRF-TOKEN" : @"my-xsrf-token"}];
  [self stubRequestBody:nil
               response:resp
                  error:nil
          validateBlock:^BOOL(NSURLRequest *req) {
            return [req.URL.absoluteString containsString:@"/xsrf/"];
          }];

  // Stub succeeding request
  [self
      stubRequestBody:nil
             response:nil
                error:nil
        validateBlock:^BOOL(NSURLRequest *req) {
          return ([req.URL.absoluteString containsString:@"/a/"] &&
                  [[req valueForHTTPHeaderField:@"X-XSRF-TOKEN"] isEqualToString:@"my-xsrf-token"]);
        }];

  NSString *stageName = [@"a" stringByAppendingFormat:@"/%@", self.syncState.machineID];
  NSURL *u1 = [NSURL URLWithString:stageName relativeToURL:self.syncState.syncBaseURL];

  SNTSyncStage *sut = [[SNTSyncStage alloc] initWithState:self.syncState];
  NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:u1];
  XCTAssertNil([sut performRequest:req intoMessage:NULL timeout:5]);
  XCTAssertEqualObjects(self.syncState.xsrfToken, @"my-xsrf-token");
}

- (void)testBaseFetchXSRFTokenHeaderRedirect {
  // Stub initial failing request
  NSURLResponse *resp = [self responseWithCode:403 headerDict:nil];
  [self stubRequestBody:nil
               response:resp
                  error:nil
          validateBlock:^BOOL(NSURLRequest *req) {
            return ([req.URL.absoluteString containsString:@"/a/"] &&
                    ![req valueForHTTPHeaderField:@"X-Client-Xsrf-Token"]);
          }];

  // Stub XSRF token request
  resp = [self responseWithCode:200
                     headerDict:@{
                       @"X-XSRF-TOKEN" : @"my-xsrf-token",
                       @"X-XSRF-TOKEN-HEADER" : @"X-Client-Xsrf-Token",
                     }];
  [self stubRequestBody:nil
               response:resp
                  error:nil
          validateBlock:^BOOL(NSURLRequest *req) {
            return [req.URL.absoluteString containsString:@"/xsrf/"];
          }];

  // Stub succeeding request
  [self stubRequestBody:nil
               response:nil
                  error:nil
          validateBlock:^BOOL(NSURLRequest *req) {
            return ([req.URL.absoluteString containsString:@"/a/"] &&
                    [[req valueForHTTPHeaderField:@"X-CLIENT-XSRF-TOKEN"]
                        isEqualToString:@"my-xsrf-token"]);
          }];

  NSString *stageName = [@"a" stringByAppendingFormat:@"/%@", self.syncState.machineID];
  NSURL *u1 = [NSURL URLWithString:stageName relativeToURL:self.syncState.syncBaseURL];

  SNTSyncStage *sut = [[SNTSyncStage alloc] initWithState:self.syncState];
  NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:u1];
  XCTAssertNil([sut performRequest:req intoMessage:NULL timeout:5]);
  XCTAssertEqualObjects(self.syncState.xsrfToken, @"my-xsrf-token");
}

#pragma mark - SNTSyncPreflight Tests

- (void)testPreflightBasicResponse {
  [self setupDefaultDaemonConnResponses];
  SNTSyncPreflight *sut = [[SNTSyncPreflight alloc] initWithState:self.syncState];

  NSData *respData = [self dataFromFixture:@"sync_preflight_basic.json"];
  [self
      stubRequestBody:respData
             response:nil
                error:nil
        validateBlock:^BOOL(NSURLRequest *req) {
          NSData *gotReqData = [req HTTPBody];
          NSData *expectedReqData = [self dataFromFixture:@"sync_preflight_request.json"];

          NSString *gotReq = [[NSString alloc] initWithData:gotReqData
                                                   encoding:NSUTF8StringEncoding];
          NSString *expectedReq = [[NSString alloc] initWithData:expectedReqData
                                                        encoding:NSUTF8StringEncoding];

          XCTAssertEqualObjects(gotReq, expectedReq);
          XCTAssertEqualObjects([req valueForHTTPHeaderField:@"Content-Type"], @"application/json");
          return YES;
        }];

  XCTAssertTrue([sut sync]);
  XCTAssertEqual(self.syncState.clientMode, SNTClientModeMonitor);
  XCTAssertEqual(self.syncState.eventBatchSize, 100);
  XCTAssertNil(self.syncState.allowlistRegex);
  XCTAssertNil(self.syncState.blocklistRegex);
  XCTAssertNil(self.syncState.overrideFileAccessAction);
}

- (void)testPreflightTurnOnBlockUSBMount {
  [self setupDefaultDaemonConnResponses];
  SNTSyncPreflight *sut = [[SNTSyncPreflight alloc] initWithState:self.syncState];

  NSData *respData = [self dataFromFixture:@"sync_preflight_turn_on_blockusb.json"];
  [self stubRequestBody:respData response:nil error:nil validateBlock:nil];

  XCTAssertTrue([sut sync]);
  XCTAssertEqualObjects(self.syncState.blockUSBMount, @1);
  NSArray<NSString *> *wantRemountUSBMode = @[ @"rdonly", @"noexec" ];
  XCTAssertEqualObjects(self.syncState.remountUSBMode, wantRemountUSBMode);
}

- (void)testPreflightTurnOffBlockUSBMount {
  [self setupDefaultDaemonConnResponses];
  SNTSyncPreflight *sut = [[SNTSyncPreflight alloc] initWithState:self.syncState];

  NSData *respData = [self dataFromFixture:@"sync_preflight_turn_off_blockusb.json"];
  [self stubRequestBody:respData response:nil error:nil validateBlock:nil];

  XCTAssertTrue([sut sync]);
  XCTAssertEqualObjects(self.syncState.blockUSBMount, @0);
}

- (void)testPreflightBlockUSBMountAbsent {
  [self setupDefaultDaemonConnResponses];
  SNTSyncPreflight *sut = [[SNTSyncPreflight alloc] initWithState:self.syncState];

  NSData *respData = [self dataFromFixture:@"sync_preflight_blockusb_absent.json"];
  [self stubRequestBody:respData response:nil error:nil validateBlock:nil];

  XCTAssertTrue([sut sync]);
  XCTAssertNil(self.syncState.blockUSBMount);
}

- (void)testPreflightOverrideFileAccessAction {
  [self setupDefaultDaemonConnResponses];
  SNTSyncPreflight *sut = [[SNTSyncPreflight alloc] initWithState:self.syncState];

  NSData *respData = [@"{\"override_file_access_action\": \"AuditOnly\", \"client_mode\": "
                      @"\"LOCKDOWN\", \"batch_size\": 100}" dataUsingEncoding:NSUTF8StringEncoding];

  [self stubRequestBody:respData response:nil error:nil validateBlock:nil];

  XCTAssertTrue([sut sync]);
  XCTAssertEqualObjects(self.syncState.overrideFileAccessAction, @"AUDIT_ONLY");
}

- (void)testPreflightOverrideFileAccessActionAbsent {
  [self setupDefaultDaemonConnResponses];
  SNTSyncPreflight *sut = [[SNTSyncPreflight alloc] initWithState:self.syncState];

  NSData *respData = [@"{\"client_mode\": \"LOCKDOWN\", \"batch_size\": 100}"
      dataUsingEncoding:NSUTF8StringEncoding];

  [self stubRequestBody:respData response:nil error:nil validateBlock:nil];

  XCTAssertTrue([sut sync]);
  XCTAssertNil(self.syncState.overrideFileAccessAction);
}

- (void)testPreflightDatabaseCounts {
  SNTSyncPreflight *sut = [[SNTSyncPreflight alloc] initWithState:self.syncState];

  struct RuleCounts ruleCounts = {
      .binary = 5,
      .certificate = 8,
      .compiler = 2,
      .transitive = 19,
      .teamID = 3,
      .signingID = 123,
      .cdhash = 11,
  };

  OCMStub([self.daemonConnRop
      databaseRuleCounts:([OCMArg invokeBlockWithArgs:OCMOCK_VALUE(ruleCounts), nil])]);

  [self stubRequestBody:nil
               response:nil
                  error:nil
          validateBlock:^BOOL(NSURLRequest *req) {
            NSDictionary *requestDict = [self dictFromRequest:req];
            XCTAssertEqualObjects(requestDict[kCDHashRuleCount], @(ruleCounts.cdhash));
            XCTAssertEqualObjects(requestDict[kBinaryRuleCount], @(ruleCounts.binary));
            XCTAssertEqualObjects(requestDict[kCertificateRuleCount], @(ruleCounts.certificate));
            XCTAssertEqualObjects(requestDict[kCompilerRuleCount], @(ruleCounts.compiler));
            XCTAssertEqualObjects(requestDict[kTransitiveRuleCount], @(ruleCounts.transitive));
            XCTAssertEqualObjects(requestDict[kTeamIDRuleCount], @(ruleCounts.teamID));
            XCTAssertEqualObjects(requestDict[kSigningIDRuleCount], @(ruleCounts.signingID));
            return YES;
          }];

  [sut sync];
}

// This method is designed to help facilitate easy testing of many different
// permutations of clean sync request / response values and how syncType gets set.
- (void)cleanSyncPreflightRequiredSyncType:(SNTSyncType)requestedSyncType
                    expectcleanSyncRequest:(BOOL)expectcleanSyncRequest
                          expectedSyncType:(SNTSyncType)expectedSyncType
                                  response:(NSDictionary *)resp {
  SNTSyncPreflight *sut = [[SNTSyncPreflight alloc] initWithState:self.syncState];

  struct RuleCounts ruleCounts = {0};
  OCMStub([self.daemonConnRop
      databaseRuleCounts:([OCMArg invokeBlockWithArgs:OCMOCK_VALUE(ruleCounts), nil])]);
  OCMStub([self.daemonConnRop
      clientMode:([OCMArg invokeBlockWithArgs:OCMOCK_VALUE(SNTClientModeMonitor), nil])]);
  OCMStub([self.daemonConnRop
      syncTypeRequired:([OCMArg invokeBlockWithArgs:OCMOCK_VALUE(requestedSyncType), nil])]);

  NSData *respData = [self dataFromDict:resp];
  [self stubRequestBody:respData
               response:nil
                  error:nil
          validateBlock:^BOOL(NSURLRequest *req) {
            NSDictionary *requestDict = [self dictFromRequest:req];
            if (expectcleanSyncRequest) {
              XCTAssertEqualObjects(requestDict[kRequestCleanSync], @YES);
            } else {
              XCTAssertNil(requestDict[kRequestCleanSync]);
            }
            return YES;
          }];

  [sut sync];

  XCTAssertEqual(self.syncState.syncType, expectedSyncType);
}

- (void)testPreflightStateNormalRequestEmptyResponseEmpty {
  [self cleanSyncPreflightRequiredSyncType:SNTSyncTypeNormal
                    expectcleanSyncRequest:NO
                          expectedSyncType:SNTSyncTypeNormal
                                  response:@{}];
}

- (void)testPreflightStateNormalRequestEmptyResponseNormalDeprecated {
  [self cleanSyncPreflightRequiredSyncType:SNTSyncTypeNormal
                    expectcleanSyncRequest:NO
                          expectedSyncType:SNTSyncTypeNormal
                                  response:@{kSyncType : @"normal"}];
}

- (void)testPreflightStateNormalRequestEmptyResponseNormal {
  [self cleanSyncPreflightRequiredSyncType:SNTSyncTypeNormal
                    expectcleanSyncRequest:NO
                          expectedSyncType:SNTSyncTypeNormal
                                  response:@{kSyncType : @"NORMAL"}];
}

- (void)testPreflightStateNormalRequestEmptyResponseCleanDeprecated {
  [self cleanSyncPreflightRequiredSyncType:SNTSyncTypeNormal
                    expectcleanSyncRequest:NO
                          expectedSyncType:SNTSyncTypeClean
                                  response:@{kSyncType : @"clean"}];
}

- (void)testPreflightStateNormalRequestEmptyResponseClean {
  [self cleanSyncPreflightRequiredSyncType:SNTSyncTypeNormal
                    expectcleanSyncRequest:NO
                          expectedSyncType:SNTSyncTypeClean
                                  response:@{kSyncType : @"CLEAN"}];
}

- (void)testPreflightStateNormalRequestEmptyResponseCleanAllDeprecated {
  [self cleanSyncPreflightRequiredSyncType:SNTSyncTypeNormal
                    expectcleanSyncRequest:NO
                          expectedSyncType:SNTSyncTypeCleanAll
                                  response:@{kSyncType : @"clean_all"}];
}

- (void)testPreflightStateNormalRequestEmptyResponseCleanAll {
  [self cleanSyncPreflightRequiredSyncType:SNTSyncTypeNormal
                    expectcleanSyncRequest:NO
                          expectedSyncType:SNTSyncTypeCleanAll
                                  response:@{kSyncType : @"CLEAN_ALL"}];
}

- (void)testPreflightStateNormalRequestEmptyResponseCleanDep {
  [self cleanSyncPreflightRequiredSyncType:SNTSyncTypeNormal
                    expectcleanSyncRequest:NO
                          expectedSyncType:SNTSyncTypeClean
                                  response:@{kCleanSyncDeprecated : @YES}];
}

- (void)testPreflightStateCleanRequestCleanResponseEmpty {
  [self cleanSyncPreflightRequiredSyncType:SNTSyncTypeClean
                    expectcleanSyncRequest:YES
                          expectedSyncType:SNTSyncTypeNormal
                                  response:@{}];
}

- (void)testPreflightStateCleanRequestCleanResponseNormalDeprecated {
  [self cleanSyncPreflightRequiredSyncType:SNTSyncTypeClean
                    expectcleanSyncRequest:YES
                          expectedSyncType:SNTSyncTypeNormal
                                  response:@{kSyncType : @"normal"}];
}

- (void)testPreflightStateCleanRequestCleanResponseNormal {
  [self cleanSyncPreflightRequiredSyncType:SNTSyncTypeClean
                    expectcleanSyncRequest:YES
                          expectedSyncType:SNTSyncTypeNormal
                                  response:@{kSyncType : @"NORMAL"}];
}

- (void)testPreflightStateCleanRequestCleanResponseCleanDeprecated {
  [self cleanSyncPreflightRequiredSyncType:SNTSyncTypeClean
                    expectcleanSyncRequest:YES
                          expectedSyncType:SNTSyncTypeClean
                                  response:@{kSyncType : @"clean"}];
}

- (void)testPreflightStateCleanRequestCleanResponseClean {
  [self cleanSyncPreflightRequiredSyncType:SNTSyncTypeClean
                    expectcleanSyncRequest:YES
                          expectedSyncType:SNTSyncTypeClean
                                  response:@{kSyncType : @"CLEAN"}];
}

- (void)testPreflightStateCleanRequestCleanResponseCleanAllDeprecated {
  [self cleanSyncPreflightRequiredSyncType:SNTSyncTypeClean
                    expectcleanSyncRequest:YES
                          expectedSyncType:SNTSyncTypeCleanAll
                                  response:@{kSyncType : @"clean_all"}];
}

- (void)testPreflightStateCleanRequestCleanResponseCleanAll {
  [self cleanSyncPreflightRequiredSyncType:SNTSyncTypeClean
                    expectcleanSyncRequest:YES
                          expectedSyncType:SNTSyncTypeCleanAll
                                  response:@{kSyncType : @"CLEAN_ALL"}];
}

- (void)testPreflightStateCleanRequestCleanResponseCleanDep {
  [self cleanSyncPreflightRequiredSyncType:SNTSyncTypeClean
                    expectcleanSyncRequest:YES
                          expectedSyncType:SNTSyncTypeClean
                                  response:@{kCleanSyncDeprecated : @YES}];
}

- (void)testPreflightStateCleanAllRequestCleanResponseEmpty {
  [self cleanSyncPreflightRequiredSyncType:SNTSyncTypeCleanAll
                    expectcleanSyncRequest:YES
                          expectedSyncType:SNTSyncTypeNormal
                                  response:@{}];
}

- (void)testPreflightStateCleanAllRequestCleanResponseNormalDeprecated {
  [self cleanSyncPreflightRequiredSyncType:SNTSyncTypeCleanAll
                    expectcleanSyncRequest:YES
                          expectedSyncType:SNTSyncTypeNormal
                                  response:@{kSyncType : @"normal"}];
}

- (void)testPreflightStateCleanAllRequestCleanResponseNormal {
  [self cleanSyncPreflightRequiredSyncType:SNTSyncTypeCleanAll
                    expectcleanSyncRequest:YES
                          expectedSyncType:SNTSyncTypeNormal
                                  response:@{kSyncType : @"NORMAL"}];
}

- (void)testPreflightStateCleanAllRequestCleanResponseCleanDeprecated {
  [self cleanSyncPreflightRequiredSyncType:SNTSyncTypeCleanAll
                    expectcleanSyncRequest:YES
                          expectedSyncType:SNTSyncTypeCleanAll
                                  response:@{kSyncType : @"clean"}];
}

- (void)testPreflightStateCleanAllRequestCleanResponseClean {
  [self cleanSyncPreflightRequiredSyncType:SNTSyncTypeCleanAll
                    expectcleanSyncRequest:YES
                          expectedSyncType:SNTSyncTypeCleanAll
                                  response:@{kSyncType : @"CLEAN"}];
}

- (void)testPreflightStateCleanAllRequestCleanResponseCleanAllDeprecated {
  [self cleanSyncPreflightRequiredSyncType:SNTSyncTypeCleanAll
                    expectcleanSyncRequest:YES
                          expectedSyncType:SNTSyncTypeCleanAll
                                  response:@{kSyncType : @"clean_all"}];
}

- (void)testPreflightStateCleanAllRequestCleanResponseCleanAll {
  [self cleanSyncPreflightRequiredSyncType:SNTSyncTypeCleanAll
                    expectcleanSyncRequest:YES
                          expectedSyncType:SNTSyncTypeCleanAll
                                  response:@{kSyncType : @"CLEAN_ALL"}];
}

- (void)testPreflightStateCleanAllRequestCleanResponseCleanDep {
  [self cleanSyncPreflightRequiredSyncType:SNTSyncTypeCleanAll
                    expectcleanSyncRequest:YES
                          expectedSyncType:SNTSyncTypeCleanAll
                                  response:@{kCleanSyncDeprecated : @YES}];
}

- (void)testPreflightStateNormalRequestNormalResponseCleanDep {
  [self cleanSyncPreflightRequiredSyncType:SNTSyncTypeNormal
                    expectcleanSyncRequest:NO
                          expectedSyncType:SNTSyncTypeNormal
                                  response:@{kCleanSyncDeprecated : @NO}];
}

- (void)testPreflightStateCleanAllRequestCleanResponseUnknown {
  [self cleanSyncPreflightRequiredSyncType:SNTSyncTypeCleanAll
                    expectcleanSyncRequest:YES
                          expectedSyncType:SNTSyncTypeNormal
                                  response:@{kSyncType : @"foo"}];
}

- (void)testPreflightStateCleanAllRequestCleanResponseTypeAndDepMismatch {
  // Note: The kSyncType key takes precedence over kCleanSyncDeprecated if both are set
  [self cleanSyncPreflightRequiredSyncType:SNTSyncTypeCleanAll
                    expectcleanSyncRequest:YES
                          expectedSyncType:SNTSyncTypeNormal
                                  response:@{kSyncType : @"NORMAL", kCleanSyncDeprecated : @YES}];
}

- (void)testPreflightLockdown {
  [self setupDefaultDaemonConnResponses];
  SNTSyncPreflight *sut = [[SNTSyncPreflight alloc] initWithState:self.syncState];

  NSData *respData = [self dataFromFixture:@"sync_preflight_lockdown.json"];
  [self stubRequestBody:respData response:nil error:nil validateBlock:nil];

  [sut sync];

  XCTAssertEqual(self.syncState.clientMode, SNTClientModeLockdown);
}

- (void)testPreflightStandalone {
  [self setupDefaultDaemonConnResponses];
  SNTSyncPreflight *sut = [[SNTSyncPreflight alloc] initWithState:self.syncState];

  NSData *respData = [self dataFromFixture:@"sync_preflight_standalone.json"];
  [self stubRequestBody:respData response:nil error:nil validateBlock:nil];

  [sut sync];

  XCTAssertEqual(self.syncState.clientMode, SNTClientModeStandalone);
}

#pragma mark - SNTSyncEventUpload Tests

- (void)testEventUploadBasic {
  SNTSyncEventUpload *sut = [[SNTSyncEventUpload alloc] initWithState:self.syncState];
  self.syncState.eventBatchSize = 50;

  NSSet *allowedClasses = [NSSet setWithObjects:[NSArray class], [SNTStoredEvent class], nil];

  NSData *eventData = [self dataFromFixture:@"sync_eventupload_input_basic.plist"];

  NSError *err;
  NSArray *events = [NSKeyedUnarchiver unarchivedObjectOfClasses:allowedClasses
                                                        fromData:eventData
                                                           error:&err];
  XCTAssertNil(err);

  OCMStub([self.daemonConnRop databaseEventsPending:([OCMArg invokeBlockWithArgs:events, nil])]);

  [self stubRequestBody:nil
               response:nil
                  error:nil
          validateBlock:^BOOL(NSURLRequest *req) {
            NSDictionary *requestDict = [self dictFromRequest:req];
            NSArray *events = requestDict[kEvents];

            XCTAssertEqual(events.count, 2);

            NSDictionary *event = events[0];
            XCTAssertEqualObjects(
                event[kFileSHA256],
                @"741879b35b9fae5b235a7c9a88a6d20a136c6e27701f03dd32369c4ea0a6acaf");
            XCTAssertEqualObjects(event[kFileName], @"yes");
            XCTAssertEqualObjects(event[kFilePath], @"/usr/bin");
            XCTAssertEqualObjects(event[kDecision], @"ALLOW_SIGNINGID");
            XCTAssertEqualObjects(event[kCurrentSessions], @[ @"nobody@console" ]);
            XCTAssertEqualObjects(event[kLoggedInUsers], (@[ @"foo", @"bar" ]));
            XCTAssertEqualObjects(event[kExecutingUser], @"foo");
            XCTAssertEqualObjects(event[kPID], @(2222));
            XCTAssertEqualObjects(event[kPPID], @(1));
            XCTAssertEqualObjects(event[kExecutionTime], @(1753128415.67169));

            NSArray *certs = event[kSigningChain];
            XCTAssertEqual(certs.count, 3);

            NSDictionary *cert = [certs firstObject];
            XCTAssertEqualObjects(
                cert[kCertSHA256],
                @"d84db96af8c2e60ac4c851a21ec460f6f84e0235beb17d24a78712b9b021ed57");
            XCTAssertEqualObjects(cert[kCertCN], @"Software Signing");
            XCTAssertEqualObjects(cert[kCertOrg], @"Apple Inc.");
            XCTAssertEqualObjects(cert[kCertOU], @"Apple Software");
            XCTAssertEqualObjects(cert[kCertValidFrom], @(1603996358));
            XCTAssertEqualObjects(cert[kCertValidUntil], @(1792863581));

            XCTAssertNil(event[kTeamID]);
            XCTAssertEqualObjects(event[kSigningID], @"platform:com.apple.yes");
            XCTAssertEqualObjects(event[kCDHash], @"18ddebfdb356b7ed575b063bbbbe40a2d0d92f23");

            event = events[1];
            XCTAssertEqualObjects(event[kFileName], @"Santa");
            XCTAssertEqualObjects(event[kExecutingUser], @"foo2");
            certs = event[kSigningChain];
            XCTAssertEqual(certs.count, 3);
            XCTAssertEqualObjects(event[kTeamID], @"ZMCG7MLDV9");
            XCTAssertEqualObjects(event[kSigningID], @"ZMCG7MLDV9:com.northpolesec.santa");

            return YES;
          }];

  [sut sync];
}

- (void)testEventUploadBundleAndQuarantineData {
  SNTSyncEventUpload *sut = [[SNTSyncEventUpload alloc] initWithState:self.syncState];
  sut = OCMPartialMock(sut);

  NSSet *allowedClasses = [NSSet setWithObjects:[NSArray class], [SNTStoredEvent class], nil];

  NSData *eventData = [self dataFromFixture:@"sync_eventupload_input_quarantine.plist"];

  NSError *err;
  NSArray *events = [NSKeyedUnarchiver unarchivedObjectOfClasses:allowedClasses
                                                        fromData:eventData
                                                           error:&err];
  XCTAssertNil(err);

  OCMStub([self.daemonConnRop databaseEventsPending:([OCMArg invokeBlockWithArgs:events, nil])]);

  [self stubRequestBody:nil
               response:nil
                  error:nil
          validateBlock:^BOOL(NSURLRequest *req) {
            NSDictionary *requestDict = [self dictFromRequest:req];
            NSArray *events = requestDict[kEvents];

            XCTAssertEqual(events.count, 1);

            NSDictionary *event = [events firstObject];
            XCTAssertEqualObjects(event[kFileBundleID], @"com.luckymarmot.Paw");
            XCTAssertEqualObjects(event[kFileBundlePath], @"/Applications/Paw.app");
            XCTAssertEqualObjects(event[kFileBundleVersion], @"2003004001");
            XCTAssertEqualObjects(event[kFileBundleShortVersionString], @"2.3.4");
            XCTAssertEqualObjects(event[kQuarantineTimestamp], @(1464204868));
            XCTAssertEqualObjects(event[kQuarantineAgentBundleID], @"com.google.Chrome");
            XCTAssertEqualObjects(
                event[kQuarantineDataURL],
                @"https://d3hevc2w7wq7nj.cloudfront.net/paw/Paw-2.3.4-2003004001.zip");
            XCTAssertEqualObjects(event[kQuarantineRefererURL], @"https://luckymarmot.com/paw");

            return YES;
          }];

  [sut sync];
}

- (void)testEventUploadBatching {
  SNTSyncEventUpload *sut = [[SNTSyncEventUpload alloc] initWithState:self.syncState];
  self.syncState.eventBatchSize = 1;
  sut = OCMPartialMock(sut);

  NSSet *allowedClasses = [NSSet setWithObjects:[NSArray class], [SNTStoredEvent class], nil];

  NSData *eventData = [self dataFromFixture:@"sync_eventupload_input_basic.plist"];

  NSError *err;
  NSArray *events = [NSKeyedUnarchiver unarchivedObjectOfClasses:allowedClasses
                                                        fromData:eventData
                                                           error:&err];
  XCTAssertNil(err);

  OCMStub([self.daemonConnRop databaseEventsPending:([OCMArg invokeBlockWithArgs:events, nil])]);

  __block int requestCount = 0;

  [self stubRequestBody:nil
               response:nil
                  error:nil
          validateBlock:^BOOL(NSURLRequest *req) {
            requestCount++;
            return YES;
          }];

  [sut sync];

  XCTAssertEqual(requestCount, 2);
}

#pragma mark - SNTSyncRuleDownload Tests

- (void)testRuleDownload {
  SNTSyncRuleDownload *sut = [[SNTSyncRuleDownload alloc] initWithState:self.syncState];

  NSData *respData = [self dataFromFixture:@"sync_ruledownload_batch1.json"];
  [self stubRequestBody:respData
               response:nil
                  error:nil
          validateBlock:^BOOL(NSURLRequest *req) {
            NSDictionary *requestDict = [self dictFromRequest:req];
            return requestDict[@"cursor"] == nil;
          }];

  respData = [self dataFromFixture:@"sync_ruledownload_batch2.json"];
  [self stubRequestBody:respData
               response:nil
                  error:nil
          validateBlock:^BOOL(NSURLRequest *req) {
            NSDictionary *requestDict = [self dictFromRequest:req];
            return requestDict[@"cursor"] != nil;
          }];

  // Stub out the call to invoke the block, verification of the input is later
  OCMStub([self.daemonConnRop
      databaseRuleAddRules:OCMOCK_ANY
               ruleCleanup:SNTRuleCleanupNone
                    source:SNTRuleAddSourceSyncService
                     reply:([OCMArg invokeBlockWithArgs:[NSNull null], nil])]);
  OCMStub([self.daemonConnRop postRuleSyncNotificationForApplication:[OCMArg any]
                                                               reply:([OCMArg invokeBlock])]);
  [sut sync];

  NSArray *rules = @[
    [[SNTRule alloc]
        initWithIdentifier:@"ee382e199f7eda58863a93a7854b930ade35798bc6856ee8e6ab6ce9277f0eab"
                     state:SNTRuleStateBlock
                      type:SNTRuleTypeBinary],
    [[SNTRule alloc]
        initWithIdentifier:@"46f8c706d0533a54554af5fc163eea704f10c08b30f8a5db12bfdc04fb382fc3"
                     state:SNTRuleStateAllow
                      type:SNTRuleTypeCertificate],
    [[SNTRule alloc] initWithIdentifier:@"platform:com.apple.yes"
                                  state:SNTRuleStateAllow
                                   type:SNTRuleTypeSigningID],
    [[SNTRule alloc]
        initWithIdentifier:@"7846698e47ef41be80b83fb9e2b98fa6dc46c9188b068bff323c302955a00142"
                     state:SNTRuleStateBlock
                      type:SNTRuleTypeCertificate
                 customMsg:@"Hi There"
                 customURL:@"http://northpole.security"
                   celExpr:nil],
    [[SNTRule alloc] initWithIdentifier:@"AAAAAAAAAA"
                                  state:SNTRuleStateBlock
                                   type:SNTRuleTypeTeamID
                              customMsg:@"Banned team ID"
                              customURL:@"http://northpole.security"
                                celExpr:nil],
  ];

  OCMVerify([self.daemonConnRop databaseRuleAddRules:rules
                                         ruleCleanup:SNTRuleCleanupNone
                                              source:SNTRuleAddSourceSyncService
                                               reply:OCMOCK_ANY]);
  OCMVerify([self.daemonConnRop postRuleSyncNotificationForApplication:@"yes" reply:OCMOCK_ANY]);
}

- (void)testRuleDownloadCel {
  SNTSyncRuleDownload *sut = [[SNTSyncRuleDownload alloc] initWithState:self.syncState];

  NSData *respData = [self dataFromFixture:@"sync_ruledownload_with_cel_1.json"];
  [self stubRequestBody:respData
               response:nil
                  error:nil
          validateBlock:^BOOL(NSURLRequest *req) {
            NSDictionary *requestDict = [self dictFromRequest:req];
            return requestDict[@"cursor"] == nil;
          }];

  // Stub out the call to invoke the block, verification of the input is later
  OCMStub([self.daemonConnRop
      databaseRuleAddRules:OCMOCK_ANY
               ruleCleanup:SNTRuleCleanupNone
                    source:SNTRuleAddSourceSyncService
                     reply:([OCMArg invokeBlockWithArgs:[NSNull null], nil])]);
  OCMStub([self.daemonConnRop postRuleSyncNotificationForApplication:[OCMArg any]
                                                               reply:([OCMArg invokeBlock])]);
  [sut sync];

  // Both rules should get sent to the daemon. It will reject the second one.
  NSArray *rules = @[
    [[SNTRule alloc]
        initWithIdentifier:@"AAAAAAAAAA"
                     state:SNTRuleStateCEL
                      type:SNTRuleTypeTeamID
                 customMsg:nil
                 customURL:nil
                   celExpr:@"target.signing_time >= timestamp('2025-05-31T00:00:00Z')"],
    [[SNTRule alloc] initWithIdentifier:@"BBBBBBBBBB"
                                  state:SNTRuleStateCEL
                                   type:SNTRuleTypeTeamID
                              customMsg:nil
                              customURL:nil
                                celExpr:@"this is an invalid expression"],
  ];

  OCMVerify([self.daemonConnRop databaseRuleAddRules:rules
                                         ruleCleanup:SNTRuleCleanupNone
                                              source:SNTRuleAddSourceSyncService
                                               reply:OCMOCK_ANY]);
}

#pragma mark - SNTSyncPostflight Tests

- (void)testPostflightBasicResponse {
  [self setupDefaultDaemonConnResponses];
  SNTSyncPostflight *sut = [[SNTSyncPostflight alloc] initWithState:self.syncState];

  [self stubRequestBody:nil
               response:nil
                  error:nil
          validateBlock:^BOOL(NSURLRequest *req) {
            NSDictionary *requestDict = [self dictFromRequest:req];
            XCTAssertEqualObjects(requestDict[@"rulesHash"], @"the-hash");
            return YES;
          }];

  XCTAssertTrue([sut sync]);
  OCMVerify([self.daemonConnRop updateSyncSettings:OCMOCK_ANY reply:OCMOCK_ANY]);
}

@end
