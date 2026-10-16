/// Copyright 2016 Google Inc. All rights reserved.
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

#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>

#import "Source/common/MOLCodesignChecker.h"
#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTFileInfo.h"
#import "Source/common/SNTRule.h"
#import "Source/common/SNTXPCControlInterface.h"

@interface SNTCommandFileInfo : NSObject

typedef id (^SNTAttributeBlock)(SNTCommandFileInfo*, SNTFileInfo*);
@property(nonatomic) BOOL recursive;
@property(nonatomic) BOOL jsonOutput;
@property(nonatomic) BOOL filterInclusive;
@property(nonatomic) NSNumber* certIndex;
@property(nonatomic, copy) NSArray<NSString*>* outputKeyList;
@property(nonatomic) NSDictionary<NSString*, SNTAttributeBlock>* propertyMap;
+ (NSArray*)fileInfoKeys;
+ (NSArray*)signingChainKeys;
- (SNTAttributeBlock)codeSigned;
- (instancetype)initWithDaemonConnection:(MOLXPCConnection*)daemonConn;
- (NSArray*)parseArguments:(NSArray*)arguments;

@end

@interface SNTCommandFileInfoTest : XCTestCase

@property SNTCommandFileInfo* cfi;
@property SNTFileInfo* fileInfo;
@property id cscMock;
@property SNTRule* matchingRule;
@property id localeMock;

@end

@implementation SNTCommandFileInfoTest

- (void)setUp {
  [super setUp];

  self.cfi = [[SNTCommandFileInfo alloc] initWithDaemonConnection:nil];
  self.fileInfo = [[SNTFileInfo alloc] initWithResolvedPath:@"/usr/bin/yes" error:nil];
  self.cscMock = OCMClassMock([MOLCodesignChecker class]);
  OCMStub([self.cscMock alloc]).andReturn(self.cscMock);
}

- (void)tearDown {
  self.cfi = nil;
  self.fileInfo = nil;
  [self.cscMock stopMocking];
  self.cscMock = nil;
  [self.localeMock stopMocking];
  self.localeMock = nil;
  self.matchingRule = nil;

  [super tearDown];
}

- (void)testParseArgumentsKey {
  NSArray* filePaths = [self.cfi parseArguments:@[ @"--key", @"SHA-256", @"/usr/bin/yes" ]];
  XCTAssertTrue([self.cfi.outputKeyList containsObject:@"SHA-256"]);
  XCTAssertTrue([filePaths containsObject:@"/usr/bin/yes"]);
}

- (void)testParseArgumentsCertIndex {
  NSArray* filePaths = [self.cfi parseArguments:@[ @"--cert-index", @"1", @"/usr/bin/yes" ]];
  XCTAssertEqual([self.cfi.certIndex intValue], 1);
  XCTAssertTrue([filePaths containsObject:@"/usr/bin/yes"]);
}

- (void)testParseArgumentsJSONFalse {
  NSArray* filePaths = [self.cfi parseArguments:@[ @"/usr/bin/yes" ]];
  XCTAssertFalse(self.cfi.jsonOutput);
  XCTAssertTrue([filePaths containsObject:@"/usr/bin/yes"]);
}

- (void)testParseArgumentsJSONFalseWithPath {
  NSArray* filePaths = [self.cfi parseArguments:@[ @"/usr/bin/yes", @"json" ]];
  XCTAssertFalse(self.cfi.jsonOutput);
  XCTAssertTrue([filePaths containsObject:@"json"]);
}

- (void)testParseArgumentsJSONTrue {
  NSArray* filePaths = [self.cfi parseArguments:@[ @"--json", @"/usr/bin/yes" ]];
  XCTAssertTrue(self.cfi.jsonOutput);
  XCTAssertTrue([filePaths containsObject:@"/usr/bin/yes"]);
}

- (void)testParseArgumentsFilePaths {
  NSArray* args = @[
    @"/usr/bin/yes", @"/bin/mv", @"--key", @"SHA-256", @"/bin/ls", @"--json", @"/bin/rm",
    @"--cert-index", @"1", @"/bin/cp"
  ];
  NSArray* filePaths = [self.cfi parseArguments:args];
  XCTAssertEqual(filePaths.count, 5);
  XCTAssertTrue([filePaths containsObject:@"/usr/bin/yes"]);
  XCTAssertTrue([filePaths containsObject:@"/bin/mv"]);
  XCTAssertTrue([filePaths containsObject:@"/bin/ls"]);
  XCTAssertTrue([filePaths containsObject:@"/bin/rm"]);
  XCTAssertTrue([filePaths containsObject:@"/bin/cp"]);
}

- (void)testParseArgumentsFilePathSameAsKey {
  NSArray* filePaths = [self.cfi parseArguments:@[ @"--key", @"Rule", @"Rule" ]];
  XCTAssertTrue([self.cfi.outputKeyList containsObject:@"Rule"]);
  XCTAssertEqual(filePaths.count, 1);
  XCTAssertTrue([filePaths containsObject:@"Rule"]);
}

- (void)testKeysAlignWithPropertyMap {
  NSArray* mapKeys = self.cfi.propertyMap.allKeys;
  NSArray* fileInfokeys = [SNTCommandFileInfo fileInfoKeys];
  for (NSString* key in fileInfokeys)
    XCTAssertTrue([mapKeys containsObject:key]);
  for (NSString* key in mapKeys)
    XCTAssertTrue([fileInfokeys containsObject:key]);
}

- (void)setUpRuleLookup {
  id daemon = OCMProtocolMock(@protocol(SNTDaemonControlXPC));
  OCMStub([daemon databaseRuleForIdentifiers:OCMOCK_ANY reply:OCMOCK_ANY])
      .andDo(^(NSInvocation* invocation) {
        __unsafe_unretained void (^reply)(SNTRule*);
        [invocation getArgument:&reply atIndex:3];
        reply(self.matchingRule);
      });
  OCMStub([daemon staticDecisionForFilePath:OCMOCK_ANY identifiers:OCMOCK_ANY reply:OCMOCK_ANY])
      .andDo(^(NSInvocation* invocation) {
        __unsafe_unretained void (^reply)(SNTRule*, NSString*);
        [invocation getArgument:&reply atIndex:4];
        reply(self.matchingRule, @"Allowed by rule");
      });
  id connection = OCMClassMock([MOLXPCConnection class]);
  OCMStub([connection remoteObjectProxy]).andReturn(daemon);
  self.cfi = [[SNTCommandFileInfo alloc] initWithDaemonConnection:connection];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY error:[OCMArg setTo:nil]])
      .andReturn(self.cscMock);
  OCMStub([self.cscMock platformBinary]).andReturn(YES);

  NSLocale* locale = [NSLocale localeWithLocaleIdentifier:@"en_US"];
  self.localeMock = OCMClassMock([NSLocale class]);
  OCMStub([self.localeMock currentLocale]).andReturn(locale);
}

- (void)setRuleExpression:(NSString*)expression {
  self.matchingRule = [[SNTRule alloc] initWithIdentifier:@"platform:com.example.app"
                                                    state:SNTRuleStateCELv2
                                                     type:SNTRuleTypeSigningID
                                                customMsg:nil
                                                customURL:nil
                                    eventDetailButtonText:nil
                                                  celExpr:expression
                                           seatbeltPolicy:nil
                                                   ruleId:1];
}

- (NSString*)timeWindow {
  NSString* display = self.cfi.propertyMap[@"Time Window"](self.cfi, self.fileInfo);
  // ICU uses a narrow no-break space before AM/PM.
  return [display stringByReplacingOccurrencesOfString:@"\u202f" withString:@" "];
}

- (void)testTimeWindowKey {
  NSArray* keys = [SNTCommandFileInfo fileInfoKeys];
  NSUInteger index = [keys indexOfObject:@"Time Window"];
  XCTAssertEqualObjects(keys[index - 1], @"Rule");
  XCTAssertEqualObjects(keys[index + 1], @"Expected Decision");
  [self.cfi parseArguments:@[ @"--key", @"Time Window", @"/usr/bin/yes" ]];
  XCTAssertEqualObjects(self.cfi.outputKeyList, (@[ @"Time Window" ]));
}

- (void)testWeeklyTimeWindow {
  [self setUpRuleLookup];
  NSArray<NSArray<NSString*>*>* cases = @[
    @[
      (@"policy_for_range([1, 2, 3, 4, 5], '09:00', '17:00', 'America/New_York', "
        "ALLOWLIST, BLOCKLIST)"),
      @"9:00 AM to 5:00 PM, Mon through Fri (America/New_York)"
    ],
    @[
      @"policy_for_range(weekdays(), '09:00', '17:00', kill_on_expiry(ALLOWLIST), BLOCKLIST)",
      @"9:00 AM to 5:00 PM, Mon through Fri"
    ],
    @[
      @"policy_for_range([0, 1, 2, 3, 4, 5, 6], '00:00', '00:00', 'UTC', ALLOWLIST, BLOCKLIST)",
      @"12:00 AM to 12:00 AM every day (UTC)"
    ],
    @[
      @"policy_for_range([5, 1, 3, 1], '22:00', '06:00', '+05:30', ALLOWLIST, BLOCKLIST)",
      @"10:00 PM to 6:00 AM, Mon, Wed, Fri (+05:30)"
    ],
    @[
      @"policy_for_range(\nweekdays(), \"09:00\", // start\n\"17:00\", 'local', ALLOWLIST, BLOCKLIST)",
      @"9:00 AM to 5:00 PM, Mon through Fri"
    ],
  ];
  for (NSArray<NSString*>* testCase in cases) {
    [self setRuleExpression:testCase[0]];
    XCTAssertEqualObjects([self timeWindow], testCase[1]);
    [self.cfi parseArguments:@[ @"--localtz", @"/usr/bin/yes" ]];
    XCTAssertEqualObjects([self timeWindow], testCase[1]);
  }
}

- (void)testFixedTimeWindowFromSyncedRule {
  [self setUpRuleLookup];
  [self setRuleExpression:@"policy_for_range(timestamp(\"2026-09-20T15:55:34Z\"), "
                           "timestamp(\"2026-09-23T16:11:34Z\"), "
                           "kill_on_expiry(ALLOWLIST), BLOCKLIST)"];
  XCTAssertEqualObjects([self timeWindow], @"2026-09-20T15:55:34Z to 2026-09-23T16:11:34Z");
}

- (void)testFixedTimeWindow {
  [self setUpRuleLookup];
  for (NSString* year in @[ @"2000", @"2099" ]) {
    [self setRuleExpression:
              [NSString stringWithFormat:@"policy_for_range(timestamp('%@-09-14T05:30:00+05:30'), "
                                          "timestamp('%@-09-21T00:00:00Z'), ALLOWLIST, BLOCKLIST)",
                                         year, year]];
    XCTAssertEqualObjects(
        [self timeWindow],
        ([NSString stringWithFormat:@"%@-09-14T00:00:00Z to %@-09-21T00:00:00Z", year, year]));
    XCTAssertEqualObjects(self.cfi.propertyMap[@"Expected Decision"](self.cfi, self.fileInfo),
                          @"Allowed by rule");
  }

  NSTimeZone* zone = [NSTimeZone timeZoneForSecondsFromGMT:19800];
  id zoneMock = OCMClassMock([NSTimeZone class]);
  OCMStub([zoneMock localTimeZone]).andReturn(zone);
  [self.cfi parseArguments:@[ @"--localtz", @"/usr/bin/yes" ]];
  XCTAssertEqualObjects([self timeWindow],
                        @"2099-09-14T05:30:00+05:30 to 2099-09-21T05:30:00+05:30");
  [zoneMock stopMocking];
}

- (void)testDurationTimeWindow {
  [self setUpRuleLookup];
  [self setRuleExpression:@"policy_for_range(duration('30m'), kill_on_expiry(ALLOWLIST))"];
  XCTAssertEqualObjects([self timeWindow], @"30 minutes from launch");
  [self setRuleExpression:@"policy_for_range(duration('1h30m'), kill_on_expiry(ALLOWLIST))"];
  XCTAssertEqualObjects([self timeWindow], @"1 hour, 30 minutes from launch");
}

- (void)testTimeWindowOmitted {
  [self setUpRuleLookup];
  XCTAssertNil([self timeWindow]);
  self.matchingRule = [[SNTRule alloc] initWithIdentifier:@"platform:com.example.app"
                                                    state:SNTRuleStateAllow
                                                     type:SNTRuleTypeSigningID];
  XCTAssertNil([self timeWindow]);
  for (NSString* expression in @[
         @"ALLOWLIST", @"policy_for_range(now(), now() + duration('8h'), ALLOWLIST, BLOCKLIST)",
         @"policy_for_range(weekdays(), '09:' + '00', '17:00', ALLOWLIST, BLOCKLIST)",
         @"policy_for_range([now().getDayOfWeek()], '09:00', '17:00', ALLOWLIST, BLOCKLIST)",
         @"policy_for_range(weekdays(), '09:00', '17:00', args[0], ALLOWLIST, BLOCKLIST)",
         @"policy_for_range(duration('30m') + duration('1h'), kill_on_expiry(ALLOWLIST))",
         @"policy_for_range(timestamp('bad'), timestamp('bad'), ALLOWLIST, BLOCKLIST)",
         @"policy_for_range(duration('bad'), kill_on_expiry(ALLOWLIST))", @"policy_for_range("
       ]) {
    [self setRuleExpression:expression];
    XCTAssertNil([self timeWindow], @"%@", expression);
  }
}

- (void)testTimeWindowOmitsIgnoredDevelopmentRule {
  [self setUpRuleLookup];
  // A signing ID rule is ignored for development signatures.
  [self.cscMock stopMocking];
  self.cscMock = OCMClassMock([MOLCodesignChecker class]);
  OCMStub([self.cscMock alloc]).andReturn(self.cscMock);
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY error:[OCMArg setTo:nil]])
      .andReturn(self.cscMock);
  [self setRuleExpression:@"policy_for_range(duration('30m'), kill_on_expiry(ALLOWLIST))"];
  XCTAssertNil([self timeWindow]);
  XCTAssertEqualObjects(self.cfi.propertyMap[@"Rule"](self.cfi, self.fileInfo),
                        @"None (SigningID rule ignored because code signed with a development "
                         "certificate.)");
}

- (void)testCodeSignedNo {
  NSError* err = [NSError errorWithDomain:@"" code:errSecCSUnsigned userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY error:[OCMArg setTo:err]])
      .andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi, self.fileInfo), @"No");
}

- (void)testCodeSignedSignatureFailed {
  NSString* expected = @"Yes, but code/signature changed/unverifiable";
  NSError* err = [NSError errorWithDomain:@"" code:errSecCSSignatureFailed userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY error:[OCMArg setTo:err]])
      .andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi, self.fileInfo), expected);
}

- (void)testCodeSignedStaticCodeChanged {
  NSString* expected = @"Yes, but code/signature changed/unverifiable";
  NSError* err = [NSError errorWithDomain:@"" code:errSecCSStaticCodeChanged userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY error:[OCMArg setTo:err]])
      .andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi, self.fileInfo), expected);
}

- (void)testCodeSignedSignatureNotVerifiable {
  NSString* expected = @"Yes, but code/signature changed/unverifiable";
  NSError* err = [NSError errorWithDomain:@"" code:errSecCSSignatureNotVerifiable userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY error:[OCMArg setTo:err]])
      .andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi, self.fileInfo), expected);
}

- (void)testCodeSignedSignatureUnsupported {
  NSString* expected = @"Yes, but code/signature changed/unverifiable";
  NSError* err = [NSError errorWithDomain:@"" code:errSecCSSignatureUnsupported userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY error:[OCMArg setTo:err]])
      .andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi, self.fileInfo), expected);
}

- (void)testCodeSignedResourceDirectoryFailed {
  NSString* expected = @"Yes, but resources invalid";
  NSError* err = [NSError errorWithDomain:@"" code:errSecCSResourceDirectoryFailed userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY error:[OCMArg setTo:err]])
      .andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi, self.fileInfo), expected);
}

- (void)testCodeSignedResourceNotSupported {
  NSString* expected = @"Yes, but resources invalid";
  NSError* err = [NSError errorWithDomain:@"" code:errSecCSResourceNotSupported userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY error:[OCMArg setTo:err]])
      .andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi, self.fileInfo), expected);
}

- (void)testCodeSignedResourceRulesInvalid {
  NSString* expected = @"Yes, but resources invalid";
  NSError* err = [NSError errorWithDomain:@"" code:errSecCSResourceRulesInvalid userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY error:[OCMArg setTo:err]])
      .andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi, self.fileInfo), expected);
}

- (void)testCodeSignedResourcesInvalid {
  NSString* expected = @"Yes, but resources invalid";
  NSError* err = [NSError errorWithDomain:@"" code:errSecCSResourcesInvalid userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY error:[OCMArg setTo:err]])
      .andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi, self.fileInfo), expected);
}

- (void)testCodeSignedResourcesNotFound {
  NSString* expected = @"Yes, but resources invalid";
  NSError* err = [NSError errorWithDomain:@"" code:errSecCSResourcesNotFound userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY error:[OCMArg setTo:err]])
      .andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi, self.fileInfo), expected);
}

- (void)testCodeSignedResourcesNotSealed {
  NSString* expected = @"Yes, but resources invalid";
  NSError* err = [NSError errorWithDomain:@"" code:errSecCSResourcesNotSealed userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY error:[OCMArg setTo:err]])
      .andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi, self.fileInfo), expected);
}

- (void)testCodeSignedReqFailed {
  NSString* expected = @"Yes, but failed requirement validation";
  NSError* err = [NSError errorWithDomain:@"" code:errSecCSReqFailed userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY error:[OCMArg setTo:err]])
      .andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi, self.fileInfo), expected);
}

- (void)testCodeSignedReqInvalid {
  NSString* expected = @"Yes, but failed requirement validation";
  NSError* err = [NSError errorWithDomain:@"" code:errSecCSReqInvalid userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY error:[OCMArg setTo:err]])
      .andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi, self.fileInfo), expected);
}

- (void)testCodeSignedReqUnsupported {
  NSString* expected = @"Yes, but failed requirement validation";
  NSError* err = [NSError errorWithDomain:@"" code:errSecCSReqUnsupported userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY error:[OCMArg setTo:err]])
      .andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi, self.fileInfo), expected);
}

- (void)testCodeSignedInfoPlistFailed {
  NSString* expected = @"Yes, but can't validate as the Info.plist has been modified";
  NSError* err = [NSError errorWithDomain:@"" code:errSecCSInfoPlistFailed userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY error:[OCMArg setTo:err]])
      .andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi, self.fileInfo), expected);
}

- (void)testCodeSignedDefault {
  NSString* expected = @"Yes, but failed to validate (999)";
  NSError* err = [NSError errorWithDomain:@"" code:999 userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY error:[OCMArg setTo:err]])
      .andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi, self.fileInfo), expected);
}

- (void)testParseArgumentsFilterInclusiveTrue {
  NSArray* filePaths = [self.cfi parseArguments:@[ @"--filter-inclusive", @"/usr/bin/yes" ]];
  XCTAssertTrue(self.cfi.filterInclusive);
  XCTAssertTrue([filePaths containsObject:@"/usr/bin/yes"]);
}

@end
