/// Copyright 2022 Google Inc. All rights reserved.
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

#import <XCTest/XCTest.h>

#include <map>

#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTError.h"
#import "Source/common/SNTSyncConstants.h"

#import "Source/common/SNTRule.h"

@interface SNTRule ()
@property(readwrite) NSUInteger timestamp;
@end

@interface SNTRuleTest : XCTestCase
@end

@implementation SNTRuleTest

- (void)testInitWithDictionaryValid {
  SNTRule *sut;

  sut = [[SNTRule alloc] initWithDictionary:@{
    @"identifier" : @"b7c1e3fd640c5f211c89b02c2c6122f78ce322aa5c56eb0bb54bc422a8f8b670",
    @"policy" : @"ALLOWLIST",
    @"rule_type" : @"BINARY",
  }
                                      error:nil];
  XCTAssertNotNil(sut);
  XCTAssertEqualObjects(sut.identifier,
                        @"b7c1e3fd640c5f211c89b02c2c6122f78ce322aa5c56eb0bb54bc422a8f8b670");
  XCTAssertEqual(sut.type, SNTRuleTypeBinary);
  XCTAssertEqual(sut.state, SNTRuleStateAllow);

  sut = [[SNTRule alloc] initWithDictionary:@{
    @"sha256" : @"b7c1e3fd640c5f211c89b02c2c6122f78ce322aa5c56eb0bb54bc422a8f8b670",
    @"policy" : @"BLOCKLIST",
    @"rule_type" : @"CERTIFICATE",
  }
                                      error:nil];
  XCTAssertNotNil(sut);
  XCTAssertEqualObjects(sut.identifier,
                        @"b7c1e3fd640c5f211c89b02c2c6122f78ce322aa5c56eb0bb54bc422a8f8b670");
  XCTAssertEqual(sut.type, SNTRuleTypeCertificate);
  XCTAssertEqual(sut.state, SNTRuleStateBlock);

  // Ensure a Binary and Certificate rules properly convert identifiers to lowercase.
  for (NSString *ruleType in @[ @"BINARY", @"CERTIFICATE" ]) {
    sut = [[SNTRule alloc] initWithDictionary:@{
      @"identifier" : @"B7C1E3FD640C5F211C89B02C2C6122F78CE322AA5C56EB0BB54BC422A8F8B670",
      @"policy" : @"BLOCKLIST",
      @"rule_type" : ruleType,
    }
                                        error:nil];
    XCTAssertNotNil(sut);
    XCTAssertEqualObjects(sut.identifier,
                          @"b7c1e3fd640c5f211c89b02c2c6122f78ce322aa5c56eb0bb54bc422a8f8b670");
  }

  sut = [[SNTRule alloc] initWithDictionary:@{
    @"identifier" : @"ABCDEFGHIJ",
    @"policy" : @"SILENT_BLOCKLIST",
    @"rule_type" : @"TEAMID",
  }
                                      error:nil];
  XCTAssertNotNil(sut);
  XCTAssertEqualObjects(sut.identifier, @"ABCDEFGHIJ");
  XCTAssertEqual(sut.type, SNTRuleTypeTeamID);
  XCTAssertEqual(sut.state, SNTRuleStateSilentBlock);

  sut = [[SNTRule alloc] initWithDictionary:@{
    @"identifier" : @"b7c1e3fd640c5f211c89b02c2c6122f78ce322aa5c56eb0bb54bc422a8f8b670",
    @"policy" : @"ALLOWLIST_COMPILER",
    @"rule_type" : @"BINARY",
  }
                                      error:nil];
  XCTAssertNotNil(sut);
  XCTAssertEqualObjects(sut.identifier,
                        @"b7c1e3fd640c5f211c89b02c2c6122f78ce322aa5c56eb0bb54bc422a8f8b670");
  XCTAssertEqual(sut.type, SNTRuleTypeBinary);
  XCTAssertEqual(sut.state, SNTRuleStateAllowCompiler);

  sut = [[SNTRule alloc] initWithDictionary:@{
    @"identifier" : @"ABCDEFGHIJ",
    @"policy" : @"REMOVE",
    @"rule_type" : @"TEAMID",
  }
                                      error:nil];
  XCTAssertNotNil(sut);
  XCTAssertEqualObjects(sut.identifier, @"ABCDEFGHIJ");
  XCTAssertEqual(sut.type, SNTRuleTypeTeamID);
  XCTAssertEqual(sut.state, SNTRuleStateRemove);

  sut = [[SNTRule alloc] initWithDictionary:@{
    @"identifier" : @"ABCDEFGHIJ",
    @"policy" : @"ALLOWLIST",
    @"rule_type" : @"TEAMID",
    @"custom_msg" : @"A custom block message",
    @"custom_url" : @"https://example.com",
  }
                                      error:nil];
  XCTAssertNotNil(sut);
  XCTAssertEqualObjects(sut.identifier, @"ABCDEFGHIJ");
  XCTAssertEqual(sut.type, SNTRuleTypeTeamID);
  XCTAssertEqual(sut.state, SNTRuleStateAllow);
  XCTAssertEqualObjects(sut.customMsg, @"A custom block message");
  XCTAssertEqualObjects(sut.customURL, @"https://example.com");

  // TeamIDs must be 10 chars in length
  sut = [[SNTRule alloc] initWithDictionary:@{
    @"identifier" : @"A",
    @"policy" : @"ALLOWLIST",
    @"rule_type" : @"TEAMID",
  }
                                      error:nil];
  XCTAssertNil(sut);

  // TeamIDs must be only alphanumeric chars
  sut = [[SNTRule alloc] initWithDictionary:@{
    @"identifier" : @"ßßßßßßßßßß",
    @"policy" : @"ALLOWLIST",
    @"rule_type" : @"TEAMID",
  }
                                      error:nil];
  XCTAssertNil(sut);

  // TeamIDs are converted to uppercase
  sut = [[SNTRule alloc] initWithDictionary:@{
    @"identifier" : @"abcdefghij",
    @"policy" : @"REMOVE",
    @"rule_type" : @"TEAMID",
  }
                                      error:nil];
  XCTAssertNotNil(sut);
  XCTAssertEqualObjects(sut.identifier, @"ABCDEFGHIJ");

  // SigningID tests
  sut = [[SNTRule alloc] initWithDictionary:@{
    @"identifier" : @"ABCDEFGHIJ:com.example",
    @"policy" : @"REMOVE",
    @"rule_type" : @"SIGNINGID",
  }
                                      error:nil];
  XCTAssertNotNil(sut);
  XCTAssertEqualObjects(sut.identifier, @"ABCDEFGHIJ:com.example");
  XCTAssertEqual(sut.type, SNTRuleTypeSigningID);
  XCTAssertEqual(sut.state, SNTRuleStateRemove);

  // Invalid SingingID tests:
  for (NSString *ident in @[
         @":com.example",     // missing team ID
         @"ABCDEFGHIJ:",      // missing signing ID
         @"ABC:com.example",  // Invalid team id
         @":",                // missing team and signing IDs
         @"",                 // empty string
       ]) {
    NSError *error;
    sut = [[SNTRule alloc] initWithDictionary:@{
      @"identifier" : ident,
      @"policy" : @"REMOVE",
      @"rule_type" : @"SIGNINGID",
    }
                                        error:&error];
    XCTAssertNil(sut);
    XCTAssertNotNil(error);
  }

  // Signing ID with lower team ID has case fixed up
  sut = [[SNTRule alloc] initWithDictionary:@{
    @"identifier" : @"abcdefghij:com.example",
    @"policy" : @"REMOVE",
    @"rule_type" : @"SIGNINGID",
  }
                                      error:nil];
  XCTAssertNotNil(sut);
  XCTAssertEqualObjects(sut.identifier, @"ABCDEFGHIJ:com.example");

  // Signing ID with lower platform team ID is left alone
  sut = [[SNTRule alloc] initWithDictionary:@{
    @"identifier" : @"platform:com.example",
    @"policy" : @"REMOVE",
    @"rule_type" : @"SIGNINGID",
  }
                                      error:nil];
  XCTAssertNotNil(sut);
  XCTAssertEqualObjects(sut.identifier, @"platform:com.example");

  // Signing ID can contain the TID:SID delimiter character (":")
  for (NSString *ident in @[
         @"ABCDEFGHIJ:com:",
         @"ABCDEFGHIJ:com:example",
         @"ABCDEFGHIJ::",
         @"ABCDEFGHIJ:com:example:with:more:components:",
       ]) {
    sut = [[SNTRule alloc] initWithDictionary:@{
      @"identifier" : ident,
      @"policy" : @"ALLOWLIST",
      @"rule_type" : @"SIGNINGID",
    }
                                        error:nil];
    XCTAssertNotNil(sut);
    XCTAssertEqualObjects(sut.identifier, ident);
  }

  // Comments are left intact
  sut = [[SNTRule alloc] initWithDictionary:@{
    @"identifier" : @"ABCDEFGHIJ",
    @"policy" : @"REMOVE",
    @"rule_type" : @"TEAMID",
    @"Comment" : @"ThIs iS Only A Comment!",
  }
                                      error:nil];
  XCTAssertNotNil(sut);
  XCTAssertEqualObjects(sut.identifier, @"ABCDEFGHIJ");
  XCTAssertEqualObjects(sut.comment, @"ThIs iS Only A Comment!");
}

- (void)testInitWithDictionaryInvalid {
  NSError *error;
  SNTRule *sut;

  sut = [[SNTRule alloc] initWithDictionary:@{} error:&error];
  XCTAssertNil(sut);
  XCTAssertNotNil(error);
  XCTAssertEqual(error.code, SNTErrorCodeRuleMissingIdentifier);

  sut = [[SNTRule alloc] initWithDictionary:@{
    @"identifier" : @"b7c1e3fd640c5f211c89b02c2c6122f78ce322aa5c56eb0bb54bc422a8f8b670",
  }
                                      error:&error];
  XCTAssertNil(sut);
  XCTAssertNotNil(error);
  XCTAssertEqual(error.code, SNTErrorCodeRuleMissingPolicy);

  sut = [[SNTRule alloc] initWithDictionary:@{
    @"identifier" : @"an-identifier",
    @"policy" : @"ALLOWLIST",
    @"rule_type" : @"BINARY",
  }
                                      error:&error];
  XCTAssertNil(sut);
  XCTAssertNotNil(error);
  XCTAssertEqual(error.code, SNTErrorCodeRuleInvalidIdentifier);

  sut = [[SNTRule alloc] initWithDictionary:@{
    @"identifier" : @"b7c1e3fd640c5f211c89b02c2c6122f78ce322aa5c56eb0bb54bc422a8f8b670",
    @"policy" : @"OTHERPOLICY",
    @"rule_type" : @"BINARY",
  }
                                      error:&error];
  XCTAssertNil(sut);
  XCTAssertNotNil(error);
  XCTAssertEqual(error.code, SNTErrorCodeRuleInvalidPolicy);

  sut = [[SNTRule alloc] initWithDictionary:@{
    @"identifier" : @"an-identifier",
    @"policy" : @"ALLOWLIST",
    @"rule_type" : @"OTHER_RULE_TYPE",
  }
                                      error:&error];
  XCTAssertNil(sut);
  XCTAssertNotNil(error);
  XCTAssertEqual(error.code, SNTErrorCodeRuleInvalidRuleType);
}

- (void)testRuleDictionaryRepresentation {
  NSDictionary *expectedTeamID = @{
    @"identifier" : @"ABCDEFGHIJ",
    @"policy" : @"ALLOWLIST",
    @"rule_type" : @"TEAMID",
    @"custom_msg" : @"A custom block message",
    @"custom_url" : @"https://example.com",
    @"comment" : @"",
    @"cel_expr": @"",
  };

  SNTRule *sut = [[SNTRule alloc] initWithDictionary:expectedTeamID error:nil];
  NSDictionary *dict = [sut dictionaryRepresentation];
  XCTAssertEqualObjects(expectedTeamID, dict);

  NSDictionary *expectedBinary = @{
    @"identifier" : @"84de9c61777ca36b13228e2446d53e966096e78db7a72c632b5c185b2ffe68a6",
    @"policy" : @"BLOCKLIST",
    @"rule_type" : @"BINARY",
    @"custom_msg" : @"",
    @"custom_url" : @"",
    @"comment" : @"",
    @"cel_expr": @"",
  };

  sut = [[SNTRule alloc] initWithDictionary:expectedBinary error:nil];
  dict = [sut dictionaryRepresentation];

  XCTAssertEqualObjects(expectedBinary, dict);
}

- (void)testRuleStateToPolicyString {
  NSDictionary *expected = @{
    @"identifier" : @"84de9c61777ca36b13228e2446d53e966096e78db7a72c632b5c185b2ffe68a6",
    @"policy" : @"ALLOWLIST",
    @"rule_type" : @"BINARY",
    @"custom_msg" : @"A custom block message",
    @"custom_url" : @"https://example.com",
    @"cel_expr": @"",
  };

  SNTRule *sut = [[SNTRule alloc] initWithDictionary:expected error:nil];
  sut.state = SNTRuleStateBlock;
  XCTAssertEqualObjects(kRulePolicyBlocklist, [sut dictionaryRepresentation][kRulePolicy]);
  sut.state = SNTRuleStateSilentBlock;
  XCTAssertEqualObjects(kRulePolicySilentBlocklist, [sut dictionaryRepresentation][kRulePolicy]);
  sut.state = SNTRuleStateAllow;
  XCTAssertEqualObjects(kRulePolicyAllowlist, [sut dictionaryRepresentation][kRulePolicy]);
  sut.state = SNTRuleStateAllowCompiler;
  XCTAssertEqualObjects(kRulePolicyAllowlistCompiler, [sut dictionaryRepresentation][kRulePolicy]);
  // Invalid states
  sut.state = SNTRuleStateRemove;
  XCTAssertEqualObjects(kRulePolicyRemove, [sut dictionaryRepresentation][kRulePolicy]);
}

- (void)testKeyCaseForInitWithDictionary {
  for (NSString *key in
       @[ kRulePolicy, kRuleIdentifier, kRuleType, kRuleCustomMsg, kRuleCustomURL, kRuleComment ]) {
    NSDictionary *expected = @{
      @"cel_expr": @"",
      @"identifier" : @"84de9c61777ca36b13228e2446d53e966096e78db7a72c632b5c185b2ffe68a6",
      @"policy" : @"ALLOWLIST",
      @"rule_type" : @"BINARY",
      @"custom_msg" : @"A custom block message",
      @"custom_url" : @"https://example.com",
      @"comment" : @"",
    };

    NSMutableDictionary *dict = [expected mutableCopy];
    NSString *value = dict[key];
    XCTAssertNotNil(value);
    dict[[key uppercaseString]] = dict[key];
    [dict removeObjectForKey:key];

    SNTRule *rule = [[SNTRule alloc] initWithDictionary:dict error:nil];
    NSDictionary *final = [rule dictionaryRepresentation];
    XCTAssertEqualObjects(expected, final);
  }
}

- (void)testStringifyWithColor {
  std::map<std::pair<SNTRuleType, SNTRuleState>, NSString *> ruleCheckToString = {
      {{SNTRuleTypeUnknown, SNTRuleStateUnknown}, @"None"},
      {{SNTRuleTypeUnknown, SNTRuleStateAllow}, @"Allowed (Unknown)"},
      {{SNTRuleTypeUnknown, SNTRuleStateBlock}, @"Blocked (Unknown)"},
      {{SNTRuleTypeUnknown, SNTRuleStateSilentBlock}, @"Blocked (Unknown, Silent)"},
      {{SNTRuleTypeUnknown, SNTRuleStateRemove}, @"Unexpected rule state: 4 (Unknown)"},
      {{SNTRuleTypeUnknown, SNTRuleStateAllowCompiler}, @"Allowed (Unknown, Compiler)"},
      {{SNTRuleTypeUnknown, SNTRuleStateAllowTransitive},
       @"Allowed (Unknown, Transitive)\nlast access date: 2023-03-08 20:26:40 +0000"},

      {{SNTRuleTypeBinary, SNTRuleStateUnknown}, @"None"},
      {{SNTRuleTypeBinary, SNTRuleStateAllow}, @"Allowed (Binary)"},
      {{SNTRuleTypeBinary, SNTRuleStateBlock}, @"Blocked (Binary)"},
      {{SNTRuleTypeBinary, SNTRuleStateSilentBlock}, @"Blocked (Binary, Silent)"},
      {{SNTRuleTypeBinary, SNTRuleStateRemove}, @"Unexpected rule state: 4 (Binary)"},
      {{SNTRuleTypeBinary, SNTRuleStateAllowCompiler}, @"Allowed (Binary, Compiler)"},
      {{SNTRuleTypeBinary, SNTRuleStateAllowTransitive},
       @"Allowed (Binary, Transitive)\nlast access date: 2023-03-08 20:26:40 +0000"},

      {{SNTRuleTypeSigningID, SNTRuleStateUnknown}, @"None"},
      {{SNTRuleTypeSigningID, SNTRuleStateAllow}, @"Allowed (SigningID)"},
      {{SNTRuleTypeSigningID, SNTRuleStateBlock}, @"Blocked (SigningID)"},
      {{SNTRuleTypeSigningID, SNTRuleStateSilentBlock}, @"Blocked (SigningID, Silent)"},
      {{SNTRuleTypeSigningID, SNTRuleStateRemove}, @"Unexpected rule state: 4 (SigningID)"},
      {{SNTRuleTypeSigningID, SNTRuleStateAllowCompiler}, @"Allowed (SigningID, Compiler)"},
      {{SNTRuleTypeSigningID, SNTRuleStateAllowTransitive},
       @"Allowed (SigningID, Transitive)\nlast access date: 2023-03-08 20:26:40 +0000"},

      {{SNTRuleTypeCertificate, SNTRuleStateUnknown}, @"None"},
      {{SNTRuleTypeCertificate, SNTRuleStateAllow}, @"Allowed (Certificate)"},
      {{SNTRuleTypeCertificate, SNTRuleStateBlock}, @"Blocked (Certificate)"},
      {{SNTRuleTypeCertificate, SNTRuleStateSilentBlock}, @"Blocked (Certificate, Silent)"},
      {{SNTRuleTypeCertificate, SNTRuleStateRemove}, @"Unexpected rule state: 4 (Certificate)"},
      {{SNTRuleTypeCertificate, SNTRuleStateAllowCompiler}, @"Allowed (Certificate, Compiler)"},
      {{SNTRuleTypeCertificate, SNTRuleStateAllowTransitive},
       @"Allowed (Certificate, Transitive)\nlast access date: 2023-03-08 20:26:40 +0000"},

      {{SNTRuleTypeTeamID, SNTRuleStateUnknown}, @"None"},
      {{SNTRuleTypeTeamID, SNTRuleStateAllow}, @"Allowed (TeamID)"},
      {{SNTRuleTypeTeamID, SNTRuleStateBlock}, @"Blocked (TeamID)"},
      {{SNTRuleTypeTeamID, SNTRuleStateSilentBlock}, @"Blocked (TeamID, Silent)"},
      {{SNTRuleTypeTeamID, SNTRuleStateRemove}, @"Unexpected rule state: 4 (TeamID)"},
      {{SNTRuleTypeTeamID, SNTRuleStateAllowCompiler}, @"Allowed (TeamID, Compiler)"},
      {{SNTRuleTypeTeamID, SNTRuleStateAllowTransitive},
       @"Allowed (TeamID, Transitive)\nlast access date: 2023-03-08 20:26:40 +0000"},
  };

  SNTRule *rule = [[SNTRule alloc] init];
  rule.timestamp = 700000000;  // time interval since reference date

  for (const auto &[typeAndState, want] : ruleCheckToString) {
    rule.type = typeAndState.first;
    rule.state = typeAndState.second;

    NSString *got = [rule stringifyWithColor:NO];
    XCTAssertEqualObjects(got, want);
  }
}

@end
