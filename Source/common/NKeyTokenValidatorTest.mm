/// Copyright 2026 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     https://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#import <XCTest/XCTest.h>

#include "Source/common/NKeyTokenValidator.h"

// Test-only operator NKey
static const std::string kTestOperatorNKey =
    "ODRCTBREJ7SHU24F5FECLYEVXGFYNM3KBRMDD7PFNL6CUQ6BORUIGY47";

static const std::set<std::string> kTrustedNKeys = {kTestOperatorNKey};

// clang-format off
// Account JWT signed by test operator
//   iss = ODRCTBREJ7SHU24F5FECLYEVXGFYNM3KBRMDD7PFNL6CUQ6BORUIGY47
//   sub = ADQXK2SZQ7TRAXQEBHXBUQJ4KOH5QPINGMEUAVPMAH43C2I4CH4U27UQ
//   exp = 2086366736 (2036-02-11T18:18:56Z)
static NSString *const kValidAccountJWT =
    @"eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ."
    @"eyJleHAiOjIwODYzNjY3MzYsImp0aSI6IlhRRTUzUDZDTjNLSlIyRDdNR0NSVlBTTDZSRklUUkNOV1VMVEJTV01CTFYzWU"
    @"FKS1RJT1EiLCJpYXQiOjE3NzEwMDY3MzYsImlzcyI6Ik9EUkNUQlJFSjdTSFUyNEY1RkVDTFlFVlhHRllOTTNLQlJNREQ"
    @"3UEZOTDZDVVE2Qk9SVUlHWTQ3IiwibmFtZSI6IlRlc3RBY2NvdW50Iiwic3ViIjoiQURRWEsyU1pRN1RSQVhRRUJIWEJV"
    @"UUo0S09INVFQSU5HTUVVQVZQTUFINDNDMkk0Q0g0VTI3VVEiLCJuYXRzIjp7ImxpbWl0cyI6eyJzdWJzIjotMSwiZGF0Y"
    @"SI6LTEsInBheWxvYWQiOi0xLCJpbXBvcnRzIjotMSwiZXhwb3J0cyI6LTEsIndpbGRjYXJkcyI6dHJ1ZSwiZGlzYWxsb3"
    @"dfYmVhcmVyIjp0cnVlLCJjb25uIjotMSwibGVhZiI6LTF9LCJkZWZhdWx0X3Blcm1pc3Npb25zIjp7InB1YiI6e30sInN"
    @"1YiI6e319LCJhdXRob3JpemF0aW9uIjp7fSwidHlwZSI6ImFjY291bnQiLCJ2ZXJzaW9uIjoyfX0."
    @"oRYDR7kj0xXj3SaTI4AGclqbNnmgk_NVC2mh4ihhw8QoyVExJsVX0Np7paXHS-5S_PC2dyS6kUzdkLZ5catHBw";

// User JWT signed by TestAccount
//   iss = ADQXK2SZQ7TRAXQEBHXBUQJ4KOH5QPINGMEUAVPMAH43C2I4CH4U27UQ
//   sub = UCGLW2S5TQJKJ7774WH3PD2SS6JFWTG3PPDTIXQHA325HXIRI5L4CGHL
//   exp = none
static NSString *const kValidUserJWT =
    @"eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ."
    @"eyJqdGkiOiJTNUYyT1ozVkFLQjQ2SlVIWk4zN1VJTVNaWjZQUVFaSDZCVEJMWkVRV1ozWlBaWVJCSFZBIiwiaWF0IjoxNz"
    @"cxMDA2NzQyLCJpc3MiOiJBRFFYSzJTWlE3VFJBWFFFQkhYQlVRSjRLT0g1UVBJTkdNRVVBVlBNQUg0M0MySTRDSDRVMjdV"
    @"USIsIm5hbWUiOiJUZXN0VXNlciIsInN1YiI6IlVDR0xXMlM1VFFKS0o3Nzc0V0gzUEQyU1M2SkZXVEczUFBEVElYUUhBM"
    @"zI1SFhJUkk1TDRDR0hMIiwibmF0cyI6eyJwdWIiOnt9LCJzdWIiOnt9LCJzdWJzIjotMSwiZGF0YSI6LTEsInBheWxvYWQi"
    @"OjEwNDg1NzYsInR5cGUiOiJ1c2VyIiwidmVyc2lvbiI6Mn19."
    @"VSsqo3Z74i83O6kGC2dhzRByq05i9tPDn6A3lbcWX9C1aKHk0o-_JoFVrk-xLe-RH9j1H-kkuu-vYzDb901CBw";

// Expired user JWT signed by TestAccount
//   iss = ADQXK2SZQ7TRAXQEBHXBUQJ4KOH5QPINGMEUAVPMAH43C2I4CH4U27UQ
//   sub = UDJJGWWTXMI56CJRWCKKOJL6ZEZXLJ6VDS4WKSE4PGJYLXLFXCDHFSRG
//   exp = 1000000000 (2001-09-09T01:46:40Z)
static NSString *const kExpiredUserJWT =
    @"eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ."
    @"eyJleHAiOjEwMDAwMDAwMDAsImp0aSI6IkVYUElSRURURVNUSlRJIiwiaWF0IjoxMDAwMDAwMDAwLCJpc3MiOiJBRFFYSzJT"
    @"WlE3VFJBWFFFQkhYQlVRSjRLT0g1UVBJTkdNRVVBVlBNQUg0M0MySTRDSDRVMjdVUSIsIm5hbWUiOiJFeHBpcmVkVGVzdFVz"
    @"ZXIiLCJzdWIiOiJVREpKR1dXVFhNSTU2Q0pSV0NLS09KTDZaRVpYTEo2VkRTNFdLU0U0UEdKWUxYTEZYQ0RIRlNSRyIsIm5h"
    @"dHMiOnsicHViIjp7fSwic3ViIjp7fSwic3VicyI6LTEsImRhdGEiOi0xLCJwYXlsb2FkIjoxMDQ4NTc2LCJ0eXBlIjoidXNl"
    @"ciIsInZlcnNpb24iOjJ9fQ."
    @"ZLmUezRnyISdu4RKW-PcKMN2GV-DVzzujJyedxXfvS9v6C6s0nGiVxdsbaXkwokDn1ORD4UF3hR6FBIm4xRvAg";

// Different account JWT - Does not match kValidUserJWT's issuer
//   iss = ODRCTBREJ7SHU24F5FECLYEVXGFYNM3KBRMDD7PFNL6CUQ6BORUIGY47
//   sub = AA6GNB3TWJ6BRXJRQILSTSYV5UJKBNSVGOIRKHHC2NLOZTL56NW5CETX
//   exp = 2086366739 (2036-02-11T18:18:59Z)
static NSString *const kOtherAccountJWT =
    @"eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ."
    @"eyJleHAiOjIwODYzNjY3MzksImp0aSI6IkdEUUs3TFVIVVZESDNaT1RVRDVVNVdQUDU0WDRFQlA0UFlRWUVXWUs0V0tUSV"
    @"I3RjRXVVEiLCJpYXQiOjE3NzEwMDY3MzksImlzcyI6Ik9EUkNUQlJFSjdTSFUyNEY1RkVDTFlFVlhHRllOTTNLQlJNREQ"
    @"3UEZOTDZDVVE2Qk9SVUlHWTQ3IiwibmFtZSI6Ik90aGVyQWNjb3VudCIsInN1YiI6IkFBNkdOQjNUV0o2QlJYSlJRSUxT"
    @"VFNZVjVVSktCTlNWR09JUktISEMyTkxPWlRMNTZOVzVDRVRYIiwibmF0cyI6eyJsaW1pdHMiOnsic3VicyI6LTEsImRhd"
    @"GEiOi0xLCJwYXlsb2FkIjotMSwiaW1wb3J0cyI6LTEsImV4cG9ydHMiOi0xLCJ3aWxkY2FyZHMiOnRydWUsImRpc2FsbG"
    @"93X2JlYXJlciI6dHJ1ZSwiY29ubiI6LTEsImxlYWYiOi0xfSwiZGVmYXVsdF9wZXJtaXNzaW9ucyI6eyJwdWIiOnt9LCJ"
    @"zdWIiOnt9fSwiYXV0aG9yaXphdGlvbiI6e30sInR5cGUiOiJhY2NvdW50IiwidmVyc2lvbiI6Mn19."
    @"ZywuDMRTKkQxjUQczJzN35wfEakZjMyJquTEMPpf93oVLEIo9OD4g4d2pnRq3ckMrOl8NBgOPRj6t0X_JnzQCA";

// Account JWT signed by UntrustedOperator (not in kTrustedNKeys)
//   iss = OBBLLE5H45CFMXWUOXTPXVL5EJYOMP332YR2UHH36FBZIYA2RMYLBVM2
//   sub = AASGQNRHELILEXYOB6LCEEGTXHKNDC6L7JWEEJ76HQAQE746PF6CGXEP
//   exp = none
static NSString *const kUntrustedAccountJWT =
    @"eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ."
    @"eyJqdGkiOiJZUUU3UzZKVkZFRkwzM0RERkc1SllOM0lUQU9GRE9SVUJMQ1NYVjRRRDJYUUdOUUJTWEFRIiwiaWF0IjoxNz"
    @"cxMDg0Mjc3LCJpc3MiOiJPQkJMTEU1SDQ1Q0ZNWFdVT1hUUFhWTDVFSllPTVAzMzJZUjJVSEgzNkZCWklZQTJSTVlMQlZN"
    @"MiIsIm5hbWUiOiJVbnRydXN0ZWRBY2NvdW50Iiwic3ViIjoiQUFTR1FOUkhFTElMRVhZT0I2TENFRUdUWEhLTkRDNkw3Sl"
    @"dFRUo3NkhRQVFFNzQ2UEY2Q0dYRVAiLCJuYXRzIjp7ImxpbWl0cyI6eyJzdWJzIjotMSwiZGF0YSI6LTEsInBheWxvYWQi"
    @"Oi0xLCJpbXBvcnRzIjotMSwiZXhwb3J0cyI6LTEsIndpbGRjYXJkcyI6dHJ1ZSwiZGlzYWxsb3dfYmVhcmVyIjp0cnVlLC"
    @"Jjb25uIjotMSwibGVhZiI6LTF9LCJkZWZhdWx0X3Blcm1pc3Npb25zIjp7InB1YiI6e30sInN1YiI6e319LCJhdXRob3Jpem"
    @"F0aW9uIjp7fSwidHlwZSI6ImFjY291bnQiLCJ2ZXJzaW9uIjoyfX0."
    @"8YidTNUQGu4BlbMIvaZ56y-7Fbba0WJRiGlNmbmFMnYyrk0w05TY8j_ZYUCnTV6zUNOqxPRHmKjkTc3_HzPXAg";

// User JWT signed by UntrustedAccount
//   iss = AASGQNRHELILEXYOB6LCEEGTXHKNDC6L7JWEEJ76HQAQE746PF6CGXEP
//   sub = UCHWDQ7NJC3J3V4D2PEPZBJVNUXDPPG7Z5IIAZ55YB2NYUB3DHNDJNZR
//   exp = none
static NSString *const kUntrustedUserJWT =
    @"eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ."
    @"eyJqdGkiOiI1RU1aWFJXTFE0NkdTM1hVS1A2UENLNTJSTTVTM0NDRE1ZVlNNS0s0SEtNTk5YTFlBS0RBIiwiaWF0IjoxNz"
    @"cxMDg0MjgxLCJpc3MiOiJBQVNHUU5SSEVMSUxFWFlPQjZMQ0VFR1RYSEtOREM2TDdKV0VFSjc2SFFBUUU3NDZQRjZDR1hF"
    @"UCIsIm5hbWUiOiJVbnRydXN0ZWRVc2VyIiwic3ViIjoiVUNIV0RRN05KQzNKM1Y0RDJQRVBaQkpWTlVYRFBQRzdaNUlJQV"
    @"o1NVlCMk5ZVUIzREhOREpOWlIiLCJuYXRzIjp7InB1YiI6e30sInN1YiI6e30sInN1YnMiOi0xLCJkYXRhIjotMSwicGF5"
    @"bG9hZCI6MTA0ODU3NiwidHlwZSI6InVzZXIiLCJ2ZXJzaW9uIjoyfX0."
    @"nsLtjkGTPawRxzHWyisefn_GuKIqtwsBtDT3tJA2eEP5GylxxkLBA8USjORFaiU-q_OP8xPO3w6JsNwgcKuaDw";
// clang-format on

@interface NKeyTokenValidatorTest : XCTestCase
@end

@implementation NKeyTokenValidatorTest

#pragma mark - NKeyTokenValidator Tests

- (void)testValidFullChain {
  XCTAssertTrue(
      santa::NKeyTokenValidator(kTrustedNKeys, kValidAccountJWT, kValidUserJWT).Validate());
}

- (void)testNilUserJWT {
  XCTAssertFalse(santa::NKeyTokenValidator(kTrustedNKeys, kValidAccountJWT, nil).Validate());
}

- (void)testEmptyUserJWT {
  XCTAssertFalse(santa::NKeyTokenValidator(kTrustedNKeys, kValidAccountJWT, @"").Validate());
}

- (void)testNilAccountJWT {
  XCTAssertFalse(santa::NKeyTokenValidator(kTrustedNKeys, nil, kValidUserJWT).Validate());
}

- (void)testEmptyAccountJWT {
  XCTAssertFalse(santa::NKeyTokenValidator(kTrustedNKeys, @"", kValidUserJWT).Validate());
}

- (void)testMalformedAccountJWTNoDots {
  XCTAssertFalse(santa::NKeyTokenValidator(kTrustedNKeys, @"nodots", kValidUserJWT).Validate());
}

- (void)testMalformedAccountJWTOneDot {
  XCTAssertFalse(santa::NKeyTokenValidator(kTrustedNKeys, @"one.dot", kValidUserJWT).Validate());
}

- (void)testMalformedAccountJWTTooManyDots {
  XCTAssertFalse(
      santa::NKeyTokenValidator(kTrustedNKeys, @"too.many.dots.here", kValidUserJWT).Validate());
}

- (void)testTamperedAccountSignature {
  NSString *tampered = [NSString
      stringWithFormat:@"%@X", [kValidAccountJWT substringToIndex:kValidAccountJWT.length - 1]];
  XCTAssertFalse(santa::NKeyTokenValidator(kTrustedNKeys, tampered, kValidUserJWT).Validate());
}

- (void)testUnknownAccountIssuer {
  NSDictionary *fakePayload = @{@"iss" : @"OAUNKNOWNFAKEKEY1234567890ABCDEFGHIJKLMNOPQRST"};
  NSData *payloadData = [NSJSONSerialization dataWithJSONObject:fakePayload options:0 error:nil];

  NSString *payloadB64 = [payloadData base64EncodedStringWithOptions:0];
  payloadB64 = [payloadB64 stringByReplacingOccurrencesOfString:@"+" withString:@"-"];
  payloadB64 = [payloadB64 stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
  payloadB64 = [payloadB64 stringByReplacingOccurrencesOfString:@"=" withString:@""];

  NSString *fakeJWT = [NSString
      stringWithFormat:@"eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.%@.%@", payloadB64,
                       @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                       @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"];
  XCTAssertFalse(santa::NKeyTokenValidator(kTrustedNKeys, fakeJWT, kValidUserJWT).Validate());
}

- (void)testBadAccountBase64Payload {
  XCTAssertFalse(
      santa::NKeyTokenValidator(kTrustedNKeys, @"header.!!!invalid!!!.signature", kValidUserJWT)
          .Validate());
}

- (void)testUserJWTWrongIssuer {
  // kOtherAccountJWT has sub = AA6GNB3TWJ6B... which doesn't match kValidUserJWT's iss
  XCTAssertFalse(
      santa::NKeyTokenValidator(kTrustedNKeys, kOtherAccountJWT, kValidUserJWT).Validate());
}

- (void)testUserJWTTamperedSignature {
  NSString *tampered =
      [NSString stringWithFormat:@"%@X", [kValidUserJWT substringToIndex:kValidUserJWT.length - 1]];
  XCTAssertFalse(santa::NKeyTokenValidator(kTrustedNKeys, kValidAccountJWT, tampered).Validate());
}

- (void)testExpiredUserJWT {
  XCTAssertFalse(
      santa::NKeyTokenValidator(kTrustedNKeys, kValidAccountJWT, kExpiredUserJWT).Validate());
}

- (void)testUntrustedOperator {
  XCTAssertFalse(
      santa::NKeyTokenValidator(kTrustedNKeys, kUntrustedAccountJWT, kUntrustedUserJWT).Validate());
}

- (void)testEmptyTrustedKeys {
  XCTAssertFalse(santa::NKeyTokenValidator({}, kValidAccountJWT, kValidUserJWT).Validate());
}

@end
