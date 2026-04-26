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

#import "Source/common/SNTSandboxExecRequest.h"

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

@interface SNTSandboxExecRequestTest : XCTestCase
@end

@implementation SNTSandboxExecRequestTest

- (void)testRoundTripSecureCoding {
  SNTRuleIdentifiers* ids = [[SNTRuleIdentifiers alloc]
      initWithRuleIdentifiers:{.cdhash = @"0102030405060708090a0b0c0d0e0f1011121314",
                               .binarySHA256 = @"abcd1234",
                               .signingID = @"TID:com.ex.app",
                               .certificateSHA256 = @"cert",
                               .teamID = @"TID"}];
  SNTSandboxExecRequest* req =
      [[SNTSandboxExecRequest alloc] initWithIdentifiers:ids
                                                   fsDev:0x1234
                                                   fsIno:0xdeadbeefULL
                                            resolvedPath:@"/usr/local/bin/foo"];

  NSError* err = nil;
  NSData* data = [NSKeyedArchiver archivedDataWithRootObject:req
                                       requiringSecureCoding:YES
                                                       error:&err];
  XCTAssertNotNil(data);
  XCTAssertNil(err);

  SNTSandboxExecRequest* decoded =
      [NSKeyedUnarchiver unarchivedObjectOfClass:[SNTSandboxExecRequest class]
                                        fromData:data
                                           error:&err];
  XCTAssertNotNil(decoded);
  XCTAssertNil(err);
  XCTAssertEqualObjects(decoded.identifiers.cdhash, ids.cdhash);
  XCTAssertEqualObjects(decoded.identifiers.binarySHA256, @"abcd1234");
  XCTAssertEqualObjects(decoded.identifiers.teamID, @"TID");
  XCTAssertEqual(decoded.fsDev, req.fsDev);
  XCTAssertEqual(decoded.fsIno, req.fsIno);
  XCTAssertEqualObjects(decoded.resolvedPath, @"/usr/local/bin/foo");

  // cdhashBytes is derived from identifiers.cdhash.
  XCTAssertEqual(decoded.identifiers.cdhashBytes.length, 20u);
}

- (void)testCdhashBytesNilForUnsignedBinary {
  SNTRuleIdentifiers* ids =
      [[SNTRuleIdentifiers alloc] initWithRuleIdentifiers:{.binarySHA256 = @"abcd1234"}];
  XCTAssertNil(ids.cdhashBytes);
}

- (void)testCdhashBytesNilForMalformedHex {
  SNTRuleIdentifiers* ids =
      [[SNTRuleIdentifiers alloc] initWithRuleIdentifiers:{.cdhash = @"not40chars"}];
  XCTAssertNil(ids.cdhashBytes);
}

@end
