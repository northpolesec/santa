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

#import <XCTest/XCTest.h>

#import "Source/common/MOLXPCConnection.h"

@interface SNTCommandVersion : NSObject
- (instancetype)initWithDaemonConnection:(MOLXPCConnection*)daemonConn;
- (NSString*)composeVersionsFromDict:(NSDictionary*)dict;
@end

@interface SNTCommandVersionTest : XCTestCase
@property SNTCommandVersion* cmd;
@end

@implementation SNTCommandVersionTest

- (void)setUp {
  self.cmd = [[SNTCommandVersion alloc] initWithDaemonConnection:nil];
}

- (void)testComposeVersionIgnoresCommitHash {
  NSDictionary* dict = @{
    @"CFBundleShortVersionString" : @"2026.10",
    @"CFBundleVersion" : @"2026.10.123",
    @"SNTCommitHash" : @"abcdef0123456789",
  };
  XCTAssertEqualObjects([self.cmd composeVersionsFromDict:dict], @"2026.10 (build 123)");
}

- (void)testComposeVersionEmptyFullVersion {
  NSDictionary* dict = @{@"CFBundleShortVersionString" : @"2026.10"};
  XCTAssertEqualObjects([self.cmd composeVersionsFromDict:dict], @"");
}

@end
