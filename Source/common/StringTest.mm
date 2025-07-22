/// Copyright 2025 North Pole Security, Inc.
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

#include "Source/common/String.h"

#include <EndpointSecurity/ESTypes.h>
#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#include <string>
#include <string_view>

using namespace santa;

@interface StringTest : XCTestCase
@end

@implementation StringTest

#pragma mark - NSStringToUTF8StringView Tests

- (void)testNSStringToUTF8StringView_BasicString {
  NSString *s = @"Hello, World!";
  std::string_view result = NSStringToUTF8StringView(s);
  XCTAssertEqual(result.size(), 13);
  XCTAssertEqual(result, "Hello, World!");
}

- (void)testNSStringToUTF8StringView_EmptyString {
  NSString *s = @"";
  std::string_view result = NSStringToUTF8StringView(s);
  XCTAssertEqual(result.size(), 0);
  XCTAssertEqual(result, "");
}

- (void)testNSStringToUTF8StringView_UnicodeString {
  NSString *s = @"Hello 🌍";
  std::string_view result = NSStringToUTF8StringView(s);
  XCTAssertEqual(result.size(), 10);
  XCTAssertEqual(result, "Hello 🌍");
}

#pragma mark - NSStringToUTF8String Tests

- (void)testNSStringToUTF8String_BasicString {
  NSString *s = @"Hello, World!";
  std::string result = NSStringToUTF8String(s);
  XCTAssertEqual(result.size(), 13);
  XCTAssertEqual(result, "Hello, World!");
}

- (void)testNSStringToUTF8String_EmptyString {
  NSString *s = @"";
  std::string result = NSStringToUTF8String(s);
  XCTAssertEqual(result.size(), 0);
  XCTAssertEqual(result, "");
}

- (void)testNSStringToUTF8String_UnicodeString {
  NSString *s = @"Hello 🌍";
  std::string result = NSStringToUTF8String(s);

  XCTAssertEqual(result, "Hello 🌍");
  XCTAssertEqual(result.size(), 10);
}

#pragma mark - UTF8StringToNSString Tests

- (void)testUTF8StringToNSString_StdString {
  std::string s = "Hello, World!";
  NSString *result = UTF8StringToNSString(s);
  XCTAssertEqualObjects(result, @"Hello, World!");
}

- (void)testUTF8StringToNSString_EmptyStdString {
  std::string s = "";
  NSString *result = UTF8StringToNSString(s);
  XCTAssertEqualObjects(result, @"");
}

- (void)testUTF8StringToNSString_CString {
  const char *s = "Hello, World!";
  NSString *result = UTF8StringToNSString(s);
  XCTAssertEqualObjects(result, @"Hello, World!");
}

- (void)testUTF8StringToNSString_EmptyCString {
  const char *s = "";
  NSString *result = UTF8StringToNSString(s);
  XCTAssertEqualObjects(result, @"");
}

- (void)testUTF8StringToNSString_StringView {
  std::string_view strView = "Hello, World!";
  NSString *result = UTF8StringToNSString(strView);
  XCTAssertEqualObjects(result, @"Hello, World!");
}

- (void)testUTF8StringToNSString_EmptyStringView {
  std::string_view strView = "";
  NSString *result = UTF8StringToNSString(strView);
  XCTAssertEqualObjects(result, @"");
}

- (void)testUTF8StringToNSString_NoNullTerminator {
  char data[] = {'H', 'e', 'l', 'l', 'o', ',', ' ', 'W', 'o', 'r', 'l', 'd', '!'};
  std::string_view s(data, 5);
  NSString *result = UTF8StringToNSString(s);
  XCTAssertEqualObjects(result, @"Hello");
}

- (void)testUTF8StringToNSString_UnicodeContent {
  std::string s = "Hello 🌍";
  NSString *result = UTF8StringToNSString(s);
  XCTAssertEqualObjects(result, @"Hello 🌍");
}

@end
