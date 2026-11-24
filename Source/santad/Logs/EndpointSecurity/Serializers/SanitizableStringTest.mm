/// Copyright 2022 Google Inc. All rights reserved.
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

#include "Source/santad/Logs/EndpointSecurity/Serializers/SanitizableString.h"

#include <EndpointSecurity/ESTypes.h>
#import <XCTest/XCTest.h>
#include <string>
#include <string_view>

#include "Source/common/TestUtils.h"

using santa::AppendSanitized;

static std::string Sanitize(std::string_view src) {
  std::string dst;
  AppendSanitized(dst, src);
  return dst;
}

@interface SanitizableStringTest : XCTestCase
@end

@implementation SanitizableStringTest

- (void)testAppendSanitized {
  XCTAssertCppStringEqual(Sanitize(""), "");
  XCTAssertCppStringEqual(Sanitize("nothing_to_sanitize"), "nothing_to_sanitize");

  XCTAssertCppStringEqual(Sanitize("|"), "<pipe>");
  XCTAssertCppStringEqual(Sanitize("\n"), "\\n");
  XCTAssertCppStringEqual(Sanitize("\r"), "\\r");

  XCTAssertCppStringEqual(Sanitize("a\nb\rc|"), "a\\nb\\rc<pipe>");
  XCTAssertCppStringEqual(Sanitize("a|trail"), "a<pipe>trail");
  XCTAssertCppStringEqual(Sanitize("||"), "<pipe><pipe>");

  // Existing contents of dst are preserved
  std::string dst = "prefix=";
  AppendSanitized(dst, "x|y");
  XCTAssertCppStringEqual(dst, "prefix=x<pipe>y");

  // Handle some long strings
  std::string base(66 * 1024, 'A');
  XCTAssertCppStringEqual(Sanitize(base + "|abc"), base + "<pipe>abc");
}

- (void)testSanitizesFullLength {
  // Compare std::strings directly; C string comparison would stop at the NUL.
  std::string_view src("a\0|b", 4);
  XCTAssertTrue(Sanitize(src) == std::string("a\0<pipe>b", 9));

  // Only `length` bytes are read
  std::string_view prefix("ab|cd", 2);
  XCTAssertCppStringEqual(Sanitize(prefix), "ab");
}

- (void)testOverloads {
  const char* sanitizable = "sani|tizable";
  const char* sanitized = "sani<pipe>tizable";

  std::string dst;
  es_string_token_t tok = {.length = strlen(sanitizable), .data = sanitizable};
  AppendSanitized(dst, tok);
  XCTAssertCppStringEqual(dst, sanitized);

  dst.clear();
  es_file_t file = MakeESFile(sanitizable);
  AppendSanitized(dst, &file);
  XCTAssertCppStringEqual(dst, sanitized);

  dst.clear();
  AppendSanitized(dst, @"sani|tizable");
  XCTAssertCppStringEqual(dst, sanitized);

  dst.clear();
  AppendSanitized(dst, (NSString*)nil);
  XCTAssertCppStringEqual(dst, "");
}

@end
