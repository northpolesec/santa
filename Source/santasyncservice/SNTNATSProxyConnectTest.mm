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

#import "Source/santasyncservice/SNTNATSProxyConnect.h"

@interface SNTNATSProxyConnectTest : XCTestCase
@end

@implementation SNTNATSProxyConnectTest

#pragma mark - URL Parsing Tests

- (void)testParseHTTPProxyURL {
  SNTProxyConfig* config = SNTParseProxyURL(@"http://proxy.corp:8080");
  XCTAssertNotNil(config);
  XCTAssertEqualObjects(config.host, @"proxy.corp");
  XCTAssertEqual(config.port, 8080);
  XCTAssertFalse(config.useTLS);
  XCTAssertNil(config.basicAuth);
}

- (void)testParseHTTPSProxyURL {
  SNTProxyConfig* config = SNTParseProxyURL(@"https://proxy.corp:8443");
  XCTAssertNotNil(config);
  XCTAssertEqualObjects(config.host, @"proxy.corp");
  XCTAssertEqual(config.port, 8443);
  XCTAssertTrue(config.useTLS);
  XCTAssertNil(config.basicAuth);
}

- (void)testParseProxyURLWithBasicAuth {
  SNTProxyConfig* config = SNTParseProxyURL(@"http://user:pass@proxy.corp:8080");
  XCTAssertNotNil(config);
  XCTAssertEqualObjects(config.host, @"proxy.corp");
  XCTAssertEqual(config.port, 8080);
  XCTAssertFalse(config.useTLS);
  XCTAssertNotNil(config.basicAuth);
  NSData* decoded = [[NSData alloc] initWithBase64EncodedString:config.basicAuth options:0];
  NSString* decodedStr = [[NSString alloc] initWithData:decoded encoding:NSUTF8StringEncoding];
  XCTAssertEqualObjects(decodedStr, @"user:pass");
}

- (void)testParseHTTPSProxyURLWithBasicAuth {
  SNTProxyConfig* config = SNTParseProxyURL(@"https://admin:s3cret@proxy.corp:8443");
  XCTAssertNotNil(config);
  XCTAssertTrue(config.useTLS);
  XCTAssertNotNil(config.basicAuth);
  NSData* decoded = [[NSData alloc] initWithBase64EncodedString:config.basicAuth options:0];
  NSString* decodedStr = [[NSString alloc] initWithData:decoded encoding:NSUTF8StringEncoding];
  XCTAssertEqualObjects(decodedStr, @"admin:s3cret");
}

- (void)testParseProxyURLWithSpecialCharsInPassword {
  SNTProxyConfig* config = SNTParseProxyURL(@"http://user:p%40ss%3Aword@proxy.corp:8080");
  XCTAssertNotNil(config);
  NSData* decoded = [[NSData alloc] initWithBase64EncodedString:config.basicAuth options:0];
  NSString* decodedStr = [[NSString alloc] initWithData:decoded encoding:NSUTF8StringEncoding];
  XCTAssertEqualObjects(decodedStr, @"user:p@ss:word");
}

- (void)testParseProxyURLRejectsUnsupportedScheme {
  XCTAssertNil(SNTParseProxyURL(@"socks5://proxy.corp:1080"));
}

- (void)testParseProxyURLRejectsMissingPort {
  XCTAssertNil(SNTParseProxyURL(@"http://proxy.corp"));
}

- (void)testParseProxyURLRejectsMissingHost {
  XCTAssertNil(SNTParseProxyURL(@":8080"));
}

- (void)testParseProxyURLRejectsEmptyString {
  XCTAssertNil(SNTParseProxyURL(@""));
}

- (void)testParseProxyURLRejectsNonsense {
  XCTAssertNil(SNTParseProxyURL(@"not-a-url"));
}

#pragma mark - HTTP Status Line Parsing Tests

- (void)testParseHTTP11Status200 {
  XCTAssertEqual(SNTParseHTTPStatusLine(@"HTTP/1.1 200 Connection established"), 200);
}

- (void)testParseHTTP10Status200 {
  XCTAssertEqual(SNTParseHTTPStatusLine(@"HTTP/1.0 200 Connection established"), 200);
}

- (void)testParseHTTPStatus407 {
  XCTAssertEqual(SNTParseHTTPStatusLine(@"HTTP/1.1 407 Proxy Authentication Required"), 407);
}

- (void)testParseHTTPStatus502 {
  XCTAssertEqual(SNTParseHTTPStatusLine(@"HTTP/1.1 502 Bad Gateway"), 502);
}

- (void)testParseHTTPStatusMalformed {
  XCTAssertEqual(SNTParseHTTPStatusLine(@"garbage"), -1);
}

- (void)testParseHTTPStatusEmpty {
  XCTAssertEqual(SNTParseHTTPStatusLine(@""), -1);
}

#pragma mark - Closure Lifecycle Tests

- (void)testClosureCreateAndDestroy {
  SNTProxyConfig* config = SNTParseProxyURL(@"http://user:pass@proxy.corp:8080");
  SNTProxyClosure* closure = SNTProxyClosureCreate(config);
  XCTAssertTrue(closure != NULL);
  XCTAssertEqual(strcmp(closure->proxyHost, "proxy.corp"), 0);
  XCTAssertEqual(closure->proxyPort, 8080);
  XCTAssertFalse(closure->proxyUseTLS);
  XCTAssertTrue(closure->basicAuth != NULL);
  XCTAssertTrue(closure->customCAPEM == NULL);
  SNTProxyClosureDestroy(closure);
}

- (void)testClosureWithCustomCA {
  SNTProxyConfig* config = SNTParseProxyURL(@"http://proxy.corp:8080");
  config.customCAData = [@"-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
      dataUsingEncoding:NSUTF8StringEncoding];
  SNTProxyClosure* closure = SNTProxyClosureCreate(config);
  XCTAssertTrue(closure != NULL);
  XCTAssertTrue(closure->customCAPEM != NULL);
  XCTAssertTrue(strstr(closure->customCAPEM, "BEGIN CERTIFICATE") != NULL);
  SNTProxyClosureDestroy(closure);
}

@end
