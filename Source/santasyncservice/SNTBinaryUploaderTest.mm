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

#import <CommonCrypto/CommonDigest.h>
#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#import "Source/santasyncservice/SNTBinaryUploader.h"

#include "commands/v1.pb.h"

namespace pbv1 = ::santa::commands::v1;

// Test-only entry points. Production callers always go through
// -handleUploadRequest:replyTopic:.
@interface SNTBinaryUploader (Testing)
- (void)performUploadForRequest:(const ::pbv1::BinaryUploadRequest &)request
                     replyTopic:(NSString *)replyTopic;

// Returns the absolute path of a freshly built multipart body file. Caller
// must unlink it. Returns nil on failure.
- (NSString *)buildMultipartBodyForFile:(NSString *)filePath
                             formValues:(NSDictionary<NSString *, NSString *> *)formValues
                               boundary:(NSString *)boundary;
@end

// Captures the last published response so tests can assert on disposition,
// sha256_computed, bytes_uploaded, etc.
@interface SNTBinaryUploaderResponseCapture : NSObject
@property(atomic, copy) NSString *replyTopic;
@property(atomic) BOOL invoked;
@property(atomic) pbv1::BinaryUploadResponse::Disposition disposition;
@property(atomic, copy) NSString *message;
@property(atomic, copy) NSString *sha256Computed;
@property(atomic) int64_t bytesUploaded;
- (SNTBinaryUploaderPublishBlock)block;
@end

@implementation SNTBinaryUploaderResponseCapture
- (SNTBinaryUploaderPublishBlock)block {
  __weak SNTBinaryUploaderResponseCapture *weakSelf = self;
  return ^(NSString *replyTopic, const pbv1::SantaCommandResponse &response) {
    __strong SNTBinaryUploaderResponseCapture *strongSelf = weakSelf;
    if (!strongSelf) return;
    strongSelf.invoked = YES;
    strongSelf.replyTopic = replyTopic;
    if (response.result_case() == pbv1::SantaCommandResponse::kBinaryUpload) {
      const auto &bu = response.binary_upload();
      strongSelf.disposition = bu.disposition();
      strongSelf.message = [NSString stringWithUTF8String:bu.message().c_str()];
      strongSelf.sha256Computed = [NSString stringWithUTF8String:bu.sha256_computed().c_str()];
      strongSelf.bytesUploaded = bu.bytes_uploaded();
    }
  };
}
@end

@interface SNTBinaryUploaderTest : XCTestCase
@property(nonatomic) SNTBinaryUploader *uploader;
@property(nonatomic) SNTBinaryUploaderResponseCapture *capture;
@property(nonatomic, copy) NSString *tempDir;
@end

@implementation SNTBinaryUploaderTest

- (void)setUp {
  [super setUp];
  self.capture = [[SNTBinaryUploaderResponseCapture alloc] init];
  // The session is unused in Task-3 tests (we don't reach the upload phase).
  self.uploader = [[SNTBinaryUploader alloc] initWithPublishBlock:[self.capture block]
                                                          session:[NSURLSession sharedSession]];

  NSString *root = NSTemporaryDirectory();
  NSString *suffix = [[NSUUID UUID] UUIDString];
  self.tempDir = [root stringByAppendingPathComponent:suffix];
  [[NSFileManager defaultManager] createDirectoryAtPath:self.tempDir
                            withIntermediateDirectories:YES
                                             attributes:nil
                                                  error:nil];
}

- (void)tearDown {
  [[NSFileManager defaultManager] removeItemAtPath:self.tempDir error:nil];
  self.uploader = nil;
  self.capture = nil;
  [super tearDown];
}

- (NSString *)writeFile:(NSString *)name bytes:(NSData *)bytes {
  NSString *path = [self.tempDir stringByAppendingPathComponent:name];
  [bytes writeToFile:path atomically:YES];
  return path;
}

- (void)testNotFoundWhenPathDoesNotExist {
  pbv1::BinaryUploadRequest req;
  req.set_path("/var/empty/this/file/does/not/exist.bin");

  [self.uploader performUploadForRequest:req replyTopic:@"_INBOX.abc"];

  XCTAssertTrue(self.capture.invoked);
  XCTAssertEqual(self.capture.disposition, pbv1::BinaryUploadResponse::DISPOSITION_NOT_FOUND);
  XCTAssertEqualObjects(self.capture.replyTopic, @"_INBOX.abc");
}

- (void)testHashMismatchWhenRequestSha256DiffersFromComputed {
  NSData *bytes = [@"hello world" dataUsingEncoding:NSUTF8StringEncoding];
  NSString *path = [self writeFile:@"a.bin" bytes:bytes];

  pbv1::BinaryUploadRequest req;
  req.set_path(path.UTF8String);
  // Expected sha256("hello world") =
  // "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
  req.set_sha256("0000000000000000000000000000000000000000000000000000000000000000");

  [self.uploader performUploadForRequest:req replyTopic:@"_INBOX.abc"];

  XCTAssertTrue(self.capture.invoked);
  XCTAssertEqual(self.capture.disposition, pbv1::BinaryUploadResponse::DISPOSITION_HASH_MISMATCH);
  XCTAssertEqualObjects(self.capture.sha256Computed,
                        @"b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
}

- (void)testEmptyRequestSha256SkipsVerificationStep {
  // With request.sha256 empty, even when the on-disk bytes hash to something
  // specific, the disposition must NOT be HASH_MISMATCH. (It will bail later
  // with HTTP_ERROR or INTERNAL_ERROR since signed_post.url is empty, but
  // never with HASH_MISMATCH.)
  NSData *bytes = [@"some bytes" dataUsingEncoding:NSUTF8StringEncoding];
  NSString *path = [self writeFile:@"b.bin" bytes:bytes];

  pbv1::BinaryUploadRequest req;
  req.set_path(path.UTF8String);
  req.set_sha256("");

  [self.uploader performUploadForRequest:req replyTopic:@"_INBOX.abc"];

  XCTAssertTrue(self.capture.invoked);
  XCTAssertNotEqual(self.capture.disposition,
                    pbv1::BinaryUploadResponse::DISPOSITION_HASH_MISMATCH);
}

@end

#pragma mark - Multipart body builder tests

@interface SNTBinaryUploaderMultipartTest : XCTestCase
@property(nonatomic) SNTBinaryUploader *uploader;
@property(nonatomic, copy) NSString *tempDir;
@end

@implementation SNTBinaryUploaderMultipartTest

- (void)setUp {
  [super setUp];
  self.uploader = [[SNTBinaryUploader alloc]
      initWithPublishBlock:^(NSString *t, const pbv1::SantaCommandResponse &r) {
      }
                   session:[NSURLSession sharedSession]];
  self.tempDir =
      [NSTemporaryDirectory() stringByAppendingPathComponent:[[NSUUID UUID] UUIDString]];
  [[NSFileManager defaultManager] createDirectoryAtPath:self.tempDir
                            withIntermediateDirectories:YES
                                             attributes:nil
                                                  error:nil];
}

- (void)tearDown {
  [[NSFileManager defaultManager] removeItemAtPath:self.tempDir error:nil];
  [super tearDown];
}

- (void)testMultipartBodyHasFileLastAndNoExtraFields {
  NSData *fileBytes = [@"BINARYBODY" dataUsingEncoding:NSUTF8StringEncoding];
  NSString *filePath = [self.tempDir stringByAppendingPathComponent:@"upload.bin"];
  [fileBytes writeToFile:filePath atomically:YES];

  NSDictionary *form = @{
    @"key" : @"uploads/abc",
    @"x-amz-credential" : @"AKIA.../20260522/us-east-1/s3/aws4_request",
    @"policy" : @"eyJjb25kaXRpb25zIjpbXX0=",
    @"x-amz-signature" : @"deadbeef",
  };
  NSString *boundary = @"BOUNDARY-1234";

  NSString *bodyPath = [self.uploader buildMultipartBodyForFile:filePath
                                                     formValues:form
                                                       boundary:boundary];
  XCTAssertNotNil(bodyPath);

  NSString *body = [NSString stringWithContentsOfFile:bodyPath
                                             encoding:NSUTF8StringEncoding
                                                error:nil];
  XCTAssertNotNil(body);

  // Every form key appears exactly once.
  for (NSString *k in form) {
    NSString *needle = [NSString stringWithFormat:@"name=\"%@\"", k];
    XCTAssertEqual([body componentsSeparatedByString:needle].count, 2u,
                   @"form key %@ should appear exactly once", k);
  }

  // The file part exists, and every form part precedes it.
  NSRange fileRange = [body rangeOfString:@"name=\"file\""];
  XCTAssertNotEqual(fileRange.location, (NSUInteger)NSNotFound);
  for (NSString *k in form) {
    NSRange formRange = [body rangeOfString:[NSString stringWithFormat:@"name=\"%@\"", k]];
    XCTAssertLessThan(formRange.location, fileRange.location,
                      @"form key %@ must precede file part", k);
  }

  // No extra Content-Type form field. (The HTTP header is separate.)
  XCTAssertEqual([body rangeOfString:@"name=\"Content-Type\""].location, (NSUInteger)NSNotFound);
  XCTAssertEqual([body rangeOfString:@"name=\"content-type\""].location, (NSUInteger)NSNotFound);

  // The closing boundary is the final non-empty line.
  NSString *closing = [NSString stringWithFormat:@"\r\n--%@--\r\n", boundary];
  XCTAssertTrue([body hasSuffix:closing], @"body must end with closing boundary");

  unlink(bodyPath.UTF8String);
}

- (void)testMultipartBodyIncludesEmptyFormValue {
  NSData *fileBytes = [@"X" dataUsingEncoding:NSUTF8StringEncoding];
  NSString *filePath = [self.tempDir stringByAppendingPathComponent:@"x.bin"];
  [fileBytes writeToFile:filePath atomically:YES];

  NSString *bodyPath = [self.uploader buildMultipartBodyForFile:filePath
                                                     formValues:@{@"acl" : @""}
                                                       boundary:@"B"];
  XCTAssertNotNil(bodyPath);
  NSString *body = [NSString stringWithContentsOfFile:bodyPath
                                             encoding:NSUTF8StringEncoding
                                                error:nil];
  XCTAssertNotEqual([body rangeOfString:@"name=\"acl\""].location, (NSUInteger)NSNotFound);
  unlink(bodyPath.UTF8String);
}

- (void)testMultipartBodyContainsFileBytesAfterFileHeader {
  NSData *fileBytes = [@"PAYLOAD-MARKER" dataUsingEncoding:NSUTF8StringEncoding];
  NSString *filePath = [self.tempDir stringByAppendingPathComponent:@"p.bin"];
  [fileBytes writeToFile:filePath atomically:YES];

  NSString *bodyPath = [self.uploader buildMultipartBodyForFile:filePath
                                                     formValues:@{@"key" : @"uploads/p.bin"}
                                                       boundary:@"B"];
  XCTAssertNotNil(bodyPath);

  NSData *body = [NSData dataWithContentsOfFile:bodyPath];
  NSData *marker = [@"PAYLOAD-MARKER" dataUsingEncoding:NSUTF8StringEncoding];
  NSRange r = [body rangeOfData:marker options:0 range:NSMakeRange(0, body.length)];
  XCTAssertNotEqual(r.location, (NSUInteger)NSNotFound, @"file bytes must appear in body");

  unlink(bodyPath.UTF8String);
}

@end

#pragma mark - Upload phase tests

// Intercepts every URL request and replies with a programmable response.
// Class-level state, since NSURLProtocol is instantiated per-request and
// tests need to inspect what got captured after the fact.
@interface SNTTestURLProtocol : NSURLProtocol
@property(class, atomic) NSInteger statusCode;
@property(class, atomic, copy) NSData *responseBody;
@property(class, atomic) NSError *responseError;
@property(class, atomic, readonly) NSString *lastRequestContentTypeHeader;
+ (void)reset;
@end

@implementation SNTTestURLProtocol

static NSInteger gStatusCode = 200;
static NSData *gResponseBody;
static NSError *gResponseError;
static NSString *gLastRequestContentTypeHeader;
static NSLock *gLock;

+ (void)initialize {
  if (self == [SNTTestURLProtocol class]) gLock = [[NSLock alloc] init];
}

+ (NSInteger)statusCode {
  return gStatusCode;
}
+ (void)setStatusCode:(NSInteger)s {
  gStatusCode = s;
}
+ (NSData *)responseBody {
  return gResponseBody;
}
+ (void)setResponseBody:(NSData *)d {
  gResponseBody = [d copy];
}
+ (NSError *)responseError {
  return gResponseError;
}
+ (void)setResponseError:(NSError *)e {
  gResponseError = e;
}
+ (NSString *)lastRequestContentTypeHeader {
  [gLock lock];
  NSString *s = [gLastRequestContentTypeHeader copy];
  [gLock unlock];
  return s;
}
+ (void)reset {
  gStatusCode = 200;
  gResponseBody = [NSData data];
  gResponseError = nil;
  [gLock lock];
  gLastRequestContentTypeHeader = nil;
  [gLock unlock];
}

+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
  return YES;
}
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request {
  return request;
}

- (void)startLoading {
  [gLock lock];
  gLastRequestContentTypeHeader = [self.request valueForHTTPHeaderField:@"Content-Type"];
  [gLock unlock];

  if (gResponseError) {
    [self.client URLProtocol:self didFailWithError:gResponseError];
    return;
  }
  NSHTTPURLResponse *resp =
      [[NSHTTPURLResponse alloc] initWithURL:self.request.URL
                                  statusCode:gStatusCode
                                 HTTPVersion:@"HTTP/1.1"
                                headerFields:@{@"Content-Type" : @"text/plain"}];
  [self.client URLProtocol:self didReceiveResponse:resp
        cacheStoragePolicy:NSURLCacheStorageNotAllowed];
  if (gResponseBody.length) {
    [self.client URLProtocol:self didLoadData:gResponseBody];
  }
  [self.client URLProtocolDidFinishLoading:self];
}

- (void)stopLoading {
}

@end

static SNTBinaryUploader *MakeUploaderWithInterception(SNTBinaryUploaderPublishBlock pub) {
  NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration ephemeralSessionConfiguration];
  cfg.protocolClasses = @[ [SNTTestURLProtocol class] ];
  NSURLSession *session = [NSURLSession sessionWithConfiguration:cfg];
  return [[SNTBinaryUploader alloc] initWithPublishBlock:pub session:session];
}

static NSString *Sha256Hex(NSData *data) {
  unsigned char digest[CC_SHA256_DIGEST_LENGTH];
  CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
  NSMutableString *s = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
  for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) [s appendFormat:@"%02x", digest[i]];
  return s;
}

@interface SNTBinaryUploaderUploadTest : XCTestCase
@property(nonatomic) SNTBinaryUploaderResponseCapture *capture;
@property(nonatomic) SNTBinaryUploader *uploader;
@property(nonatomic, copy) NSString *tempDir;
@end

@implementation SNTBinaryUploaderUploadTest

- (void)setUp {
  [super setUp];
  [SNTTestURLProtocol reset];
  self.capture = [[SNTBinaryUploaderResponseCapture alloc] init];
  self.uploader = MakeUploaderWithInterception([self.capture block]);
  self.tempDir =
      [NSTemporaryDirectory() stringByAppendingPathComponent:[[NSUUID UUID] UUIDString]];
  [[NSFileManager defaultManager] createDirectoryAtPath:self.tempDir
                            withIntermediateDirectories:YES
                                             attributes:nil
                                                  error:nil];
}

- (void)tearDown {
  [[NSFileManager defaultManager] removeItemAtPath:self.tempDir error:nil];
  [SNTTestURLProtocol reset];
  [super tearDown];
}

- (NSString *)writeFile:(NSString *)name bytes:(NSData *)b {
  NSString *p = [self.tempDir stringByAppendingPathComponent:name];
  [b writeToFile:p atomically:YES];
  return p;
}

- (void)testCompletedDispositionOn204 {
  NSData *bytes = [@"some-binary-bytes" dataUsingEncoding:NSUTF8StringEncoding];
  NSString *path = [self writeFile:@"upload.bin" bytes:bytes];

  pbv1::BinaryUploadRequest req;
  req.set_path(path.UTF8String);
  auto *sp = req.mutable_signed_post();
  sp->set_url("https://example-bucket.s3.amazonaws.com/");
  (*sp->mutable_form_values())["key"] = "uploads/foo.bin";

  SNTTestURLProtocol.statusCode = 204;
  [self.uploader performUploadForRequest:req replyTopic:@"_INBOX.x"];

  XCTAssertTrue(self.capture.invoked);
  XCTAssertEqual(self.capture.disposition, pbv1::BinaryUploadResponse::DISPOSITION_COMPLETED);
  XCTAssertEqualObjects(self.capture.sha256Computed, Sha256Hex(bytes));
  // bytes_uploaded reflects the full multipart body length (file + boundaries
  // + form parts), which is strictly larger than just the file bytes.
  XCTAssertGreaterThan(self.capture.bytesUploaded, (int64_t)bytes.length);

  NSString *ct = [SNTTestURLProtocol lastRequestContentTypeHeader];
  XCTAssertTrue([ct hasPrefix:@"multipart/form-data; boundary="]);
}

- (void)testHTTPErrorDispositionOn403 {
  NSData *bytes = [@"X" dataUsingEncoding:NSUTF8StringEncoding];
  NSString *path = [self writeFile:@"f.bin" bytes:bytes];

  pbv1::BinaryUploadRequest req;
  req.set_path(path.UTF8String);
  req.mutable_signed_post()->set_url("https://example.invalid/");

  SNTTestURLProtocol.statusCode = 403;
  SNTTestURLProtocol.responseBody = [@"<Error>Forbidden</Error>"
      dataUsingEncoding:NSUTF8StringEncoding];

  [self.uploader performUploadForRequest:req replyTopic:@"_INBOX.x"];

  XCTAssertTrue(self.capture.invoked);
  XCTAssertEqual(self.capture.disposition, pbv1::BinaryUploadResponse::DISPOSITION_HTTP_ERROR);
  XCTAssertNotEqual([self.capture.message rangeOfString:@"403"].location, (NSUInteger)NSNotFound);
  XCTAssertNotEqual([self.capture.message rangeOfString:@"Forbidden"].location,
                    (NSUInteger)NSNotFound);
}

- (void)testHTTPErrorDispositionOnNetworkError {
  NSData *bytes = [@"X" dataUsingEncoding:NSUTF8StringEncoding];
  NSString *path = [self writeFile:@"f.bin" bytes:bytes];

  pbv1::BinaryUploadRequest req;
  req.set_path(path.UTF8String);
  req.mutable_signed_post()->set_url("https://example.invalid/");

  SNTTestURLProtocol.responseError = [NSError
      errorWithDomain:NSURLErrorDomain
                 code:NSURLErrorCannotFindHost
             userInfo:@{
               NSLocalizedDescriptionKey :
                   @"A server with the specified hostname could not be found."
             }];

  [self.uploader performUploadForRequest:req replyTopic:@"_INBOX.x"];

  XCTAssertEqual(self.capture.disposition, pbv1::BinaryUploadResponse::DISPOSITION_HTTP_ERROR);
  XCTAssertNotEqual([self.capture.message rangeOfString:@"hostname"].location,
                    (NSUInteger)NSNotFound);
}

- (void)testInvalidURLYieldsInternalError {
  NSData *bytes = [@"X" dataUsingEncoding:NSUTF8StringEncoding];
  NSString *path = [self writeFile:@"f.bin" bytes:bytes];

  pbv1::BinaryUploadRequest req;
  req.set_path(path.UTF8String);
  req.mutable_signed_post()->set_url("");  // unparseable

  [self.uploader performUploadForRequest:req replyTopic:@"_INBOX.x"];

  XCTAssertEqual(self.capture.disposition, pbv1::BinaryUploadResponse::DISPOSITION_INTERNAL_ERROR);
}

@end
