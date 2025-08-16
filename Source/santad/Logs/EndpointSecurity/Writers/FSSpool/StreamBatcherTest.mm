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

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#include <cstring>
#include <random>

#include <sys/stat.h>

#include "Source/santad/Logs/EndpointSecurity/Writers/FSSpool/AnyBatcher.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/FSSpool/StreamBatcher.h"
#include "absl/status/statusor.h"
#include "zstd.h"

@interface StreamBatcherTest : XCTestCase
@property NSFileManager *fileMgr;
@property NSString *testDir;
@end

@implementation StreamBatcherTest

- (void)setUp {
  self.fileMgr = [NSFileManager defaultManager];

  self.testDir = [NSString
      stringWithFormat:@"%@santa-stream-batcher-test-%d", NSTemporaryDirectory(), getpid()];

  XCTAssertTrue([self.fileMgr createDirectoryAtPath:self.testDir
                        withIntermediateDirectories:YES
                                         attributes:nil
                                              error:nil]);
}

- (void)tearDown {
  XCTAssertTrue([self.fileMgr removeItemAtPath:self.testDir error:nil]);
}

- (void)testCompression {
  // This test ensures that the files produced via the Uncompressed/Gzip/Zstd stream batchers
  // meet expectations. Additionally, the Zstd file is decompressed and compared to the
  // uncompressed output to ensure it matches.

  // This test should not generally continue after any fialure due to filesystem interactions
  self.continueAfterFailure = NO;

  static constexpr size_t kFileSize = 256 * 1024;
  // Give some wiggle room on top of kFileSize to hold decompressed output
  static constexpr size_t kDstBuffSize = kFileSize * 2;

  // Seed on time to get new values on each test run
  std::mt19937 rng(static_cast<unsigned int>(time(NULL)));
  // Semi arbitrary per-message min/max
  std::uniform_int_distribution<size_t> sizeDist(500, 1100);
  // Keep range of chars mostly printable so that at least some compression can happen
  std::uniform_int_distribution<uint8_t> byteDist(32, 126);

  ::fsspool::UncompressedStreamBatcher uncompressedStream;
  ::fsspool::GzipStreamBatcher gzipStream(
      ^(google::protobuf::io::ZeroCopyOutputStream *raw_stream) {
        return std::make_shared<google::protobuf::io::GzipOutputStream>(raw_stream);
      });
  ::fsspool::ZstdStreamBatcher zstdStream(
      ^(google::protobuf::io::ZeroCopyOutputStream *raw_stream) {
        return ::fsspool::ZstdOutputStream::Create(raw_stream);
      });

  // Create and open the test files
  NSString *uncompressedFile = [NSString stringWithFormat:@"%@/%@", self.testDir, @"uncomp.bin"];
  NSString *gzipFile = [NSString stringWithFormat:@"%@/%@", self.testDir, @"gzip.bin"];
  NSString *zstdFile = [NSString stringWithFormat:@"%@/%@", self.testDir, @"zstd.bin"];

  XCTAssertTrue([self.fileMgr createFileAtPath:uncompressedFile contents:nil attributes:nil]);
  XCTAssertTrue([self.fileMgr createFileAtPath:gzipFile contents:nil attributes:nil]);
  XCTAssertTrue([self.fileMgr createFileAtPath:zstdFile contents:nil attributes:nil]);

  NSFileHandle *uncompressedHandle = [NSFileHandle fileHandleForWritingAtPath:uncompressedFile];
  NSFileHandle *gzipHandle = [NSFileHandle fileHandleForWritingAtPath:gzipFile];
  NSFileHandle *zstdHandle = [NSFileHandle fileHandleForWritingAtPath:zstdFile];

  XCTAssertNotNil(uncompressedHandle);
  XCTAssertNotNil(gzipHandle);
  XCTAssertNotNil(zstdHandle);

  // Initialize all the streams
  uncompressedStream.InitializeBatch(uncompressedHandle.fileDescriptor);
  gzipStream.InitializeBatch(gzipHandle.fileDescriptor);
  zstdStream.InitializeBatch(zstdHandle.fileDescriptor);

  // Write random-sized "messages" of random bytes until the batch size is reached.
  size_t currentBytes = 0;
  do {
    size_t numBytes = sizeDist(rng);
    std::vector<uint8_t> buf;
    buf.reserve(numBytes);
    for (size_t i = 0; i < numBytes; ++i) {
      buf.push_back(byteDist(rng));
    }

    XCTAssertTrue(uncompressedStream.Write(buf).ok());
    XCTAssertTrue(gzipStream.Write(buf).ok());
    XCTAssertTrue(zstdStream.Write(buf).ok());

    currentBytes += numBytes;
  } while (currentBytes < kFileSize);

  // Close out all the streams
  absl::StatusOr<size_t> statusOrSizeUncompressed =
      uncompressedStream.CompleteBatch(uncompressedHandle.fileDescriptor);
  XCTAssertTrue(statusOrSizeUncompressed.ok());

  absl::StatusOr<size_t> statusOrSizeGzip = gzipStream.CompleteBatch(gzipHandle.fileDescriptor);
  XCTAssertTrue(statusOrSizeGzip.ok());

  absl::StatusOr<size_t> statusOrSizeZstd = zstdStream.CompleteBatch(zstdHandle.fileDescriptor);
  XCTAssertTrue(statusOrSizeZstd.ok());

  // Number of bytes written should be the same
  XCTAssertEqual(*statusOrSizeUncompressed, *statusOrSizeGzip);
  XCTAssertEqual(*statusOrSizeUncompressed, *statusOrSizeZstd);

  [uncompressedHandle closeFile];
  [gzipHandle closeFile];
  [zstdHandle closeFile];

  // Stat files, ensure compression happened
  struct stat sbUncompressed, sbGzip, sbZstd;
  XCTAssertEqual(0, stat(uncompressedFile.UTF8String, &sbUncompressed));
  XCTAssertEqual(0, stat(gzipFile.UTF8String, &sbGzip));
  XCTAssertEqual(0, stat(zstdFile.UTF8String, &sbZstd));

  XCTAssertLessThan(sbGzip.st_size, sbUncompressed.st_size);
  XCTAssertLessThan(sbZstd.st_size, sbUncompressed.st_size);

  NSData *zstdData = [NSData dataWithContentsOfFile:zstdFile];
  std::vector<uint8_t> zstdDecompressed(kDstBuffSize);
  size_t bytesDecompressed = ZSTD_decompress(zstdDecompressed.data(), zstdDecompressed.size(),
                                             zstdData.bytes, zstdData.length);
  XCTAssertFalse(ZSTD_isError(bytesDecompressed), "Decompression error: %d: %s",
                 ZSTD_getErrorCode(bytesDecompressed), ZSTD_getErrorName(bytesDecompressed));

  // Uncompressed file size should match number of decompressed bytes
  XCTAssertEqual(bytesDecompressed, sbUncompressed.st_size);

  // Compare the decompressed zstd data with the uncompressed data
  NSData *uncompressedData = [NSData dataWithContentsOfFile:uncompressedFile];
  XCTAssertEqual(uncompressedData.length, sbUncompressed.st_size);  // sanity check
  XCTAssertEqual(0,
                 memcmp(zstdDecompressed.data(), uncompressedData.bytes, uncompressedData.length));

  //
  // Now do it again! Check that completing and then re-initialization produces expected content
  //
  uncompressedFile = [NSString stringWithFormat:@"%@/%@", self.testDir, @"uncomp2.bin"];
  gzipFile = [NSString stringWithFormat:@"%@/%@", self.testDir, @"gzip2.bin"];
  zstdFile = [NSString stringWithFormat:@"%@/%@", self.testDir, @"zstd2.bin"];

  XCTAssertTrue([self.fileMgr createFileAtPath:uncompressedFile contents:nil attributes:nil]);
  XCTAssertTrue([self.fileMgr createFileAtPath:gzipFile contents:nil attributes:nil]);
  XCTAssertTrue([self.fileMgr createFileAtPath:zstdFile contents:nil attributes:nil]);

  uncompressedHandle = [NSFileHandle fileHandleForWritingAtPath:uncompressedFile];
  gzipHandle = [NSFileHandle fileHandleForWritingAtPath:gzipFile];
  zstdHandle = [NSFileHandle fileHandleForWritingAtPath:zstdFile];

  XCTAssertNotNil(uncompressedHandle);
  XCTAssertNotNil(gzipHandle);
  XCTAssertNotNil(zstdHandle);

  // Re-initiallize all the streams
  uncompressedStream.InitializeBatch(uncompressedHandle.fileDescriptor);
  gzipStream.InitializeBatch(gzipHandle.fileDescriptor);
  zstdStream.InitializeBatch(zstdHandle.fileDescriptor);

  // Write random-sized "messages" of random bytes until the batch size is reached.
  currentBytes = 0;
  do {
    size_t numBytes = sizeDist(rng);
    std::vector<uint8_t> buf;
    buf.reserve(numBytes);
    for (size_t i = 0; i < numBytes; ++i) {
      buf.push_back(byteDist(rng));
    }

    XCTAssertTrue(uncompressedStream.Write(buf).ok());
    XCTAssertTrue(gzipStream.Write(buf).ok());
    XCTAssertTrue(zstdStream.Write(buf).ok());

    currentBytes += numBytes;
  } while (currentBytes < kFileSize);

  // Close out all the streams
  statusOrSizeUncompressed = uncompressedStream.CompleteBatch(uncompressedHandle.fileDescriptor);
  XCTAssertTrue(statusOrSizeUncompressed.ok());

  statusOrSizeGzip = gzipStream.CompleteBatch(gzipHandle.fileDescriptor);
  XCTAssertTrue(statusOrSizeGzip.ok());

  statusOrSizeZstd = zstdStream.CompleteBatch(zstdHandle.fileDescriptor);
  XCTAssertTrue(statusOrSizeZstd.ok());

  // Number of bytes written should be the same
  XCTAssertEqual(*statusOrSizeUncompressed, *statusOrSizeGzip);
  XCTAssertEqual(*statusOrSizeUncompressed, *statusOrSizeZstd);

  [uncompressedHandle closeFile];
  [gzipHandle closeFile];
  [zstdHandle closeFile];

  XCTAssertEqual(0, stat(uncompressedFile.UTF8String, &sbUncompressed));
  XCTAssertEqual(0, stat(gzipFile.UTF8String, &sbGzip));
  XCTAssertEqual(0, stat(zstdFile.UTF8String, &sbZstd));

  XCTAssertLessThan(sbGzip.st_size, sbUncompressed.st_size);
  XCTAssertLessThan(sbZstd.st_size, sbUncompressed.st_size);

  zstdData = [NSData dataWithContentsOfFile:zstdFile];
  bytesDecompressed = ZSTD_decompress(zstdDecompressed.data(), zstdDecompressed.size(),
                                      zstdData.bytes, zstdData.length);
  XCTAssertFalse(ZSTD_isError(bytesDecompressed), "Decompression error: %d: %s",
                 ZSTD_getErrorCode(bytesDecompressed), ZSTD_getErrorName(bytesDecompressed));

  // Uncompressed file size should match number of decompressed bytes
  XCTAssertEqual(bytesDecompressed, sbUncompressed.st_size);

  // Compare the decompressed zstd data with the uncompressed data
  uncompressedData = [NSData dataWithContentsOfFile:uncompressedFile];
  XCTAssertEqual(uncompressedData.length, sbUncompressed.st_size);  // sanity check
  XCTAssertEqual(0,
                 memcmp(zstdDecompressed.data(), uncompressedData.bytes, uncompressedData.length));
}

@end
