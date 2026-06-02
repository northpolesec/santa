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

#include <fcntl.h>
#include <mach-o/loader.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstring>
#include <map>
#include <memory>
#include <string>
#include <vector>

#import "Source/common/SNTConfigurator.h"
#include "Source/santad/SNTBinaryUploadController.h"
#include "Source/santad/SleighLauncher.h"
#include "absl/status/statusor.h"
#include "commands/v1.pb.h"
#include "telemetry/sleighconfig.pb.h"

namespace pbv1 = ::santa::commands::v1;
namespace pbtel = ::santa::telemetry::v1;

// A SleighLauncher that records what it was asked to launch and returns a canned
// COMPLETED response without forking anything.
class FakeSleighLauncher : public santa::SleighLauncher {
 public:
  FakeSleighLauncher() : santa::SleighLauncher("/nonexistent/sleigh") {}

  absl::StatusOr<pbv1::BinaryUploadResponse> LaunchBinaryUpload(
      int input_fd, const std::string& signed_post_url,
      const std::map<std::string, std::string>& form_values, const std::string& expected_sha256,
      const pbtel::BinaryMetadata& metadata, const std::vector<std::string>& filter_expressions,
      uint32_t timeout_seconds) override {
    launched = true;
    last_fd = input_fd;
    last_url = signed_post_url;
    last_form_values = form_values;
    last_expected_sha256 = expected_sha256;
    last_metadata = metadata;
    last_filter_expressions = filter_expressions;
    // The controller hands fd ownership to us; close it like the real launcher.
    if (input_fd >= 0) {
      close(input_fd);
    }
    pbv1::BinaryUploadResponse response;
    response.set_disposition(pbv1::BinaryUploadResponse::DISPOSITION_COMPLETED);
    return response;
  }

  bool launched = false;
  int last_fd = -1;
  std::string last_url;
  std::map<std::string, std::string> last_form_values;
  std::string last_expected_sha256;
  pbtel::BinaryMetadata last_metadata;
  std::vector<std::string> last_filter_expressions;
};

@interface SNTBinaryUploadControllerTest : XCTestCase
@end

@implementation SNTBinaryUploadControllerTest

- (void)setUp {
  [super setUp];
  // Clear any filter expressions leaked from another test in this process.
  [[SNTConfigurator configurator] setSyncServerBinaryUploadFilterExpressions:@[]];
}

- (void)tearDown {
  [[SNTConfigurator configurator] setSyncServerBinaryUploadFilterExpressions:@[]];
  [super tearDown];
}

- (NSString*)uniqueTempPath:(NSString*)prefix {
  return [NSTemporaryDirectory()
      stringByAppendingPathComponent:[NSString stringWithFormat:@"%@-%@", prefix,
                                                                [[NSUUID UUID] UUIDString]]];
}

// Writes a minimal 64-bit mach-o executable header (filetype MH_EXECUTE).
- (NSString*)writeMachOExecutable {
  uint8_t buf[sizeof(struct mach_header_64)] = {0};
  uint32_t magic = MH_MAGIC_64;
  std::memcpy(buf, &magic, sizeof(magic));
  uint32_t filetype = MH_EXECUTE;
  std::memcpy(buf + offsetof(struct mach_header_64, filetype), &filetype, sizeof(filetype));

  NSString* path = [self uniqueTempPath:@"macho"];
  [[NSData dataWithBytes:buf length:sizeof(buf)] writeToFile:path atomically:YES];
  return path;
}

- (pbv1::BinaryUploadRequest)requestForPath:(NSString*)path {
  pbv1::BinaryUploadRequest request;
  request.set_path(path.UTF8String);
  request.mutable_signed_post()->set_url("https://example.com/post");
  (*request.mutable_signed_post()->mutable_form_values())["key"] = "objects/x";
  return request;
}

// A regular mach-o file launches sleigh, the macho_type is computed from the fd,
// and the configured filter expressions are forwarded (the filter runs in sleigh).
- (void)testHandleMachOLaunchesAndForwardsInputs {
  [[SNTConfigurator configurator]
      setSyncServerBinaryUploadFilterExpressions:@[ @"binary.is_platform_binary" ]];

  auto fake = std::make_unique<FakeSleighLauncher>();
  FakeSleighLauncher* fakePtr = fake.get();
  santa::SNTBinaryUploadController controller(std::move(fake), /*timeout_seconds=*/10);

  pbv1::BinaryUploadRequest request = [self requestForPath:[self writeMachOExecutable]];
  pbv1::BinaryUploadResponse response = controller.Handle(request);

  XCTAssertEqual(response.disposition(), pbv1::BinaryUploadResponse::DISPOSITION_COMPLETED);
  XCTAssertTrue(fakePtr->launched);
  XCTAssertEqual(fakePtr->last_metadata.macho_type(), std::string("executable"));
  XCTAssertEqual(fakePtr->last_url, std::string("https://example.com/post"));
  XCTAssertEqual(fakePtr->last_form_values["key"], std::string("objects/x"));
  XCTAssertEqual(fakePtr->last_filter_expressions.size(), 1u);
  XCTAssertEqual(fakePtr->last_filter_expressions[0], std::string("binary.is_platform_binary"));
}

// A non-regular file (FIFO) is rejected without launching (C4).
- (void)testHandleFifoIsNotFoundAndDoesNotLaunch {
  auto fake = std::make_unique<FakeSleighLauncher>();
  FakeSleighLauncher* fakePtr = fake.get();
  santa::SNTBinaryUploadController controller(std::move(fake), /*timeout_seconds=*/10);

  NSString* fifo = [self uniqueTempPath:@"fifo"];
  XCTAssertEqual(mkfifo(fifo.UTF8String, 0644), 0);

  pbv1::BinaryUploadRequest request = [self requestForPath:fifo];
  pbv1::BinaryUploadResponse response = controller.Handle(request);

  XCTAssertEqual(response.disposition(), pbv1::BinaryUploadResponse::DISPOSITION_NOT_FOUND);
  XCTAssertFalse(fakePtr->launched);
  unlink(fifo.UTF8String);
}

// A missing path is NOT_FOUND and does not launch.
- (void)testHandleMissingPathIsNotFound {
  auto fake = std::make_unique<FakeSleighLauncher>();
  FakeSleighLauncher* fakePtr = fake.get();
  santa::SNTBinaryUploadController controller(std::move(fake), /*timeout_seconds=*/10);

  pbv1::BinaryUploadRequest request = [self requestForPath:[self uniqueTempPath:@"missing"]];
  pbv1::BinaryUploadResponse response = controller.Handle(request);

  XCTAssertEqual(response.disposition(), pbv1::BinaryUploadResponse::DISPOSITION_NOT_FOUND);
  XCTAssertFalse(fakePtr->launched);
}

@end
