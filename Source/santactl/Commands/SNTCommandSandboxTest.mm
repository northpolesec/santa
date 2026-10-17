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

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <spawn.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include <optional>
#include <string>

#import "Source/common/MOLCodesignChecker.h"

extern char** environ;

@interface SNTCommandSandbox : NSObject
+ (std::optional<std::string>)resolvedDirectoryPath:(const char*)path errorCode:(int*)errorCode;
+ (NSString*)cdhashForExecutedSliceOfFD:(int)fd path:(NSString*)path;
@end

@interface SNTCommandSandboxTest : XCTestCase
// Fully resolved, so expected values below can be built from it directly.
@property NSString* scratchDir;
@end

@implementation SNTCommandSandboxTest

- (void)setUp {
  NSFileManager* fm = [NSFileManager defaultManager];
  NSString* dir = [NSTemporaryDirectory()
      stringByAppendingPathComponent:[NSString stringWithFormat:@"SNTCommandSandboxTest-%@",
                                                                NSUUID.UUID.UUIDString]];
  XCTAssertTrue([fm createDirectoryAtPath:[dir stringByAppendingPathComponent:@"real/sub"]
              withIntermediateDirectories:YES
                               attributes:nil
                                    error:NULL]);
  XCTAssertTrue([fm createSymbolicLinkAtPath:[dir stringByAppendingPathComponent:@"link"]
                         withDestinationPath:@"real"
                                       error:NULL]);
  XCTAssertTrue([fm createSymbolicLinkAtPath:[dir stringByAppendingPathComponent:@"dangling"]
                         withDestinationPath:@"nonexistent"
                                       error:NULL]);
  XCTAssertTrue([fm createFileAtPath:[dir stringByAppendingPathComponent:@"file"]
                            contents:nil
                          attributes:nil]);
  char buf[PATH_MAX];
  XCTAssertTrue(realpath(dir.fileSystemRepresentation, buf) != NULL);
  self.scratchDir = @(buf);
}

- (void)tearDown {
  [[NSFileManager defaultManager] removeItemAtPath:self.scratchDir error:NULL];
}

- (NSString*)resolve:(NSString*)path errorCode:(int*)errorCode {
  std::optional<std::string> resolved = [SNTCommandSandbox resolvedDirectoryPath:path.UTF8String
                                                                       errorCode:errorCode];
  return resolved ? @(resolved->c_str()) : nil;
}

- (void)testResolvesSymlinksAboveLastComponent {
  int err = 0;
  XCTAssertEqualObjects([self resolve:@"/var/tmp" errorCode:&err], @"/private/var/tmp");
  XCTAssertEqualObjects([self resolve:[self.scratchDir stringByAppendingPathComponent:@"link/sub"]
                            errorCode:&err],
                        [self.scratchDir stringByAppendingPathComponent:@"real/sub"]);
}

- (void)testResolvesDarwinUserTempDir {
  char buf[PATH_MAX];
  size_t len = confstr(_CS_DARWIN_USER_TEMP_DIR, buf, sizeof(buf));
  XCTAssertTrue(len > 0 && len <= sizeof(buf));
  NSString* raw = @(buf);
  XCTAssertTrue([raw hasPrefix:@"/var/folders/"], @"%@", raw);
  if ([raw hasSuffix:@"/"]) raw = [raw substringToIndex:raw.length - 1];

  int err = 0;
  XCTAssertEqualObjects([self resolve:@(buf) errorCode:&err],
                        [@"/private" stringByAppendingString:raw]);
}

- (void)testStripsTrailingSlashes {
  int err = 0;
  XCTAssertEqualObjects([self resolve:@"/var/tmp//" errorCode:&err], @"/private/var/tmp");
  XCTAssertEqualObjects([self resolve:@"/" errorCode:&err], @"/");
}

- (void)testResolvesMissingLastComponent {
  NSString* name = [NSString stringWithFormat:@"SNTCommandSandboxTest-%@", NSUUID.UUID.UUIDString];
  NSDictionary<NSString*, NSString*>* cases = @{
    [self.scratchDir stringByAppendingPathComponent:@"missing"] :
        [self.scratchDir stringByAppendingPathComponent:@"missing"],
    [self.scratchDir stringByAppendingPathComponent:@"link/missing/"] :
        [self.scratchDir stringByAppendingPathComponent:@"real/missing"],
    [@"/var" stringByAppendingPathComponent:name] :
        [@"/private/var" stringByAppendingPathComponent:name],
    [@"/" stringByAppendingString:name] : [@"/" stringByAppendingString:name],
  };
  for (NSString* path in cases) {
    int err = 0;
    XCTAssertEqualObjects([self resolve:path errorCode:&err], cases[path], @"%@", path);
  }
}

- (void)testRejectsDotLastComponent {
  for (NSString* suffix in @[ @"/link/.", @"/link/..", @"/link/./", @"/real/." ]) {
    int err = 0;
    XCTAssertNil([self resolve:[self.scratchDir stringByAppendingString:suffix] errorCode:&err],
                 @"%@", suffix);
    XCTAssertEqual(err, EINVAL, @"%@", suffix);
  }
}

- (void)testRejectsSymlinkAsLastComponent {
  // Trailing slashes must not hide the link.
  for (NSString* suffix in @[ @"/link", @"/link/", @"/link//", @"/dangling" ]) {
    int err = 0;
    XCTAssertNil([self resolve:[self.scratchDir stringByAppendingString:suffix] errorCode:&err],
                 @"%@", suffix);
    XCTAssertEqual(err, ENOTDIR, @"%@", suffix);
  }
}

- (void)testRejectsUnusablePaths {
  NSDictionary<NSString*, NSNumber*>* cases = @{
    @"" : @(EINVAL),
    @"tmp" : @(EINVAL),
    [self.scratchDir stringByAppendingPathComponent:@"missing/child"] : @(ENOENT),
    [self.scratchDir stringByAppendingPathComponent:@"file"] : @(ENOTDIR),
  };
  for (NSString* path in cases) {
    int err = 0;
    XCTAssertNil([self resolve:path errorCode:&err], @"%@", path);
    XCTAssertEqual(err, cases[path].intValue, @"%@", path);
  }
}

/// santad compares the registered cdhash against the kernel-reported cdhash of
/// the exec'd image, so the oracle here is a running process: a SecCodeRef for a
/// live pid names the slice the kernel actually loaded. /bin/sleep is a fat
/// Apple binary, which is the case that regressed -- Security.framework grades
/// its arm64e.x1 slice above the arm64e slice the kernel executes, so the
/// whole-file cdhash names a slice that never runs.
- (void)testCdhashNamesTheSliceTheKernelExecutes {
  const char* kBinary = "/bin/sleep";
  char* const argv[] = {(char*)kBinary, (char*)"30", NULL};
  pid_t pid = 0;
  XCTAssertEqual(posix_spawn(&pid, kBinary, NULL, NULL, argv, environ), 0);
  // A failed spawn leaves pid at 0, and the assertion above does not end the
  // method. Registering the teardown anyway would kill(0, SIGKILL) the whole
  // process group, the test runner included.
  if (pid <= 0) return;
  [self addTeardownBlock:^{
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
  }];

  // The guest lookup only resolves once the child has finished exec'ing.
  MOLCodesignChecker* running = nil;
  for (int i = 0; i < 200 && running.cdhash.length == 0; i++) {
    running = [[MOLCodesignChecker alloc] initWithPID:pid error:NULL];
    if (running.cdhash.length == 0) usleep(10 * USEC_PER_SEC / 1000);
  }
  XCTAssertGreaterThan(running.cdhash.length, 0UL, @"could not read the running cdhash");

  int fd = open(kBinary, O_RDONLY | O_CLOEXEC);
  XCTAssertGreaterThanOrEqual(fd, 0);
  [self addTeardownBlock:^{
    close(fd);
  }];

  // santactl reads the signature off the descriptor it pinned, not the path.
  NSString* fdPath = [NSString stringWithFormat:@"/dev/fd/%d", fd];
  XCTAssertEqualObjects([SNTCommandSandbox cdhashForExecutedSliceOfFD:fd path:fdPath],
                        running.cdhash);
}

@end
