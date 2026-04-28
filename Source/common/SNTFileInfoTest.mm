/// Copyright 2015 Google Inc. All rights reserved.
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
#include <mach/machine.h>
#include <sys/stat.h>
#include <unistd.h>

#import "Source/common/MOLCodesignChecker.h"
#import "Source/common/SNTFileInfo.h"
#import "Source/common/TestUtils.h"

@interface SNTFileInfoTest : XCTestCase
@end

@implementation SNTFileInfoTest

- (NSString*)directoryBundle {
  NSString* rp = [[NSBundle bundleForClass:[self class]] resourcePath];
  return [rp stringByAppendingPathComponent:@"testdata/DirectoryBundle"];
}

- (NSString*)bundleExample {
  NSString* rp = [[NSBundle bundleForClass:[self class]] resourcePath];
  return [rp stringByAppendingPathComponent:@"testdata/BundleExample.app"];
}

- (void)testPathStandardizing {
  SNTFileInfo* sut = [[SNTFileInfo alloc] initWithPath:@"/Applications/Safari.app"];
  XCTAssertNotNil(sut);
  XCTAssertEqualObjects(sut.path, @"/System/Volumes/Preboot/Cryptexes/App/System/Applications/"
                                  @"Safari.app/Contents/MacOS/Safari");

  sut = [[SNTFileInfo alloc] initWithPath:@"../../../../../../../../../../../../../../../bin/ls"];
  XCTAssertEqualObjects(sut.path, @"/bin/ls");

  sut = [[SNTFileInfo alloc] initWithPath:@"/usr/sbin/DirectoryService"];
  XCTAssertEqualObjects(sut.path, @"/usr/libexec/dspluginhelperd");
}

- (void)testSHA1 {
  NSString* path = [[NSBundle bundleForClass:[self class]] pathForResource:@"missing_pagezero"
                                                                    ofType:@""];
  SNTFileInfo* sut = [[SNTFileInfo alloc] initWithPath:path];

  XCTAssertNotNil(sut.SHA1);
  XCTAssertEqual(sut.SHA1.length, 40);
  XCTAssertEqualObjects(sut.SHA1, @"3a865bf47b4ceba20496e0e66e39e4cfa101ffe6");
}

- (void)testSHA256 {
  NSString* path = [[NSBundle bundleForClass:[self class]] pathForResource:@"missing_pagezero"
                                                                    ofType:@""];
  SNTFileInfo* sut = [[SNTFileInfo alloc] initWithPath:path];

  XCTAssertNotNil(sut.SHA256);
  XCTAssertEqual(sut.SHA256.length, 64);
  XCTAssertEqualObjects(sut.SHA256,
                        @"5e089b65a1e7a4696d84a34510710b6993d1de21250c41daaec63d9981083eba");
}

- (void)testExecutable {
  SNTFileInfo* sut = [[SNTFileInfo alloc] initWithPath:@"/sbin/launchd"];

  XCTAssertTrue(sut.isMachO);
  XCTAssertTrue(sut.isExecutable);

  XCTAssertFalse(sut.isDylib);
  XCTAssertFalse(sut.isKext);
  XCTAssertFalse(sut.isScript);
}

- (void)testPageZero {
  NSString* path = [[NSBundle bundleForClass:[self class]] pathForResource:@"missing_pagezero"
                                                                    ofType:@""];
  SNTFileInfo* sut = [[SNTFileInfo alloc] initWithPath:path];
  XCTAssertTrue(sut.isMissingPageZero);

  path = [[NSBundle bundleForClass:[self class]] pathForResource:@"bad_pagezero" ofType:@""];
  sut = [[SNTFileInfo alloc] initWithPath:path];
  XCTAssertTrue(sut.isMissingPageZero);

  sut = [[SNTFileInfo alloc] initWithPath:@"/usr/sbin/bless"];
  XCTAssertFalse(sut.isMissingPageZero);
}

- (void)testDylibs {
  SNTFileInfo* sut = [[SNTFileInfo alloc] initWithPath:@"/usr/lib/system/libsystem_platform.dylib"];

  XCTAssertTrue(sut.isMachO);
  XCTAssertTrue(sut.isDylib);
  XCTAssertTrue(sut.isFat);

  XCTAssertFalse(sut.isKext);
  XCTAssertFalse(sut.isExecutable);
  XCTAssertFalse(sut.isScript);
}

- (void)testScript {
  SNTFileInfo* sut = [[SNTFileInfo alloc] initWithPath:@"/usr/bin/h2ph"];

  XCTAssertTrue(sut.isScript);

  XCTAssertFalse(sut.isDylib);
  XCTAssertFalse(sut.isExecutable);
  XCTAssertFalse(sut.isFat);
  XCTAssertFalse(sut.isKext);
  XCTAssertFalse(sut.isMachO);
}

- (void)testBundle {
  NSString* path = [self bundleExample];
  SNTFileInfo* sut = [[SNTFileInfo alloc] initWithPath:path];

  XCTAssertNotNil([sut bundle]);

  XCTAssertEqualObjects([sut bundleIdentifier], @"com.northpolesec.santa.BundleExample");
  XCTAssertEqualObjects([sut bundleName], @"BundleExample");
  XCTAssertEqualObjects([sut bundleVersion], @"1");
  XCTAssertEqualObjects([sut bundleShortVersionString], @"1.0");
  XCTAssertEqualObjects([sut bundlePath], path);
}

- (void)testAncestorBundle {
  NSString* path = [self bundleExample];
  SNTFileInfo* sut = [[SNTFileInfo alloc] initWithPath:path];
  sut.useAncestorBundle = YES;

  XCTAssertNotNil([sut bundle]);

  XCTAssertEqualObjects([sut bundleIdentifier], @"com.northpolesec.santa.UnitTest.SNTFileInfoTest");
  XCTAssertNotNil([sut bundleVersion]);
  XCTAssertNotNil([sut bundleShortVersionString]);

  NSString* ancestorBundlePath = path;
  for (int i = 0; i < 4; i++) {
    ancestorBundlePath = [ancestorBundlePath stringByDeletingLastPathComponent];
  }
  XCTAssertEqualObjects([sut bundlePath], ancestorBundlePath);
}

- (void)testBundleIsAncestor {
  NSString* path = [NSBundle bundleForClass:[self class]].bundlePath;
  SNTFileInfo* sut = [[SNTFileInfo alloc] initWithPath:path];
  sut.useAncestorBundle = YES;

  XCTAssertNotNil([sut bundle]);

  XCTAssertEqualObjects([sut bundleIdentifier], @"com.northpolesec.santa.UnitTest.SNTFileInfoTest");
  XCTAssertNotNil([sut bundleVersion]);
  XCTAssertNotNil([sut bundleShortVersionString]);
  XCTAssertEqualObjects([sut bundlePath], path);
}

- (void)testDirectoryBundleIsNotAncestor {
  NSString* path = [self directoryBundle];
  NSString* directoryBundle = @"/tmp/DirectoryBundle";
  NSFileManager* fm = [NSFileManager defaultManager];
  [fm removeItemAtPath:directoryBundle error:NULL];
  [fm copyItemAtPath:path toPath:directoryBundle error:NULL];
  path = [directoryBundle stringByAppendingString:@"/Contents/Resources/BundleExample.app"];
  SNTFileInfo* sut = [[SNTFileInfo alloc] initWithPath:path];
  sut.useAncestorBundle = YES;

  XCTAssertNotNil([sut bundle]);

  XCTAssertEqualObjects([sut bundleIdentifier], @"com.northpolesec.santa.BundleExample");
  XCTAssertEqualObjects([sut bundleName], @"BundleExample");
  XCTAssertEqualObjects([sut bundleVersion], @"1");
  XCTAssertEqualObjects([sut bundleShortVersionString], @"1.0");
  XCTAssertEqualObjects([sut bundlePath], path);
}

- (void)testBundleCacheReset {
  NSString* path = [self bundleExample];
  SNTFileInfo* sut = [[SNTFileInfo alloc] initWithPath:path];

  XCTAssertNotNil([sut bundle]);

  XCTAssertEqualObjects([sut bundleIdentifier], @"com.northpolesec.santa.BundleExample");
  XCTAssertEqualObjects([sut bundleName], @"BundleExample");
  XCTAssertEqualObjects([sut bundleVersion], @"1");
  XCTAssertEqualObjects([sut bundleShortVersionString], @"1.0");
  XCTAssertEqualObjects([sut bundlePath], path);

  sut.useAncestorBundle = YES;

  XCTAssertNotNil([sut bundle]);

  XCTAssertEqualObjects([sut bundleIdentifier], @"com.northpolesec.santa.UnitTest.SNTFileInfoTest");
  XCTAssertNotNil([sut bundleVersion]);
  XCTAssertNotNil([sut bundleShortVersionString]);

  NSString* ancestorBundlePath = path;
  for (int i = 0; i < 4; i++) {
    ancestorBundlePath = [ancestorBundlePath stringByDeletingLastPathComponent];
  }
  XCTAssertEqualObjects([sut bundlePath], ancestorBundlePath);
}

- (void)testNonBundle {
  SNTFileInfo* sut = [[SNTFileInfo alloc] initWithPath:@"/usr/bin/yes"];

  XCTAssertNil([sut bundle]);

  sut.useAncestorBundle = YES;

  XCTAssertNil([sut bundle]);
}

- (void)testEmbeddedInfoPlist {
  NSString* path = [[NSBundle bundleForClass:[self class]] pathForResource:@"32bitplist"
                                                                    ofType:@""];
  SNTFileInfo* sut = [[SNTFileInfo alloc] initWithPath:path];
  XCTAssertNotNil([sut infoPlist]);
  XCTAssertEqualObjects([sut infoPlist][@"CFBundleShortVersionString"], @"1.0");
  XCTAssertEqualObjects([sut infoPlist][@"CFBundleIdentifier"], @"com.google.i386plist");

  // csreq is installed on all machines with Xcode installed. If you're running these tests,
  // it should be available..
  sut = [[SNTFileInfo alloc] initWithPath:@"/usr/bin/csreq"];
  XCTAssertNotNil([sut infoPlist]);
}

- (void)testCodesignStatus {
  {
    NSString* path = [[NSBundle bundleForClass:[self class]] pathForResource:@"cal-yikes-universal"
                                                                      ofType:@""];
    SNTFileInfo* sut = [[SNTFileInfo alloc] initWithPath:path];
    XCTAssertNotNil(sut);
    XCTAssertEqualObjects([sut codesignStatus],
                          @"Yes, but signing is not consistent for all architectures");
  }

  {
    NSString* path = [[NSBundle bundleForClass:[self class]] pathForResource:@"32bitplist"
                                                                      ofType:@""];
    SNTFileInfo* sut = [[SNTFileInfo alloc] initWithPath:path];
    XCTAssertNotNil(sut);
    XCTAssertEqualObjects([sut codesignStatus], @"No");
  }

  {
    NSString* path =
        [[NSBundle bundleForClass:[self class]] pathForResource:@"yikes-universal_adhoc"
                                                         ofType:@""];
    SNTFileInfo* sut = [[SNTFileInfo alloc] initWithPath:path];
    XCTAssertNotNil(sut);
    XCTAssertEqualObjects([sut codesignStatus], @"Yes, but ad-hoc");
  }

  {
    NSString* path = @"/sbin/launchd";
    SNTFileInfo* sut = [[SNTFileInfo alloc] initWithPath:path];
    XCTAssertNotNil(sut);
    XCTAssertEqualObjects([sut codesignStatus], @"Yes, platform binary");
  }
}

- (void)testInitWithEndpointSecurityExecEvent_StoresCpuType {
  // Use a real path so the underlying initWithResolvedPath:stat:error: succeeds.
  const char* path = "/usr/bin/yes";
  struct stat sb;
  XCTAssertEqual(stat(path, &sb), 0);

  es_file_t file = MakeESFile(path, sb);
  es_process_t proc = MakeESProcess(&file);
  es_event_exec_t exec = {
      .target = &proc,
      .image_cputype = CPU_TYPE_ARM64,
      .image_cpusubtype = CPU_SUBTYPE_ARM64_ALL,
  };

  NSError* error;
  SNTFileInfo* sut = [[SNTFileInfo alloc] initWithEndpointSecurityExecEvent:&exec error:&error];
  XCTAssertNotNil(sut);
  XCTAssertNil(error);
  XCTAssertEqual(sut.cpuType, CPU_TYPE_ARM64);
  XCTAssertEqual(sut.cpuSubtype, CPU_SUBTYPE_ARM64_ALL);
}

- (void)testInitWithEndpointSecurityFile_DefaultsCpuTypeToAny {
  const char* path = "/usr/bin/yes";
  struct stat sb;
  XCTAssertEqual(stat(path, &sb), 0);

  es_file_t file = MakeESFile(path, sb);

  NSError* error;
  SNTFileInfo* sut = [[SNTFileInfo alloc] initWithEndpointSecurityFile:&file error:&error];
  XCTAssertNotNil(sut);
  XCTAssertEqual(sut.cpuType, CPU_TYPE_ANY);
  XCTAssertEqual(sut.cpuSubtype, CPU_SUBTYPE_ANY);
}

- (void)testInitWithPath_DefaultsCpuTypeToAny {
  // Path-based init: cputype/cpusubtype default to ANY since there's no
  // exec-event context to infer them from.
  SNTFileInfo* sut = [[SNTFileInfo alloc] initWithPath:@"/usr/bin/yes"];
  XCTAssertNotNil(sut);
  XCTAssertEqual(sut.cpuType, CPU_TYPE_ANY);
  XCTAssertEqual(sut.cpuSubtype, CPU_SUBTYPE_ANY);
}

// On the exec-event path, codesignCheckerWithError: routes through MOL's
// fd-bound init, which calls SecStaticCode APIs that read from the
// underlying file via /dev/fd/N. That descriptor shares its file offset
// with the SNTFileInfo fd, so the absolute file offset is unspecified once
// validation has run. Pin the contract that downstream callers using
// pread() are unaffected: the bytes at a given offset must match before
// and after codesignCheckerWithError:.
- (void)testFileHandle_PreadStableAcrossCodesignCheckerWithError {
  const char* path = "/bin/ls";  // signed binary present on every macOS host
  struct stat sb;
  XCTAssertEqual(stat(path, &sb), 0);

  es_file_t file = MakeESFile(path, sb);
  es_process_t proc = MakeESProcess(&file);
  // image_cputype must be > 0 to engage the fd-binding path in
  // codesignCheckerWithError: (CPU_TYPE_ANY = -1 falls through to the
  // diagnostic / path-based MOL init).
  // System binaries on Apple Silicon are arm64e (PAC); Intel hosts are x86_64.
  // Match the host architecture so the cputype hint actually resolves to a
  // real slice in /bin/ls's fat header (otherwise MOL leaves _signingInformation
  // empty per its no-matching-slice path and cdhash is empty).
  es_event_exec_t exec = {
      .target = &proc,
#if defined(__arm64__)
      .image_cputype = CPU_TYPE_ARM64,
      .image_cpusubtype = CPU_SUBTYPE_ARM64E,
#else
      .image_cputype = CPU_TYPE_X86_64,
      .image_cpusubtype = CPU_SUBTYPE_X86_64_ALL,
#endif
  };

  NSError* fiErr;
  SNTFileInfo* fi = [[SNTFileInfo alloc] initWithEndpointSecurityExecEvent:&exec error:&fiErr];
  XCTAssertNotNil(fi);
  XCTAssertGreaterThan(fi.cpuType, 0);

  int fd = fi.fileHandle.fileDescriptor;

  uint8_t before[16] = {0};
  XCTAssertEqual(pread(fd, before, sizeof(before), 0), (ssize_t)sizeof(before));

  NSError* csErr;
  MOLCodesignChecker* csc = [fi codesignCheckerWithError:&csErr];
  XCTAssertNotNil(csc);
  XCTAssertGreaterThan(csc.cdhash.length, 0u);

  uint8_t after[16] = {0};
  XCTAssertEqual(pread(fd, after, sizeof(after), 0), (ssize_t)sizeof(after));

  XCTAssertEqual(memcmp(before, after, sizeof(before)), 0,
                 @"pread must return identical bytes before and after "
                 @"codesignCheckerWithError: despite Sec framework's "
                 @"manipulation of the shared file offset");
}

@end
