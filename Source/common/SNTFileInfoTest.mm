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
#include <libkern/OSByteOrder.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>

#import "Source/common/SNTFileInfo.h"

static const uint32_t kFatTestSliceSize = 8192;

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

- (void)testResolvedPathStatFailure {
  NSString* path = [NSTemporaryDirectory()
      stringByAppendingPathComponent:[NSString stringWithFormat:@"SNTFileInfo-%@",
                                                                NSUUID.UUID.UUIDString]];
  NSError* error;
  SNTFileInfo* sut = [[SNTFileInfo alloc] initWithResolvedPath:path error:&error];

  XCTAssertNil(sut);
  XCTAssertNotNil(error);
  XCTAssertTrue([error.localizedDescription containsString:@"Unable to stat file"]);
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

#pragma mark Universal (fat) binary slice offsets

///  Writes a universal binary wrapping one x86_64 slice at |sliceOffset|, with
///  the architecture record declaring |recordOffset| and |recordSize|. Header
///  fields are written big-endian as Apple's tools emit them. The slice is
///  written via seek, so the file is sparse and an offset above 2 GiB costs only
///  a few allocated blocks.
- (NSString*)writeFatFixtureWithRecordOffset:(uint32_t)recordOffset
                                  recordSize:(uint32_t)recordSize
                                 sliceOffset:(uint32_t)sliceOffset {
  NSString* path = [NSTemporaryDirectory()
      stringByAppendingPathComponent:[NSString stringWithFormat:@"SNTFileInfoFat-%@",
                                                                NSUUID.UUID.UUIDString]];

  struct fat_header fh = {
      .magic = OSSwapHostToBigInt32(FAT_MAGIC),
      .nfat_arch = OSSwapHostToBigInt32(1),
  };
  struct fat_arch fa = {
      .cputype = (cpu_type_t)OSSwapHostToBigInt32((uint32_t)CPU_TYPE_X86_64),
      .cpusubtype = (cpu_subtype_t)OSSwapHostToBigInt32((uint32_t)CPU_SUBTYPE_X86_64_ALL),
      .offset = OSSwapHostToBigInt32(recordOffset),
      .size = OSSwapHostToBigInt32(recordSize),
      .align = OSSwapHostToBigInt32(12),
  };
  NSMutableData* contents = [NSMutableData dataWithBytes:&fh length:sizeof(fh)];
  [contents appendBytes:&fa length:sizeof(fa)];
  XCTAssertTrue([[NSFileManager defaultManager] createFileAtPath:path
                                                        contents:contents
                                                      attributes:nil]);
  [self addTeardownBlock:^{
    [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
  }];

  NSMutableData* slice = [NSMutableData dataWithLength:kFatTestSliceSize];
  struct mach_header_64* mh = (struct mach_header_64*)slice.mutableBytes;
  mh->magic = MH_MAGIC_64;
  mh->cputype = CPU_TYPE_X86_64;
  mh->cpusubtype = CPU_SUBTYPE_X86_64_ALL;
  mh->filetype = MH_EXECUTE;

  NSFileHandle* handle = [NSFileHandle fileHandleForWritingAtPath:path];
  XCTAssertNotNil(handle);
  [handle seekToFileOffset:sliceOffset];
  [handle writeData:slice];
  [handle closeFile];

  return path;
}

- (void)testFatSliceOffsetBelowIntMax {
  NSString* path = [self writeFatFixtureWithRecordOffset:0x1000
                                              recordSize:kFatTestSliceSize
                                             sliceOffset:0x1000];
  SNTFileInfo* sut = [[SNTFileInfo alloc] initWithPath:path];
  XCTAssertNotNil(sut);
  XCTAssertTrue(sut.isMachO);
  XCTAssertEqualObjects(sut.architectures, @[ @"x86_64" ]);
}

- (void)testFatSliceOffsetAboveIntMax {
  // A slice offset with the high bit set is valid and must still resolve.
  NSString* path = [self writeFatFixtureWithRecordOffset:0x80001000
                                              recordSize:kFatTestSliceSize
                                             sliceOffset:0x80001000];
  SNTFileInfo* sut = [[SNTFileInfo alloc] initWithPath:path];
  XCTAssertNotNil(sut);
  XCTAssertTrue(sut.isMachO, @"a slice offset above INT_MAX must still resolve");
  XCTAssertEqualObjects(sut.architectures, @[ @"x86_64" ]);
}

- (void)testFatSliceOffsetPlusSizeDoesNotWrap {
  // offset + size exceeds UINT32_MAX and must be rejected, not wrapped.
  NSString* path = [self writeFatFixtureWithRecordOffset:0xFFFFF000
                                              recordSize:0xFFFFF000
                                             sliceOffset:0x1000];
  SNTFileInfo* sut = [[SNTFileInfo alloc] initWithPath:path];
  XCTAssertNotNil(sut);
  XCTAssertFalse(sut.isMachO);
}

- (void)testFatArchCountTooLargeIsRejectedWithoutHugeRead {
  // An arch count far past anything real, on a file whose logical size is large
  // enough that the arch table appears to fit. The file is sparse, so it costs a
  // few blocks while the declared table is 40MB. Parsing must reject the count up
  // front rather than reading the table and iterating over it.
  const uint32_t kArchCount = 2000000;  // 20 bytes each -> 40MB table
  NSString* path = [NSTemporaryDirectory()
      stringByAppendingPathComponent:[NSString stringWithFormat:@"SNTFileInfoFat-%@",
                                                                NSUUID.UUID.UUIDString]];
  struct fat_header fh = {
      .magic = OSSwapHostToBigInt32(FAT_MAGIC),
      .nfat_arch = OSSwapHostToBigInt32(kArchCount),
  };
  XCTAssertTrue([[NSFileManager defaultManager] createFileAtPath:path
                                                        contents:[NSData dataWithBytes:&fh
                                                                                length:sizeof(fh)]
                                                      attributes:nil]);
  [self addTeardownBlock:^{
    [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
  }];

  // Extend logically without allocating, so the declared table fits inside the
  // reported file size.
  NSFileHandle* handle = [NSFileHandle fileHandleForWritingAtPath:path];
  XCTAssertNotNil(handle);
  [handle truncateFileAtOffset:(sizeof(struct fat_header) +
                                sizeof(struct fat_arch) * (uint64_t)kArchCount + 4096)];
  [handle closeFile];

  NSDate* start = [NSDate date];
  SNTFileInfo* sut = [[SNTFileInfo alloc] initWithPath:path];
  XCTAssertNotNil(sut);
  XCTAssertFalse(sut.isMachO);
  // Rejecting up front should be immediate. Reading and walking a 2M-entry table
  // would take far longer than this.
  XCTAssertLessThan(-[start timeIntervalSinceNow], 1.0);
}

- (void)testRealUniversalBinaryStillParses {
  NSString* path = [[NSBundle bundleForClass:[self class]] pathForResource:@"cal-yikes-universal"
                                                                    ofType:@""];
  SNTFileInfo* sut = [[SNTFileInfo alloc] initWithPath:path];
  XCTAssertNotNil(sut);
  XCTAssertTrue(sut.isMachO);
  XCTAssertTrue(sut.isFat);
}

#pragma mark Thin Mach-O identification

///  Writes a thin little-endian 64-bit MH_EXECUTE of exactly |totalSize| bytes.
///  Only the header is meaningful; the remainder is padding.
- (NSString*)writeThinMachOFixtureOfSize:(NSUInteger)totalSize {
  XCTAssertGreaterThanOrEqual(totalSize, sizeof(struct mach_header_64));

  NSMutableData* contents = [NSMutableData dataWithLength:totalSize];
  struct mach_header_64* mh = (struct mach_header_64*)contents.mutableBytes;
  mh->magic = MH_MAGIC_64;
  mh->cputype = CPU_TYPE_X86_64;
  mh->cpusubtype = CPU_SUBTYPE_X86_64_ALL;
  mh->filetype = MH_EXECUTE;

  NSString* path = [NSTemporaryDirectory()
      stringByAppendingPathComponent:[NSString stringWithFormat:@"SNTFileInfoThin-%@",
                                                                NSUUID.UUID.UUIDString]];
  XCTAssertTrue([[NSFileManager defaultManager] createFileAtPath:path
                                                        contents:contents
                                                      attributes:nil]);
  [self addTeardownBlock:^{
    [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
  }];
  return path;
}

- (void)testThinMachOSmallerThanOnePage {
  // A complete image can be well under a page. Identification must not depend on
  // the file being large enough to satisfy a fixed-size read.
  for (NSUInteger size : {sizeof(struct mach_header_64), (size_t)64, (size_t)715, (size_t)2048}) {
    NSString* path = [self writeThinMachOFixtureOfSize:size];
    SNTFileInfo* sut = [[SNTFileInfo alloc] initWithPath:path];
    XCTAssertNotNil(sut);
    XCTAssertTrue(sut.isMachO, @"a %lu byte Mach-O must be recognized", (unsigned long)size);
    XCTAssertEqualObjects(sut.architectures, @[ @"x86_64" ]);
  }
}

- (void)testThinMachOAtPageBoundary {
  for (NSUInteger size : {(size_t)4095, (size_t)4096, (size_t)4097}) {
    NSString* path = [self writeThinMachOFixtureOfSize:size];
    SNTFileInfo* sut = [[SNTFileInfo alloc] initWithPath:path];
    XCTAssertNotNil(sut);
    XCTAssertTrue(sut.isMachO, @"a %lu byte Mach-O must be recognized", (unsigned long)size);
  }
}

- (void)testShortNonMachOIsNotRecognized {
  // The reverse guard: reading a short prefix must not start classifying small
  // non-executable files as Mach-O.
  NSString* path = [NSTemporaryDirectory()
      stringByAppendingPathComponent:[NSString stringWithFormat:@"SNTFileInfoShort-%@",
                                                                NSUUID.UUID.UUIDString]];
  NSMutableData* contents = [NSMutableData dataWithLength:512];
  memcpy(contents.mutableBytes, "not a mach-o at all", 19);
  XCTAssertTrue([[NSFileManager defaultManager] createFileAtPath:path
                                                        contents:contents
                                                      attributes:nil]);
  [self addTeardownBlock:^{
    [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
  }];

  SNTFileInfo* sut = [[SNTFileInfo alloc] initWithPath:path];
  XCTAssertNotNil(sut);
  XCTAssertFalse(sut.isMachO);
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

@end
