/// Copyright 2023 Google LLC
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

#include "Source/common/ScopedCFTypeRef.h"

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#import <XCTest/XCTest.h>

using santa::ScopedCFTypeRef;

@interface ScopedCFTypeRefTest : XCTestCase
@end

@implementation ScopedCFTypeRefTest

- (void)testDefaultConstruction {
  // Default construction creates wraps a NULL object
  ScopedCFTypeRef<CFNumberRef> scopedRef;
  XCTAssertFalse(scopedRef.Unsafe());
}

- (void)testOperatorBool {
  // Operator bool is `false` when object is null
  {
    ScopedCFTypeRef<CFNumberRef> scopedNullRef;
    XCTAssertFalse(scopedNullRef.Unsafe());
    XCTAssertFalse(scopedNullRef);
  }

  // Operator bool is `true` when object is NOT null
  {
    int x = 123;
    CFNumberRef numRef = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &x);

    ScopedCFTypeRef<CFNumberRef> scopedNumRef = ScopedCFTypeRef<CFNumberRef>::Assume(numRef);
    XCTAssertTrue(scopedNumRef.Unsafe());
    XCTAssertTrue(scopedNumRef);
  }
}

// Note that CFMutableArray is used for testing, even when subtypes aren't
// needed, because it is never optimized into immortal constant values, unlike
// other types.
- (void)testAssume {
  int want = 123;
  int got = 0;
  CFMutableArrayRef array = CFArrayCreateMutable(nullptr, /*capacity=*/0, &kCFTypeArrayCallBacks);

  // Baseline state, initial retain count is 1 after object creation
  XCTAssertEqual(1, CFGetRetainCount(array));

  CFNumberRef numRef = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &want);
  CFArrayAppendValue(array, numRef);
  CFRelease(numRef);

  XCTAssertEqual(1, CFArrayGetCount(array));

  {
    ScopedCFTypeRef<CFMutableArrayRef> scopedArray =
        ScopedCFTypeRef<CFMutableArrayRef>::Assume(array);

    // Ensure ownership was taken, and retain count remains unchanged
    XCTAssertTrue(scopedArray.Unsafe());
    XCTAssertEqual(1, CFGetRetainCount(scopedArray.Unsafe()));

    // Make sure the object contains expected contents
    CFMutableArrayRef ref = scopedArray.Unsafe();
    XCTAssertEqual(1, CFArrayGetCount(ref));
    XCTAssertTrue(
        CFNumberGetValue((CFNumberRef)CFArrayGetValueAtIndex(ref, 0), kCFNumberIntType, &got));
    XCTAssertEqual(want, got);
  }
}

// Note that CFMutableArray is used for testing, even when subtypes aren't
// needed, because it is never optimized into immortal constant values, unlike
// other types.
- (void)testRetain {
  int want = 123;
  int got = 0;
  CFMutableArrayRef array = CFArrayCreateMutable(nullptr, /*capacity=*/0, &kCFTypeArrayCallBacks);

  // Baseline state, initial retain count is 1 after object creation
  XCTAssertEqual(1, CFGetRetainCount(array));

  CFNumberRef numRef = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &want);
  CFArrayAppendValue(array, numRef);
  CFRelease(numRef);

  XCTAssertEqual(1, CFArrayGetCount(array));

  {
    ScopedCFTypeRef<CFMutableArrayRef> scopedArray =
        ScopedCFTypeRef<CFMutableArrayRef>::Retain(array);

    // Ensure ownership was taken, and retain count was incremented
    XCTAssertTrue(scopedArray.Unsafe());
    XCTAssertEqual(2, CFGetRetainCount(scopedArray.Unsafe()));

    // Make sure the object contains expected contents
    CFMutableArrayRef ref = scopedArray.Unsafe();
    XCTAssertEqual(1, CFArrayGetCount(ref));
    XCTAssertTrue(
        CFNumberGetValue((CFNumberRef)CFArrayGetValueAtIndex(ref, 0), kCFNumberIntType, &got));
    XCTAssertEqual(want, got);
  }

  // The original `array` object should still be valid due to the extra retain.
  // Ensure the retain count has decreased since `scopedArray` went out of scope
  XCTAssertEqual(1, CFArrayGetCount(array));
}

- (void)testInto {
  ScopedCFTypeRef<CFURLRef> scopedURLRef =
      ScopedCFTypeRef<CFURLRef>::Assume(CFURLCreateWithFileSystemPath(
          kCFAllocatorDefault, CFSTR("/usr/bin/true"), kCFURLPOSIXPathStyle, YES));

  ScopedCFTypeRef<SecStaticCodeRef> scopedCodeRef;
  XCTAssertFalse(scopedCodeRef);

  SecStaticCodeCreateWithPath(scopedURLRef.Unsafe(), kSecCSDefaultFlags,
                              scopedCodeRef.InitializeInto());

  // Ensure the scoped object was initialized
  XCTAssertTrue(scopedCodeRef);
}

- (void)testBridge {
  ScopedCFTypeRef<CFStringRef> scopedString = ScopedCFTypeRef<CFStringRef>::Retain(CFSTR("foo"));

  NSString *s = scopedString.Bridge<NSString *>();
  XCTAssertEqualObjects(s, @"foo");

  // Force s to nil to ensure no issues with overrelase.
  // The pointer shouldn't have been moved into ARC.
  s = nil;

  XCTAssertTrue(scopedString);
}

- (void)testBridgeRelease {
  ScopedCFTypeRef<CFStringRef> scopedString = ScopedCFTypeRef<CFStringRef>::Retain(CFSTR("foo"));

  NSString *s = scopedString.BridgeRelease<NSString *>();
  XCTAssertEqualObjects(s, @"foo");

  // The scoped object should no longer be valid as it was moved into ARC
  XCTAssertFalse(scopedString);
}

- (void)testBridgeRetain {
  NSString *s = @"foo";

  auto scopedString = ScopedCFTypeRef<CFStringRef>::BridgeRetain(s);
  XCTAssertTrue(scopedString);
  XCTAssertEqual(CFStringCompare(scopedString.Unsafe(), CFSTR("foo"), 0), kCFCompareEqualTo);

  // Ensure changing s doesn't affect the scoped object
  s = nil;
  XCTAssertEqual(CFStringCompare(scopedString.Unsafe(), CFSTR("foo"), 0), kCFCompareEqualTo);
  XCTAssertTrue(scopedString);
}

- (void)testMoves {
  ScopedCFTypeRef<CFStringRef> s1 = ScopedCFTypeRef<CFStringRef>::Retain(CFSTR("foo"));
  ScopedCFTypeRef<CFStringRef> s2;
  XCTAssertTrue(s1);
  XCTAssertFalse(s2);
  XCTAssertEqualObjects(s1.Bridge<NSString *>(), @"foo");

  // Move assignment from s1 to s2, verify contents and that s1 was moved out of
  s2 = std::move(s1);
  XCTAssertFalse(s1);
  XCTAssertTrue(s2);
  XCTAssertEqualObjects(s2.Bridge<NSString *>(), @"foo");

  // Move ctor from s2 into s3
  ScopedCFTypeRef<CFStringRef> s3(std::move(s2));
  XCTAssertFalse(s1);
  XCTAssertFalse(s2);
  XCTAssertTrue(s3);
  XCTAssertEqualObjects(s3.Bridge<NSString *>(), @"foo");
}

- (void)testCopies {
  ScopedCFTypeRef<CFStringRef> s1 = ScopedCFTypeRef<CFStringRef>::Retain(CFSTR("foo"));
  ScopedCFTypeRef<CFStringRef> s2;
  XCTAssertTrue(s1);
  XCTAssertFalse(s2);
  XCTAssertEqualObjects(s1.Bridge<NSString *>(), @"foo");

  // Copy assignment from s1 to s2
  s2 = s1;
  XCTAssertTrue(s1);
  XCTAssertTrue(s2);
  XCTAssertEqualObjects(s1.Bridge<NSString *>(), @"foo");
  XCTAssertEqualObjects(s2.Bridge<NSString *>(), @"foo");

  // Copy ctor from s2 to s3
  ScopedCFTypeRef<CFStringRef> s3(s2);
  XCTAssertTrue(s1);
  XCTAssertTrue(s2);
  XCTAssertTrue(s3);
  XCTAssertEqualObjects(s1.Bridge<NSString *>(), @"foo");
  XCTAssertEqualObjects(s2.Bridge<NSString *>(), @"foo");
  XCTAssertEqualObjects(s3.Bridge<NSString *>(), @"foo");
}

- (void)testAssumeFrom {
  {
    auto [ret, scopedStr] = ScopedCFTypeRef<CFStringRef>::AssumeFrom(^bool(CFStringRef *out) {
      // Check expected memory of the out param
      XCTAssertNotEqual(out, (CFStringRef *)NULL);
      XCTAssertEqual(*out, (CFStringRef)NULL);

      *out = CFStringCreateWithCString(kCFAllocatorDefault, "foo", kCFStringEncodingUTF8);

      return true;
    });

    XCTAssertTrue(ret);
    XCTAssertEqualObjects(scopedStr.Bridge<NSString *>(), @"foo");
  }

  {
    auto [ret, scopedStr] = ScopedCFTypeRef<CFStringRef>::AssumeFrom(^int(CFStringRef *out) {
      // Check expected memory of the out param
      XCTAssertNotEqual(out, (CFStringRef *)NULL);
      XCTAssertEqual(*out, (CFStringRef)NULL);

      *out = CFStringCreateWithCString(kCFAllocatorDefault, "bar", kCFStringEncodingUTF8);

      return 123;
    });

    XCTAssertEqual(ret, 123);
    XCTAssertEqualObjects(scopedStr.Bridge<NSString *>(), @"bar");
  }
}

@end
