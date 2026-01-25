/// Copyright 2015 Google Inc. All rights reserved.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///    http://www.apache.org/licenses/LICENSE-2.0
///
///    Unless required by applicable law or agreed to in writing, software
///    distributed under the License is distributed on an "AS IS" BASIS,
///    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
///    See the License for the specific language governing permissions and
///    limitations under the License.

#import "Source/common/MOLCodesignChecker.h"

#include <CoreFoundation/CoreFoundation.h>
#import <Security/Security.h>
#include <sys/cdefs.h>

#include <mach-o/arch.h>
#include <mach-o/fat.h>
#include <mach-o/utils.h>

#import "Source/common/MOLCertificate.h"
#include "Source/common/ScopedCFTypeRef.h"
#include "Source/common/String.h"

/**
  kStaticSigningFlags are the flags used when validating signatures on disk.

  Don't validate resources but do validate nested code. Ignoring resources _dramatically_ speeds
  up validation (see below) but does mean images, plists, etc will not be checked and modifying
  these will not be considered invalid. To ensure any code inside the binary is still checked,
  we check nested code.

  We also want to make sure no network access occurs as a result of us checking,
  for performance. This potentially means accepting revoked certs for a short
  period but this is an acceptable trade-off.

  Timings with different flags:
    Checking Xcode 5.1.1 bundle:
       kSecCSDefaultFlags:                                   3.895s
       kSecCSDoNotValidateResources:                         0.013s
       kSecCSDoNotValidateResources | kSecCSCheckNestedCode: 0.013s

    Checking Google Chrome 36.0.1985.143 bundle:
       kSecCSDefaultFlags:                                   0.529s
       kSecCSDoNotValidateResources:                         0.032s
       kSecCSDoNotValidateResources | kSecCSCheckNestedCode: 0.033s
*/
static const SecCSFlags kStaticSigningFlags =
    (kSecCSDoNotValidateResources | kSecCSCheckNestedCode | kSecCSCheckAllArchitectures |
     kSecCSNoNetworkAccess);

/**
  kSigningFlags are the flags used when validating signatures for running binaries.

  No special flags needed currently.
*/
static const SecCSFlags kSigningFlags = kSecCSDefaultFlags;

NSString *const kMOLCodesignCheckerErrorDomain = @"com.northpolesec.santa.molcodesignchecker";

__BEGIN_DECLS

// SecAssessment API declarations - these exist in Security.framework but lack public headers
typedef const struct __SecAssessment *SecAssessmentRef;
static const uint64_t kSecAssessmentDefaultFlags = 0;

extern SecAssessmentRef SecAssessmentCreate(CFURLRef path, uint64_t flags, CFDictionaryRef context,
                                            CFErrorRef *errors);
extern CFDictionaryRef SecAssessmentCopyResult(SecAssessmentRef assessment, uint64_t flags,
                                               CFErrorRef *errors);
extern CFStringRef kSecAssessmentAssessmentVerdict;
extern CFStringRef kSecAssessmentAssessmentAuthority;
extern CFStringRef kSecAssessmentAssessmentSource;
extern CFStringRef kSecAssessmentAssessmentOriginator;
extern CFStringRef kSecAssessmentContextKeyOperation;
extern CFStringRef kSecAssessmentOperationTypeExecute;

__END_DECLS

using ScopedCFError = santa::ScopedCFTypeRef<CFErrorRef>;
using ScopedCFString = santa::ScopedCFTypeRef<CFStringRef>;
using ScopedSecAssessment = santa::ScopedCFTypeRef<SecAssessmentRef>;
using ScopedSecStaticCode = santa::ScopedCFTypeRef<SecStaticCodeRef>;

@implementation SNTAssessmentResult

- (instancetype)initWithAccepted:(BOOL)accepted
                         skipped:(BOOL)skipped
                          source:(NSString *)source
                      originator:(NSString *)originator
                          reason:(NSString *)reason {
  self = [super init];
  if (self) {
    _accepted = accepted;
    _source = [source copy];
    _originator = [originator copy];
    _reason = [reason copy];
  }
  return self;
}

- (instancetype)initWithAccepted:(BOOL)accepted
                          source:(NSString *)source
                      originator:(NSString *)originator
                          reason:(NSString *)reason {
  return [self initWithAccepted:accepted
                        skipped:NO
                         source:source
                     originator:originator
                         reason:reason];
}

- (instancetype)initRejectedWithReason:(NSString *)reason {
  return [self initWithAccepted:NO source:nil originator:nil reason:reason];
}

- (instancetype)initSkippedWithReason:(NSString *)reason {
  return [self initWithAccepted:NO
                        skipped:YES
                         source:nil
                     originator:nil
                         reason:reason];
}

@end

@interface MOLCodesignChecker ()
/// Cached designated requirement
@property SecRequirementRef requirement;

// Cached on-disk binary path
@property NSString *binaryPath;

// Cached on-disk binary file descriptor
@property int binaryFileDescriptor;
@end

@implementation MOLCodesignChecker

#pragma mark Init/dealloc

- (instancetype)initWithSecStaticCodeRef:(SecStaticCodeRef)codeRef error:(NSError **)error {
  self = [super init];

  if (self) {
    auto [status, scopedError] = ScopedCFError::AssumeFrom(^OSStatus(CFErrorRef *out) {
      if (CFGetTypeID(codeRef) == SecStaticCodeGetTypeID()) {
        return SecStaticCodeCheckValidityWithErrors(codeRef, kStaticSigningFlags, NULL, out);
      } else if (CFGetTypeID(codeRef) == SecCodeGetTypeID()) {
        return SecCodeCheckValidityWithErrors((SecCodeRef)codeRef, kSigningFlags, NULL, out);
      } else {
        OSStatus status = errSecUnimplemented;
        *out = (CFErrorRef)CFBridgingRetain([self errorWithCode:status
                                                    description:@"Invalid code ref type"]);
        return status;
      }
    });

    // For static code checks perform additional checks across all slices
    if (CFGetTypeID(codeRef) == SecStaticCodeGetTypeID()) {
      // Ensure signing is consistent for all architectures.
      // Any issues found here take precedence over already found issues.
      if (!_binaryPath) _binaryPath = [self binaryPathForCodeRef:self.codeRef];
      NSArray *infos = [self universalSigningInformationForBinaryPath:_binaryPath
                                                       fileDescriptor:_binaryFileDescriptor];
      if (infos) _universalSigningInformation = infos;
      if (infos && ![self allSigningInformationMatches:infos]) {
        status = errSecCSSignatureInvalid;
        scopedError = ScopedCFError::BridgeRetain([self
            errorWithCode:status
              description:@"Signing is not consistent for all architectures."]);
      }
    }

    // Do not set _signingInformation or _certificates for universal binaries with signing issues.
    NSError *err = scopedError.BridgeRelease<NSError *>();
    if (!([err.domain isEqualToString:kMOLCodesignCheckerErrorDomain] &&
          status == errSecCSSignatureInvalid)) {
      // Get CFDictionary of signing information for binary
      CFDictionaryRef signingDict = NULL;
      SecCodeCopySigningInformation(codeRef, kSecCSSigningInformation, &signingDict);
      _signingInformation = CFBridgingRelease(signingDict);

      // Get array of certificates.
      NSArray *certs = _signingInformation[(__bridge id)kSecCodeInfoCertificates];
      _certificates = [MOLCertificate certificatesFromArray:certs];
    }
    if (status != errSecSuccess)
      if (error) *error = err;
    _codeRef = codeRef;
    CFRetain(_codeRef);
  }
  return self;
}

- (instancetype)initWithSecStaticCodeRef:(SecStaticCodeRef)codeRef {
  NSError *error;
  self = [self initWithSecStaticCodeRef:codeRef error:&error];
  return (error) ? nil : self;
}

- (instancetype)initWithBinaryPath:(NSString *)binaryPath error:(NSError **)error {
  return [self initWithBinaryPath:binaryPath fileDescriptor:-1 error:error];
}

- (instancetype)initWithBinaryPath:(NSString *)binaryPath {
  NSError *error;
  self = [self initWithBinaryPath:binaryPath error:&error];
  return (error) ? nil : self;
}

- (instancetype)initWithBinaryPath:(NSString *)binaryPath
                    fileDescriptor:(int)fileDescriptor
                             error:(NSError **)error {
  OSStatus status = errSecSuccess;
  SecStaticCodeRef codeRef = NULL;

  // Get SecStaticCodeRef for binary
  status = SecStaticCodeCreateWithPath((__bridge CFURLRef)[NSURL fileURLWithPath:binaryPath],
                                       kSecCSDefaultFlags, &codeRef);
  if (status != errSecSuccess) {
    if (error) {
      *error = [self errorWithCode:status];
    }
    return nil;
  }

  _binaryPath = binaryPath;
  _binaryFileDescriptor = (fileDescriptor != -1) ? fileDescriptor : -1;

  self = [self initWithSecStaticCodeRef:codeRef error:error];
  if (codeRef) CFRelease(codeRef);  // it was retained above
  return self;
}

- (instancetype)initWithBinaryPath:(NSString *)binaryPath fileDescriptor:(int)fileDescriptor {
  NSError *error;
  self = [self initWithBinaryPath:binaryPath fileDescriptor:fileDescriptor error:&error];
  return (error) ? nil : self;
}

- (instancetype)initWithPID:(pid_t)pid error:(NSError **)error {
  OSStatus status = errSecSuccess;
  SecCodeRef codeRef = NULL;
  NSDictionary *attributes = @{(__bridge NSString *)kSecGuestAttributePid : @(pid)};

  status = SecCodeCopyGuestWithAttributes(NULL, (__bridge CFDictionaryRef)attributes,
                                          kSecCSDefaultFlags, &codeRef);
  if (status != errSecSuccess) {
    if (error) {
      *error = [self errorWithCode:status];
    }
    return nil;
  }

  self = [self initWithSecStaticCodeRef:(SecStaticCodeRef)codeRef error:error];
  if (codeRef) CFRelease(codeRef);  // it was retained above
  return self;
}

- (instancetype)initWithPID:(pid_t)pid {
  NSError *error;
  self = [self initWithPID:pid error:&error];
  return (error) ? nil : self;
}

- (instancetype)initWithSelfError:(NSError **)error {
  SecCodeRef codeSelf = NULL;
  OSStatus status = SecCodeCopySelf(kSecCSDefaultFlags, &codeSelf);

  if (status != errSecSuccess) {
    if (error) {
      *error = [self errorWithCode:status];
    }
    return nil;
  }

  self = [self initWithSecStaticCodeRef:(SecStaticCodeRef)codeSelf error:error];
  if (codeSelf) CFRelease(codeSelf);  // it was retained above
  return self;
}

- (instancetype)initWithSelf {
  NSError *error;
  self = [self initWithSelfError:&error];
  return (error) ? nil : self;
}

- (instancetype)init {
  [self doesNotRecognizeSelector:_cmd];
  return nil;
}

- (void)dealloc {
  if (_codeRef) {
    CFRelease(_codeRef);
    _codeRef = NULL;
  }
  if (_requirement) {
    CFRelease(_requirement);
    _requirement = NULL;
  }
}

#pragma mark Description

- (NSString *)description {
  NSString *binarySource;
  if (CFGetTypeID(self.codeRef) == SecStaticCodeGetTypeID()) {
    binarySource = @"On-disk";
  } else {
    binarySource = @"In-memory";
  }

  return [NSString stringWithFormat:@"%@ binary, signed by %@, located at: %@", binarySource,
                                    self.leafCertificate.orgName, self.binaryPath];
}

#pragma mark Public accessors

- (SecRequirementRef)requirement {
  if (!_requirement) {
    SecCodeCopyDesignatedRequirement(self.codeRef, kSecCSDefaultFlags, &_requirement);
  }
  return _requirement;
}

- (MOLCertificate *)leafCertificate {
  return [self.certificates firstObject];
}

- (NSString *)binaryPath {
  if (!_binaryPath) _binaryPath = [self binaryPathForCodeRef:self.codeRef];
  return _binaryPath;
}

- (NSString *)binaryPathForCodeRef:(SecStaticCodeRef)codeRef {
  CFURLRef path;
  OSStatus status = SecCodeCopyPath(codeRef, kSecCSDefaultFlags, &path);
  NSURL *pathURL = CFBridgingRelease(path);
  if (status != errSecSuccess) return nil;
  return [pathURL path];
}

- (uint32_t)signatureFlags {
  return [self.signingInformation[(__bridge id)kSecCodeInfoFlags] intValue];
}

- (NSString *)cdhash {
  return santa::StringToNSString(
      santa::BufToHexString((NSData *)self.signingInformation[(__bridge id)kSecCodeInfoUnique]));
}

- (NSString *)teamID {
  return self.signingInformation[(__bridge id)kSecCodeInfoTeamIdentifier];
}

- (NSString *)signingID {
  return self.signingInformation[(__bridge id)kSecCodeInfoIdentifier];
}

- (BOOL)platformBinary {
  id p = self.signingInformation[(__bridge id)kSecCodeInfoPlatformIdentifier];
  if (![p isKindOfClass:[NSNumber class]] || [p intValue] == 0) return NO;
  return YES;
}

- (NSDictionary *)entitlements {
  return self.signingInformation[(__bridge NSString *)kSecCodeInfoEntitlementsDict];
}

- (NSDate *)secureSigningTime {
  return self.signingInformation[(__bridge NSString *)kSecCodeInfoTimestamp];
}

- (NSDate *)signingTime {
  return self.signingInformation[(__bridge NSString *)kSecCodeInfoTime];
}

- (BOOL)signingInformationMatches:(MOLCodesignChecker *)otherChecker {
  return [self.certificates isEqual:otherChecker.certificates];
}

- (BOOL)validateWithRequirement:(SecRequirementRef)requirement {
  if (!requirement) return NO;
  return (SecStaticCodeCheckValidity(self.codeRef, kStaticSigningFlags, requirement) ==
          errSecSuccess);
}

- (SNTAssessmentResult *)securityAssessment {
  if (!self.binaryPath) return nil;

  // Security assessment (spctl --assess) is only meaningful for app bundles
  NSBundle *bundle = [NSBundle bundleWithPath:self.binaryPath];
  if (!bundle || !bundle.bundleIdentifier) {
    return [[SNTAssessmentResult alloc] initSkippedWithReason:@"not part of an app bundle"];
  }

  NSURL *url = [NSURL fileURLWithPath:self.binaryPath];

  auto [assessmentRef, createError] = ScopedCFError::AssumeFrom([&](CFErrorRef *out) {
    return ScopedSecAssessment::Assume(SecAssessmentCreate(
        (__bridge CFURLRef)url, kSecAssessmentDefaultFlags, (__bridge CFDictionaryRef) @{}, out));
  });
  if (!assessmentRef) {
    return [self rejectedAssessmentWithError:createError];
  }

  auto [result, resultError] = ScopedCFError::AssumeFrom(
      [&](CFErrorRef *out) { return SecAssessmentCopyResult(assessmentRef.Unsafe(), 0, out); });
  if (!result) {
    return [self rejectedAssessmentWithError:resultError];
  }

  NSDictionary *resultDict = CFBridgingRelease(result);

  BOOL accepted = [resultDict[(__bridge NSString *)kSecAssessmentAssessmentVerdict] boolValue];
  NSString *source = nil;
  NSString *originator = nil;
  NSString *reason = nil;

  NSDictionary *authority = resultDict[(__bridge NSString *)kSecAssessmentAssessmentAuthority];
  if (authority) {
    source = authority[(__bridge NSString *)kSecAssessmentAssessmentSource];
    originator = authority[(__bridge NSString *)kSecAssessmentAssessmentOriginator];
  }

  // If rejected, try to get the reason from the CS error code
  if (!accepted) {
    NSNumber *csError = resultDict[@"assessment:cserror"];
    if (csError) {
      OSStatus csErrorCode = [csError intValue];
      ScopedCFString errorMessage =
          ScopedCFString::Assume(SecCopyErrorMessageString(csErrorCode, NULL));
      if (errorMessage) {
        reason = errorMessage.BridgeRelease<NSString *>();
      }
    }
  }

  return [[SNTAssessmentResult alloc] initWithAccepted:accepted
                                                source:source
                                            originator:originator
                                                reason:reason];
}

- (NSString *)validationStatusForArchitecture:(NSString *)architecture {
  NSDictionary *offsets;
  if (_binaryFileDescriptor == -1) {
    offsets = [self architectureAndOffsetsForUniversalBinaryPath:self.binaryPath];
  } else {
    offsets = [self architectureAndOffsetsForFileDescriptor:_binaryFileDescriptor];
  }

  ScopedSecStaticCode scopedCodeRef;
  SecStaticCodeRef codeRef = NULL;

  if (offsets) {
    NSNumber *offset = offsets[architecture];
    if (!offset) return nil;

    NSDictionary *attributes =
        @{(__bridge NSString *)kSecCodeAttributeUniversalFileOffset : offset};
    SecStaticCodeRef newCodeRef = NULL;
    OSStatus createStatus = SecStaticCodeCreateWithPathAndAttributes(
        (__bridge CFURLRef)[NSURL fileURLWithPath:self.binaryPath], kSecCSDefaultFlags,
        (__bridge CFDictionaryRef)attributes, &newCodeRef);

    if (createStatus != errSecSuccess || !newCodeRef) {
      return @"Failed to create code reference";
    }
    scopedCodeRef = ScopedSecStaticCode::Assume(newCodeRef);
    codeRef = scopedCodeRef.Unsafe();
  } else {
    // Single-architecture binary - use the existing code ref
    codeRef = self.codeRef;
  }

  auto [status, scopedError] = ScopedCFError::AssumeFrom(^OSStatus(CFErrorRef *out) {
    return SecStaticCodeCheckValidityWithErrors(codeRef, kStaticSigningFlags, NULL, out);
  });

  if (status == errSecSuccess) {
    // Check if it's ad-hoc signed
    CFDictionaryRef signingDict = NULL;
    SecCodeCopySigningInformation(codeRef, kSecCSSigningInformation, &signingDict);
    NSDictionary *info = CFBridgingRelease(signingDict);
    int flags = [info[(__bridge id)kSecCodeInfoFlags] intValue];
    if (flags & kSecCodeSignatureAdhoc) {
      return @"Ad-hoc signed";
    }
    return @"Valid on disk";
  }

  if (status == errSecCSUnsigned) {
    return @"Unsigned";
  }

  // Get a human-readable error message
  if (scopedError) {
    return [NSString
        stringWithFormat:@"Invalid (%@)",
                         scopedError.Bridge<NSError *>().localizedDescription ?: @"unknown"];
  }
  ScopedCFString errorMessage = ScopedCFString::Assume(SecCopyErrorMessageString(status, NULL));
  return
      [NSString stringWithFormat:@"Invalid (%@)", errorMessage.Bridge<NSString *>() ?: @"unknown"];
}

#pragma mark Private

- (SNTAssessmentResult *)rejectedAssessmentWithError:(const ScopedCFError &)scopedError {
  NSString *reason;
  if (scopedError) {
    OSStatus errorCode = (OSStatus)CFErrorGetCode(scopedError.Unsafe());
    ScopedCFString errorMessage =
        ScopedCFString::Assume(SecCopyErrorMessageString(errorCode, NULL));
    if (errorMessage) {
      reason = [NSString stringWithFormat:@"%@ (%d)", errorMessage.Bridge<NSString *>(), errorCode];
    } else {
      reason = [NSString stringWithFormat:@"error %d", errorCode];
    }
  } else {
    reason = @"Assessment failed";
  }
  return [[SNTAssessmentResult alloc] initRejectedWithReason:reason];
}

- (NSError *)errorWithCode:(OSStatus)code description:(NSString *)description {
  if (!description) {
    CFStringRef cfErrorString = SecCopyErrorMessageString(code, NULL);
    description = CFBridgingRelease(cfErrorString);
  }

  NSDictionary *userInfo = @{NSLocalizedDescriptionKey : description ?: @""};
  return [NSError errorWithDomain:kMOLCodesignCheckerErrorDomain code:code userInfo:userInfo];
}

- (NSError *)errorWithCode:(OSStatus)code {
  return [self errorWithCode:code description:nil];
}

- (BOOL)allSigningInformationMatches:(NSArray *)signingInformation {
  NSMutableSet *chains = [NSMutableSet set];
  for (NSDictionary *arch in signingInformation) {
    NSDictionary *info = arch.allValues.firstObject;
    int flags = [info[(__bridge id)kSecCodeInfoFlags] intValue];
    if (flags & kSecCodeSignatureAdhoc) {
      [chains addObject:@"-"];
    } else {
      NSArray *certs = info[(__bridge id)kSecCodeInfoCertificates];
      [chains addObject:[MOLCertificate certificatesFromArray:certs]];
    }
    if (chains.count > 1) return NO;
  }
  return YES;
}

- (NSArray *)universalSigningInformationForBinaryPath:(NSString *)path fileDescriptor:(int)fd {
  NSDictionary *offsets;
  if (fd == -1) {
    offsets = [self architectureAndOffsetsForUniversalBinaryPath:path];
  } else {
    offsets = [self architectureAndOffsetsForFileDescriptor:fd];
  }

  if (!offsets) return nil;
  NSMutableArray *infos = [NSMutableArray arrayWithCapacity:offsets.count];
  for (NSString *arch in offsets) {
    NSDictionary *attributes =
        @{(__bridge NSString *)kSecCodeAttributeUniversalFileOffset : offsets[arch]};
    SecStaticCodeRef codeRef = NULL;
    SecStaticCodeCreateWithPathAndAttributes((__bridge CFURLRef)[NSURL fileURLWithPath:path],
                                             kSecCSDefaultFlags,
                                             (__bridge CFDictionaryRef)attributes, &codeRef);
    CFDictionaryRef signingDict = NULL;
    SecCodeCopySigningInformation(codeRef, kSecCSSigningInformation, &signingDict);
    [infos addObject:@{arch : CFBridgingRelease(signingDict) ?: @{}}];
    if (codeRef) CFRelease(codeRef);
  }
  return infos.count ? infos : nil;
}

- (NSString *)architectureString:(struct fat_arch *)fatArch bigEndian:(BOOL)bigEndian {
  cpu_type_t cpu = bigEndian ? OSSwapBigToHostInt(fatArch->cputype) : fatArch->cputype;
  cpu_subtype_t cpuSub = bigEndian ? OSSwapBigToHostInt(fatArch->cpusubtype) : fatArch->cpusubtype;
  const char *name = macho_arch_name_for_cpu_type(cpu, cpuSub);
  if (name) {
    return @(name);
  }
  return [NSString stringWithFormat:@"%i:%i", cpu, cpuSub];
}

- (NSDictionary *)architectureAndOffsetsForFileDescriptor:(int)fd {
  size_t len = sizeof(struct fat_header);
  const uint8 *headerBytes = (const uint8 *)alloca(len);
  lseek(fd, 0, SEEK_SET);
  if (read(fd, (void *)headerBytes, len) != len) return nil;
  struct fat_header *fh = (struct fat_header *)headerBytes;
  uint32_t m = fh->magic;
  if (!(m == FAT_MAGIC || m == FAT_CIGAM || m == FAT_MAGIC_64 || m == FAT_CIGAM_64)) return nil;

  BOOL bigEndian = (m == FAT_CIGAM || m == FAT_CIGAM_64);
  BOOL use64 = (m == FAT_MAGIC_64 || m == FAT_CIGAM_64);

  int archCount = bigEndian ? OSSwapBigToHostInt32(fh->nfat_arch) : fh->nfat_arch;
  if (archCount < 1 || archCount > 128) return nil;  // Upper bound of 4k

  len = use64 ? sizeof(struct fat_arch_64) * archCount : sizeof(struct fat_arch) * archCount;
  const uint8 *archBytes = (const uint8 *)alloca(len);
  if (read(fd, (void *)archBytes, len) != len) return nil;

  NSMutableDictionary *offsets = [NSMutableDictionary dictionaryWithCapacity:archCount];
  if (use64) {
    struct fat_arch_64 *fat_arch = (struct fat_arch_64 *)archBytes;
    for (int i = 0; i < archCount; ++i) {
      uint64_t offset = bigEndian ? OSSwapBigToHostInt64(fat_arch[i].offset) : fat_arch[i].offset;
      // Passing an offset of 0 to SecStaticCodeCreateWithPathAndAttributes() will create a code ref
      // for the whole universal binary.
      if (offset > 0) {
        NSString *arch = [self architectureString:(struct fat_arch *)&fat_arch[i]
                                        bigEndian:bigEndian];
        offsets[arch] = @(offset);
      }
    }
  } else {
    struct fat_arch *fat_arch = (struct fat_arch *)archBytes;
    for (int i = 0; i < archCount; ++i) {
      uint32_t offset = bigEndian ? OSSwapBigToHostInt32(fat_arch[i].offset) : fat_arch[i].offset;
      // Passing an offset of 0 to SecStaticCodeCreateWithPathAndAttributes() will create a code ref
      // for the whole universal binary.
      if (offset > 0) {
        NSString *arch = [self architectureString:&fat_arch[i] bigEndian:bigEndian];
        offsets[arch] = @(offset);
      }
    }
  }

  return offsets.count ? offsets : nil;
}

- (NSDictionary *)architectureAndOffsetsForUniversalBinaryPath:(NSString *)path {
  int fd = open(path.UTF8String, O_RDONLY | O_CLOEXEC);
  if (fd == -1) return nil;
  NSDictionary *offsets = [self architectureAndOffsetsForFileDescriptor:fd];
  close(fd);
  return offsets;
}

@end
