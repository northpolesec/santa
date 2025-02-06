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

@class MOLCertificate;

#import <Foundation/Foundation.h>

/**
  `MOLCodesignChecker` validates a binary (either on-disk or in memory) has been signed
  and if so allows for pulling out the certificates that were used to sign it.

  @warning When checking bundles this class will ignore non-code resources inside the bundle for
  validation purposes. This very dramatically speeds up validation but means that it is possible
  to tamper with resource files without this class noticing.
*/
@interface MOLCodesignChecker : NSObject

/**  The `SecStaticCodeRef` that this `MOLCodesignChecker` is wrapping. */
@property(readonly) SecStaticCodeRef codeRef;

/**
  The designated requirement for this binary.

  Does not need to be freed.
*/
@property(readonly, nonatomic) SecRequirementRef requirement;

/**
  A dictionary of raw signing information provided by the Security framework.
*/
@property(readonly) NSDictionary *signingInformation;

/**
  An array of dictionaries. Each dictionary contains a single architecture string as a key and
  a dictionary of raw signing information as the value.
  Available for universal/FAT binaries only.
*/
@property(readonly) NSArray *universalSigningInformation;

/**
  An array of `MOLCertificate` objects representing the chain that signed this binary.

  @see [MOLCertificate](http://cocoadocs.org/docsets/MOLCertificate)
*/
@property(readonly) NSArray *certificates;

/**
  The leaf certificate that this binary was signed with.

  @see [MOLCertificate](http://cocoadocs.org/docsets/MOLCertificate)
*/
@property(readonly, nonatomic) MOLCertificate *leafCertificate;

/** The on-disk path of this binary. */
@property(readonly, nonatomic) NSString *binaryPath;

/** Code signature flags. */
@property(readonly, nonatomic) uint32_t signatureFlags;

/** The CDHash for this binary, if properly signed. */
@property(readonly) NSString *cdhash;

/** The Team ID from the certificate that signed this binary. */
@property(readonly) NSString *teamID;

/** The developer provided signing ID for this binary. */
@property(readonly) NSString *signingID;

/** Whether or not this binary is considered a platform binary (i.e. part of the OS) */
@property(readonly) BOOL platformBinary;

/** The entitlements encoded in this binary. */
@property(readonly) NSDictionary *entitlements;

/**
  Designated initializer

  @note Takes ownership of `codeRef`.

  @param codeRef A `SecStaticCodeRef` or `SecCodeRef` representing a binary.
  @param error NSError to be filled in if validation fails for any reason.
  @return An initialized `MOLCodesignChecker`
*/
- (instancetype)initWithSecStaticCodeRef:(SecStaticCodeRef)codeRef error:(NSError **)error;

/**
  Initialize with a SecStaticCodeRef (or SecCodeRef);

  @note Takes ownership of `codeRef`.

  @param codeRef A `SecStaticCodeRef` or `SecCodeRef` representing a binary.
  @return An initialized `MOLCodesignChecker` or nil if validation failed.
*/
- (instancetype)initWithSecStaticCodeRef:(SecStaticCodeRef)codeRef;

/**
  Initialize with a binary on disk.

  @note While the method name mentions binary path, it is possible to initialize with a bundle
  instead by passing the path to the root of the bundle.

  @param binaryPath Path to a binary file on disk.
  @param error NSError to be filled in if validation fails for any reason.
  @return An initialized `MOLCodesignChecker`.
*/
- (instancetype)initWithBinaryPath:(NSString *)binaryPath error:(NSError **)error;

/**
  Initialize with a binary on disk.

  @note While the method name mentions binary path, it is possible to initialize with a bundle
  instead by passing the path to the root of the bundle.

  @param binaryPath Path to a binary file on disk.
  @return An initialized `MOLCodesignChecker` or nil if validation failed.
*/
- (instancetype)initWithBinaryPath:(NSString *)binaryPath;

/**
  Wrapper around initWithBinaryPath:error: that takes a file descriptor for reading.
  The file descriptor will be used to read binary header infomation. This provides a minor
  performace increase if the caller already has the file open.

  @note The file offset will be set to the amount of bytes read while parsing the header.
*/
- (instancetype)initWithBinaryPath:(NSString *)binaryPath
                    fileDescriptor:(int)fileDescriptor
                             error:(NSError **)error;
/**
  Wrapper around initWithBinaryPath:fileDescriptor:error:.
*/
- (instancetype)initWithBinaryPath:(NSString *)binaryPath fileDescriptor:(int)fileDescriptor;

/**
  Initialize with a running binary using its process ID.

  @param pid PID of a running process.
  @param error NSError to be filled in if validation fails for any reason.
  @return An initialized `MOLCodesignChecker`.
*/
- (instancetype)initWithPID:(pid_t)pid error:(NSError **)error;

/**
  Initialize with a running binary using its process ID.

  @param pid PID of a running process.
  @return An initialized `MOLCodesignChecker` or nil if validation failed.
*/
- (instancetype)initWithPID:(pid_t)pid;

/**
  Initialize with the currently running process.

  @param error Optional NSError to be filled in if validation fails for any reason.
  @return An initialized `MOLCodesignChecker`.
*/
- (instancetype)initWithSelfError:(NSError **)error;

/**
  Initialize with the currently running process.

  @return An initialized `MOLCodesignChecker` or nil if validation failed.
*/
- (instancetype)initWithSelf;

/**
  Compares the signatures of the binaries represented by this `MOLCodesignChecker` and
  `otherChecker` to see if both are correctly signed and the leaf signatures are identical.

  @return YES if both binaries are signed with the same leaf certificate.
*/
- (BOOL)signingInformationMatches:(MOLCodesignChecker *)otherChecker;

/**
  Validates this binary against the given requirement.
*/
- (BOOL)validateWithRequirement:(SecRequirementRef)requirement;

@end
