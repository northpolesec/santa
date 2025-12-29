/// Copyright 2025 North Pole Security, Inc.
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

#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTStoredEvent.h"

@class MOLCertificate;
@class SNTFileInfo;

/// Represents an execution event stored in the events database.
@interface SNTStoredExecutionEvent : SNTStoredEvent <NSSecureCoding>

- (nullable instancetype)initWithFileInfo:(nullable SNTFileInfo *)fileInfo;

/// The SHA-256 of the executed file.
@property(nullable) NSString *fileSHA256;

/// The full path of the executed file.
@property(nullable) NSString *filePath;

/// Set to YES if the event is a part of a bundle. When an event is passed to SantaGUI this propery
/// will be used as an indicator to to kick off bundle hashing as necessary. Default value is NO.
@property BOOL needsBundleHash;

/// If the executed file was part of a bundle, this is the calculated hash of all the nested
/// executables within the bundle.
@property(nullable) NSString *fileBundleHash;

/// If the executed file was part of a bundle, this is the time in ms it took to hash the bundle.
@property(nullable) NSNumber *fileBundleHashMilliseconds;

/// If the executed file was part of a bundle, this is the total count of related mach-o binaries.
@property(nullable) NSNumber *fileBundleBinaryCount;

/// If the executed file was part of the bundle, this is the CFBundleDisplayName, if it exists
/// or the CFBundleName if not.
@property(nullable) NSString *fileBundleName;

/// If the executed file was part of the bundle, this is the path to the bundle.
@property(nullable) NSString *fileBundlePath;

/// The relative path to the bundle's main executable.
@property(nullable) NSString *fileBundleExecutableRelPath;

/// If the executed file was part of the bundle, this is the CFBundleID.
@property(nullable) NSString *fileBundleID;

/// If the executed file was part of the bundle, this is the CFBundleVersion.
@property(nullable) NSString *fileBundleVersion;

/// If the executed file was part of the bundle, this is the CFBundleShortVersionString.
@property(nullable) NSString *fileBundleVersionString;

/// If the executed file was signed, this is an NSArray of MOLCertificate's
/// representing the signing chain.
@property(nullable) NSArray<MOLCertificate *> *signingChain;

/// If the executed file was signed, this is the Team ID if present in the signature information.
@property(nullable) NSString *teamID;

/// If the executed file was signed, this is the Signing ID if present in the signature information.
@property(nullable) NSString *signingID;

/// If the executed file was signed, this is the CDHash of the binary.
@property(nullable) NSString *cdhash;

/// Codesigning flags for the process (from `<Kernel/kern/cs_blobs.h>`)
@property uint32_t codesigningFlags;

/// The signing status of the executable file
@property SNTSigningStatus signingStatus;

/// The user who executed the binary.
@property(nullable) NSString *executingUser;

/// The decision santad returned.
@property SNTEventState decision;

/// The decision depends on the user approving execution.
@property BOOL holdAndAsk;

/// NSArray of logged in users when the decision was made.
@property(nullable) NSArray *loggedInUsers;

/// NSArray of sessions when the decision was made (e.g. nobody@console, nobody@ttys000).
@property(nullable) NSArray *currentSessions;

/// The process ID of the binary being executed.
@property(nullable) NSNumber *pid;

/// The parent process ID of the binary being executed.
@property(nullable) NSNumber *ppid;

/// The name of the parent process.
@property(nullable) NSString *parentName;

/// Quarantine data about the executed file, if any.
@property(nullable) NSString *quarantineDataURL;
@property(nullable) NSString *quarantineRefererURL;
@property(nullable) NSDate *quarantineTimestamp;
@property(nullable) NSString *quarantineAgentBundleID;

/// A generated string representing the publisher based on the signingChain
@property(readonly, nullable) NSString *publisherInfo;

/// Return an array of the underlying SecCertificateRef's of the signingChain
///
/// WARNING: If the refs need to be used for a long time be careful to properly
/// CFRetain/CFRelease the returned items.
@property(readonly, nullable) NSArray *signingChainCertRefs;

/// If the executed file was entitled, this is the set of key/value pairs of entitlements
@property(nullable) NSDictionary *entitlements;

/// Whether or not the set of entitlements were filtered (e.g. due to configuration)
@property BOOL entitlementsFiltered;

/// The timestamp of when the binary was signed. This timestamp is the secure
/// timestamp that was certified by Apple's timestamp authority service and can
/// be trusted.
@property(nullable) NSDate *secureSigningTime;

/// The timestamp of when the binary was signed. This timestamp is the insecure
/// timestamp provided by the developer during signing. It has not been validated
/// and could be spoofed.
@property(nullable) NSDate *signingTime;

@end
