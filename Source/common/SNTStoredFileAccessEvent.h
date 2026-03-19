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
@class SNTStoredFileAccessProcess;

/// Represents a file access event stored in the events database.
@interface SNTStoredFileAccessEvent : SNTStoredEvent <NSSecureCoding>

/// The rule version that was violated.
@property(nullable) NSString *ruleVersion;

/// The rule name that was violated.
@property(nullable) NSString *ruleName;

/// The watched path that was accessed.
@property(nullable) NSString *accessedPath;

/// Information about the process that performed the access.
@property(nullable) SNTStoredFileAccessProcess *process;

/// The decision made by Santa about the access operation.
@property FileAccessPolicyDecision decision;

@end

@interface SNTStoredFileAccessProcess : NSObject <NSSecureCoding>

/// The full path of the process's executable file.
@property(nullable) NSString *filePath;

/// If the process was signed, this is the CDHash of the binary.
@property(nullable) NSString *cdhash;

/// The SHA-256 of the executed file.
@property(nullable) NSString *fileSHA256;

/// If the process was signed, this is the Signing ID if present in the signature information.
@property(nullable) NSString *signingID;

/// If the executed file was signed, this is an NSArray of MOLCertificate's
/// representing the signing chain.
@property(nullable) NSArray<MOLCertificate *> *signingChain;

/// If the process was signed, this is the Team ID if present in the signature information.
@property(nullable) NSString *teamID;

/// The process ID of the binary being executed.
@property(nullable) NSNumber *pid;

/// The user who executed the binary.
@property(nullable) NSString *executingUser;

/// Information about this process's parent
@property(nullable) SNTStoredFileAccessProcess *parent;

@end
