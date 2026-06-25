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
#import "Source/common/SNTStoredProcess.h"

/// Represents a file access event stored in the events database.
@interface SNTStoredFileAccessEvent : SNTStoredEvent <NSSecureCoding>

/// The rule version that was violated.
@property(nullable) NSString* ruleVersion;

/// The rule name that was violated.
@property(nullable) NSString* ruleName;

/// The watched path that was accessed.
@property(nullable) NSString* accessedPath;

/// Information about the process that performed the access.
@property(nullable) SNTStoredProcess* process;

/// The decision made by Santa about the access operation.
@property FileAccessPolicyDecision decision;

/// The server-assigned rule ID that matched this event.
@property int64_t ruleId;

@end
