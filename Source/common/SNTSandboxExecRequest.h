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

#import "Source/common/SNTRuleIdentifiers.h"

/// Request payload sent by santactl to santad's `prepareSandboxExec:reply:`.
/// Immutable once constructed; santad decides which fields to trust based on
/// the exec target's codesigning flags at AUTH_EXEC. Callers that need the
/// raw cdhash or SHA-256 read them directly off `identifiers`.
@interface SNTSandboxExecRequest : NSObject <NSSecureCoding>

- (instancetype)initWithIdentifiers:(SNTRuleIdentifiers*)identifiers
                              fsDev:(uint64_t)fsDev
                              fsIno:(uint64_t)fsIno
                       resolvedPath:(NSString*)resolvedPath;

- (instancetype)init NS_UNAVAILABLE;

@property(readonly) SNTRuleIdentifiers* identifiers;

/// Vnode identity of the file santactl pinned via O_RDONLY fd.
@property(readonly) uint64_t fsDev;
@property(readonly) uint64_t fsIno;

/// Diagnostic only. Never trust for authorization.
@property(readonly) NSString* resolvedPath;

@end
