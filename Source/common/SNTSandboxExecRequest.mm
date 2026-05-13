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

#import "Source/common/SNTSandboxExecRequest.h"

#import "Source/common/CoderMacros.h"

@implementation SNTSandboxExecRequest

- (instancetype)initWithIdentifiers:(SNTRuleIdentifiers*)identifiers
                              fsDev:(uint64_t)fsDev
                              fsIno:(uint64_t)fsIno
                       resolvedPath:(NSString*)resolvedPath {
  self = [super init];
  if (self) {
    _identifiers = identifiers;
    _fsDev = fsDev;
    _fsIno = fsIno;
    _resolvedPath = [resolvedPath copy];
  }
  return self;
}

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder*)coder {
  ENCODE(coder, identifiers);
  ENCODE(coder, resolvedPath);
  ENCODE_BOXABLE(coder, fsDev);
  ENCODE_BOXABLE(coder, fsIno);
}

- (instancetype)initWithCoder:(NSCoder*)decoder {
  self = [super init];
  if (self) {
    DECODE(decoder, identifiers, SNTRuleIdentifiers);
    DECODE(decoder, resolvedPath, NSString);
    DECODE_SELECTOR(decoder, fsDev, NSNumber, unsignedLongLongValue);
    DECODE_SELECTOR(decoder, fsIno, NSNumber, unsignedLongLongValue);
  }
  return self;
}

@end
