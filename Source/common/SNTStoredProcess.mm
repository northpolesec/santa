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

#import "Source/common/SNTStoredProcess.h"

#import "Source/common/CoderMacros.h"
#import "Source/common/MOLCertificate.h"

@implementation SNTStoredProcess

+ (void)initialize {
  if (self == [SNTStoredProcess class]) {
    // FAA events persisted by older versions carry this type's former class
    // name; map it so they still decode after the rename.
    [NSKeyedUnarchiver setClass:self forClassName:@"SNTStoredFileAccessProcess"];
  }
}

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder*)coder {
  ENCODE(coder, filePath);
  ENCODE(coder, cdhash);
  ENCODE(coder, fileSHA256);
  ENCODE(coder, signingID);
  ENCODE(coder, signingChain);
  ENCODE(coder, teamID);
  ENCODE(coder, pid);
  ENCODE(coder, executingUser);
  ENCODE(coder, parent);
}

- (instancetype)initWithCoder:(NSCoder*)decoder {
  self = [super init];
  if (self) {
    DECODE(decoder, filePath, NSString);
    DECODE(decoder, cdhash, NSString);
    DECODE(decoder, fileSHA256, NSString);
    DECODE(decoder, signingID, NSString);
    DECODE_ARRAY(decoder, signingChain, MOLCertificate);
    DECODE(decoder, teamID, NSString);
    DECODE(decoder, pid, NSNumber);
    DECODE(decoder, executingUser, NSString);
    DECODE(decoder, parent, SNTStoredProcess);
  }
  return self;
}

- (NSString*)description {
  return [NSString stringWithFormat:@"SNTStoredProcess (pid: %@): %@", self.pid, self.filePath];
}

@end
