/// Copyright 2025 North Pole Security, Inc.
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

#import "Source/common/SNTStoredFileAccessEvent.h"

#import "Source/common/CoderMacros.h"
#import "Source/common/MOLCertificate.h"

@implementation SNTStoredFileAccessEvent

- (instancetype)init {
  self = [super init];
  if (self) {
    _process = [[SNTStoredFileAccessProcess alloc] init];
  }
  return self;
}
+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder {
  [super encodeWithCoder:coder];
  ENCODE(coder, accessedPath);
  ENCODE(coder, ruleVersion);
  ENCODE(coder, ruleName);
  ENCODE(coder, process);
}

- (instancetype)initWithCoder:(NSCoder *)decoder {
  self = [super initWithCoder:decoder];
  if (self) {
    DECODE(decoder, ruleVersion, NSString);
    DECODE(decoder, ruleName, NSString);
    DECODE(decoder, accessedPath, NSString);
    DECODE(decoder, process, SNTStoredFileAccessProcess);
  }
  return self;
}

- (NSString *)description {
  return [NSString stringWithFormat:@"SNTStoredFileAccessEvent: Accessed: %@, By: %@",
                                    self.accessedPath, self.process];
}

- (NSString *)hashForEvent {
  return _process.fileSHA256;
}

@end

@implementation SNTStoredFileAccessProcess

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder {
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

- (instancetype)initWithCoder:(NSCoder *)decoder {
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
    DECODE(decoder, parent, SNTStoredFileAccessProcess);
  }
  return self;
}

- (NSString *)description {
  return [NSString
      stringWithFormat:@"SNTStoredFileAccessProcess (pid: %@): %@", self.pid, self.filePath];
}

@end
