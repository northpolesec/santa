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

#import "Source/common/SNTKillCommand.h"
#include <Foundation/Foundation.h>

#import "Source/common/CodeSigningIdentifierUtils.h"
#include "Source/common/CoderMacros.h"

@interface SNTKillRequest ()
- (instancetype)initWithUUID:(NSString *)uuid;
@end

@implementation SNTKillRequest

- (instancetype)initWithUUID:(NSString *)uuid {
  self = [super init];
  if (self) {
    _uuid = uuid;
  }
  return self;
}

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder {
  ENCODE(coder, uuid);
}

- (instancetype)initWithCoder:(NSCoder *)decoder {
  self = [super init];
  if (self) {
    DECODE(decoder, uuid, NSString);
  }
  return self;
}

@end

//
// SNTKillRequestRunningProcess
//
@implementation SNTKillRequestRunningProcess

- (instancetype)initWithUUID:(NSString *)uuid
                         pid:(int)pid
                  pidversion:(int)pidversion
             bootSessionUUID:(NSString *)bootSessionUUID {
  if (pid == 0 || pidversion == 0 || ![[NSUUID alloc] initWithUUIDString:bootSessionUUID]) {
    return nil;
  }

  self = [super initWithUUID:uuid];
  if (self) {
    _pid = pid;
    _pidversion = pidversion;
    _bootSessionUUID = bootSessionUUID;
  }
  return self;
}

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder {
  [super encodeWithCoder:coder];
  ENCODE_BOXABLE(coder, pid);
  ENCODE_BOXABLE(coder, pidversion);
  ENCODE(coder, bootSessionUUID);
}

- (instancetype)initWithCoder:(NSCoder *)decoder {
  self = [super initWithCoder:decoder];
  if (self) {
    DECODE_SELECTOR(decoder, pid, NSNumber, intValue);
    DECODE_SELECTOR(decoder, pidversion, NSNumber, intValue);
    DECODE(decoder, bootSessionUUID, NSString);
  }
  return self;
}

@end

//
// SNTKillRequestCDHash
//
@implementation SNTKillRequestCDHash

- (instancetype)initWithUUID:(NSString *)uuid cdHash:(NSString *)cdhash {
  if (!santa::IsValidCDHash(cdhash)) {
    return nil;
  }

  self = [super initWithUUID:uuid];
  if (self) {
    _cdhash = cdhash;
  }
  return self;
}

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder {
  [super encodeWithCoder:coder];
  ENCODE(coder, cdhash);
}

- (instancetype)initWithCoder:(NSCoder *)decoder {
  self = [super initWithCoder:decoder];
  if (self) {
    DECODE(decoder, cdhash, NSString);
  }
  return self;
}

@end

//
// SNTKillRequestSigningID
//
@implementation SNTKillRequestSigningID

- (instancetype)initWithUUID:(NSString *)uuid signingID:(NSString *)signingID {
  auto [tid, sid] = santa::SplitSigningID(signingID);
  if (!tid || !sid) {
    return nil;
  }

  self = [super initWithUUID:uuid];
  if (self) {
    _teamID = tid;
    _signingID = sid;
  }
  return self;
}

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder {
  [super encodeWithCoder:coder];
  ENCODE(coder, teamID);
  ENCODE(coder, signingID);
}

- (instancetype)initWithCoder:(NSCoder *)decoder {
  self = [super initWithCoder:decoder];
  if (self) {
    DECODE(decoder, teamID, NSString);
    DECODE(decoder, signingID, NSString);
  }
  return self;
}

@end

//
// SNTKillRequestTeamID
//
@implementation SNTKillRequestTeamID

- (instancetype)initWithUUID:(NSString *)uuid teamID:(NSString *)teamID {
  if (!santa::IsValidTeamID(teamID)) {
    return nil;
  }

  self = [super initWithUUID:uuid];
  if (self) {
    _teamID = [teamID uppercaseString];
  }
  return self;
}

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder {
  [super encodeWithCoder:coder];
  ENCODE(coder, teamID);
}

- (instancetype)initWithCoder:(NSCoder *)decoder {
  self = [super initWithCoder:decoder];
  if (self) {
    DECODE(decoder, teamID, NSString);
  }
  return self;
}

@end

//
// SNTKilledProcess
//
@implementation SNTKilledProcess

- (instancetype)initWithPid:(int)pid pidversion:(int)pidversion error:(SNTKilledProcessError)error {
  self = [super init];
  if (self) {
    _pid = pid;
    _pidversion = pidversion;
    _error = error;
  }
  return self;
}

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder {
  ENCODE_BOXABLE(coder, pid);
  ENCODE_BOXABLE(coder, pidversion);
  ENCODE_BOXABLE(coder, error);
}

- (instancetype)initWithCoder:(NSCoder *)decoder {
  self = [super init];
  if (self) {
    DECODE_SELECTOR(decoder, pid, NSNumber, intValue);
    DECODE_SELECTOR(decoder, pidversion, NSNumber, intValue);
    DECODE_SELECTOR(decoder, error, NSNumber, integerValue);
  }
  return self;
}

@end

//
// SNTKillResponse
//
@implementation SNTKillResponse

- (instancetype)initWithKilledProcesses:(NSArray<SNTKilledProcess *> *)killedProcesses {
  return [self initWithError:SNTKillResponseErrorNone killedProcesses:killedProcesses];
}

- (instancetype)initWithError:(SNTKillResponseError)error {
  return [self initWithError:error killedProcesses:nil];
}

- (instancetype)initWithError:(SNTKillResponseError)error
              killedProcesses:(NSArray<SNTKilledProcess *> *)killedProcesses {
  self = [super init];
  if (self) {
    _error = error;
    _killedProcesses = killedProcesses;
  }
  return self;
}

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder {
  ENCODE_BOXABLE(coder, error);
  ENCODE(coder, killedProcesses);
}

- (instancetype)initWithCoder:(NSCoder *)decoder {
  self = [super init];
  if (self) {
    DECODE_SELECTOR(decoder, error, NSNumber, integerValue);
    DECODE_ARRAY(decoder, killedProcesses, SNTKilledProcess);
  }
  return self;
}

@end
