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
#import <Foundation/Foundation.h>
#include <sys/signal.h>

#import "Source/common/CodeSigningIdentifierUtils.h"
#include "Source/common/CoderMacros.h"

@interface SNTKillRequest ()
- (instancetype)initWithUUID:(NSString*)uuid;
- (instancetype)initWithUUID:(NSString*)uuid
                      signal:(int)signal
         targetProcessGroups:(BOOL)targetProcessGroups;
@end

@implementation SNTKillRequest

- (instancetype)initWithUUID:(NSString*)uuid {
  return [self initWithUUID:uuid signal:SIGKILL targetProcessGroups:NO];
}

- (instancetype)initWithUUID:(NSString*)uuid
                      signal:(int)signal
         targetProcessGroups:(BOOL)targetProcessGroups {
  // kill(2) treats signal 0 as a liveness probe rather than a kill, and rejects
  // anything outside the signal table at delivery. Either would leave a request
  // that reports success for every match while signaling nothing.
  if (signal <= 0 || signal >= NSIG) {
    return nil;
  }

  self = [super init];
  if (self) {
    _uuid = uuid;
    _signal = signal;
    _targetProcessGroups = targetProcessGroups;
  }
  return self;
}

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder*)coder {
  ENCODE(coder, uuid);
  ENCODE_BOXABLE(coder, signal);
  ENCODE_BOXABLE(coder, targetProcessGroups);
}

- (instancetype)initWithCoder:(NSCoder*)decoder {
  // An archive written before the signal field existed has no signal key at
  // all; keep such a request meaning what it meant when it was written. An
  // archive that does carry a signal is held to the same range the
  // initializers enforce.
  NSNumber* encodedSignal = [decoder decodeObjectOfClass:[NSNumber class] forKey:@"signal"];
  int decodedSignal = encodedSignal ? encodedSignal.intValue : SIGKILL;
  if (decodedSignal <= 0 || decodedSignal >= NSIG) {
    return nil;
  }

  self = [super init];
  if (self) {
    DECODE(decoder, uuid, NSString);
    _signal = decodedSignal;
    DECODE_SELECTOR(decoder, targetProcessGroups, NSNumber, boolValue);
  }
  return self;
}

@end

//
// SNTKillRequestRunningProcess
//
@implementation SNTKillRequestRunningProcess

- (instancetype)initWithUUID:(NSString*)uuid
                         pid:(int)pid
                  pidversion:(int)pidversion
             bootSessionUUID:(NSString*)bootSessionUUID {
  return [self initWithUUID:uuid
                        pid:pid
                 pidversion:pidversion
            bootSessionUUID:bootSessionUUID
                     signal:SIGKILL
        targetProcessGroups:NO];
}

- (instancetype)initWithUUID:(NSString*)uuid
                         pid:(int)pid
                  pidversion:(int)pidversion
             bootSessionUUID:(NSString*)bootSessionUUID
                      signal:(int)signal
         targetProcessGroups:(BOOL)targetProcessGroups {
  if (pid == 0 || pidversion == 0) {
    return nil;
  } else {
    // Validate the UUID and normalize it to not have hyphens and be lowercase.
    if ([[NSUUID alloc] initWithUUIDString:bootSessionUUID]) {
      // If we have a long form UUID, shorten it.
      bootSessionUUID = [[bootSessionUUID stringByReplacingOccurrencesOfString:@"-" withString:@""]
          lowercaseString];
    } else {
      // If an NSUUID could not be initialized, see if it is the short version
      static NSCharacterSet* nonHex = [[NSCharacterSet
          characterSetWithCharactersInString:@"0123456789abcdefABCDEF"] invertedSet];
      if (bootSessionUUID.length == 32 &&
          [bootSessionUUID rangeOfCharacterFromSet:nonHex].location == NSNotFound) {
        bootSessionUUID = [bootSessionUUID lowercaseString];
      } else {
        return nil;
      }
    }
  }

  self = [super initWithUUID:uuid signal:signal targetProcessGroups:targetProcessGroups];
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

- (void)encodeWithCoder:(NSCoder*)coder {
  [super encodeWithCoder:coder];
  ENCODE_BOXABLE(coder, pid);
  ENCODE_BOXABLE(coder, pidversion);
  ENCODE(coder, bootSessionUUID);
}

- (instancetype)initWithCoder:(NSCoder*)decoder {
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

- (instancetype)initWithUUID:(NSString*)uuid cdHash:(NSString*)cdhash {
  return [self initWithUUID:uuid cdHash:cdhash signal:SIGKILL targetProcessGroups:NO];
}

- (instancetype)initWithUUID:(NSString*)uuid
                      cdHash:(NSString*)cdhash
                      signal:(int)signal
         targetProcessGroups:(BOOL)targetProcessGroups {
  if (!santa::IsValidCDHash(cdhash)) {
    return nil;
  }

  self = [super initWithUUID:uuid signal:signal targetProcessGroups:targetProcessGroups];
  if (self) {
    _cdhash = cdhash;
  }
  return self;
}

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder*)coder {
  [super encodeWithCoder:coder];
  ENCODE(coder, cdhash);
}

- (instancetype)initWithCoder:(NSCoder*)decoder {
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

- (instancetype)initWithUUID:(NSString*)uuid signingID:(NSString*)signingID {
  return [self initWithUUID:uuid signingID:signingID signal:SIGKILL targetProcessGroups:NO];
}

- (instancetype)initWithUUID:(NSString*)uuid
                   signingID:(NSString*)signingID
                      signal:(int)signal
         targetProcessGroups:(BOOL)targetProcessGroups {
  auto [tid, sid] = santa::SplitSigningID(signingID);
  if (!tid || !sid) {
    return nil;
  }

  self = [super initWithUUID:uuid signal:signal targetProcessGroups:targetProcessGroups];
  if (self) {
    _teamID = tid;
    _signingID = sid;
  }
  return self;
}

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder*)coder {
  [super encodeWithCoder:coder];
  ENCODE(coder, teamID);
  ENCODE(coder, signingID);
}

- (instancetype)initWithCoder:(NSCoder*)decoder {
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

- (instancetype)initWithUUID:(NSString*)uuid teamID:(NSString*)teamID {
  return [self initWithUUID:uuid teamID:teamID signal:SIGKILL targetProcessGroups:NO];
}

- (instancetype)initWithUUID:(NSString*)uuid
                      teamID:(NSString*)teamID
                      signal:(int)signal
         targetProcessGroups:(BOOL)targetProcessGroups {
  if (!santa::IsValidTeamID(teamID)) {
    return nil;
  }

  self = [super initWithUUID:uuid signal:signal targetProcessGroups:targetProcessGroups];
  if (self) {
    _teamID = [teamID uppercaseString];
  }
  return self;
}

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder*)coder {
  [super encodeWithCoder:coder];
  ENCODE(coder, teamID);
}

- (instancetype)initWithCoder:(NSCoder*)decoder {
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

- (void)encodeWithCoder:(NSCoder*)coder {
  ENCODE_BOXABLE(coder, pid);
  ENCODE_BOXABLE(coder, pidversion);
  ENCODE_BOXABLE(coder, error);
}

- (instancetype)initWithCoder:(NSCoder*)decoder {
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

- (instancetype)initWithKilledProcesses:(NSArray<SNTKilledProcess*>*)killedProcesses {
  return [self initWithError:SNTKillResponseErrorNone killedProcesses:killedProcesses];
}

- (instancetype)initWithError:(SNTKillResponseError)error {
  return [self initWithError:error killedProcesses:nil];
}

- (instancetype)initWithError:(SNTKillResponseError)error
              killedProcesses:(NSArray<SNTKilledProcess*>*)killedProcesses {
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

- (void)encodeWithCoder:(NSCoder*)coder {
  ENCODE_BOXABLE(coder, error);
  ENCODE(coder, killedProcesses);
}

- (instancetype)initWithCoder:(NSCoder*)decoder {
  self = [super init];
  if (self) {
    DECODE_SELECTOR(decoder, error, NSNumber, integerValue);
    DECODE_ARRAY(decoder, killedProcesses, SNTKilledProcess);
  }
  return self;
}

@end
