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

@interface SNTKillRequest : NSObject <NSSecureCoding>
@property(readonly) NSString *uuid;
@end

@interface SNTKillRequestRunningProcess : SNTKillRequest <NSSecureCoding>
@property(readonly) int pid;
@property(readonly) int pidversion;
@property(readonly) NSString *bootSessionUUID;

- (instancetype)initWithUUID:(NSString *)uuid
                         pid:(int)pid
                  pidversion:(int)pidversion
             bootSessionUUID:(NSString *)bootSessionUUID;
@end

@interface SNTKillRequestCDHash : SNTKillRequest <NSSecureCoding>
@property(readonly) NSString *cdhash;

- (instancetype)initWithUUID:(NSString *)uuid cdHash:(NSString *)cdhash;
@end

@interface SNTKillRequestSigningID : SNTKillRequest <NSSecureCoding>
@property(readonly) NSString *teamID;
@property(readonly) NSString *signingID;

- (instancetype)initWithUUID:(NSString *)uuid signingID:(NSString *)signingID;
@end

@interface SNTKillRequestTeamID : SNTKillRequest <NSSecureCoding>
@property(readonly) NSString *teamID;

- (instancetype)initWithUUID:(NSString *)uuid teamID:(NSString *)teamID;
@end

typedef NS_ENUM(NSInteger, SNTKilledProcessError) {
  SNTKilledProcessErrorUnknown = 0,
  SNTKilledProcessErrorNone,
  SNTKilledProcessErrorInvalidTarget,
  SNTKilledProcessErrorNotPermitted,
  SNTKilledProcessErrorNoSuchProcess,
  SNTKilledProcessErrorInvalidArgument,
  SNTKilledProcessErrorBootSessionMismatch,
};

@interface SNTKilledProcess : NSObject <NSSecureCoding>
@property(readonly) int pid;
@property(readonly) int pidversion;
@property(readonly) SNTKilledProcessError error;

- (instancetype)initWithPid:(int)pid pidversion:(int)pidversion error:(SNTKilledProcessError)error;
@end

typedef NS_ENUM(NSInteger, SNTKillResponseError) {
  SNTKillResponseErrorUnknown = 0,
  SNTKillResponseErrorNone,
  SNTKillResponseErrorListPids,
  SNTKillResponseErrorInvalidRequest,
};

@interface SNTKillResponse : NSObject <NSSecureCoding>
@property(readonly) NSArray<SNTKilledProcess *> *killedProcesses;
@property(readonly) SNTKillResponseError error;

- (instancetype)initWithKilledProcesses:(NSArray<SNTKilledProcess *> *)killedProcesses;
- (instancetype)initWithError:(SNTKillResponseError)error;
- (instancetype)initWithError:(SNTKillResponseError)error
              killedProcesses:(NSArray<SNTKilledProcess *> *)killedProcesses;
@end
