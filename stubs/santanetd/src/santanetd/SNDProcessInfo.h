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

// Forward declaration for stub
struct SantaVnode;

// Stub implementation to allow Santa to build independently without
// access to the Network Extension repo.
@interface SNDProcessInfo : NSObject <NSSecureCoding>

@property(nonatomic, readonly) pid_t pid;
@property(nonatomic, readonly) int pidversion;

- (SantaVnode)vnode;

@end
