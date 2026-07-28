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

#include <google/protobuf/arena.h>
#include <string>

#import "Source/santasyncservice/SNTSantaCommandHandler.h"
#include "commands/v1.pb.h"

/// Package-inventory command execution, shared by every command transport.
@interface SNTSantaCommandHandler (PackageInventory)

/// Run a Sleigh package-inventory scan via santad. Blocks until santad replies;
/// santad owns and bounds the scan. On failure sets the response error and,
/// when available, `errorMessage`.
- (santa::commands::v1::PackageInventoryResponse*)
    handlePackageInventoryRequest:(const santa::commands::v1::PackageInventoryRequest&)request
                          onArena:(google::protobuf::Arena*)arena
                     errorMessage:(std::string*)errorMessage;

@end
