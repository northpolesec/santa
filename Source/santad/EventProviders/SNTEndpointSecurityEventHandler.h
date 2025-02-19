/// Copyright 2022 Google Inc. All rights reserved.
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

#import <Foundation/Foundation.h>

#include <string>
#include <vector>

#import "Source/common/SNTFileAccessEvent.h"
#include "Source/santad/DataLayer/WatchItemPolicy.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/Metrics.h"

// Protocol that all subclasses of `SNTEndpointSecurityClient` should adhere to.
@protocol SNTEndpointSecurityEventHandler <NSObject>

// Called Synchronously and serially for each message provided by the
// EndpointSecurity framework.
- (void)handleMessage:(santa::Message &&)esMsg
    recordEventMetrics:(void (^)(santa::EventDisposition))recordEventMetrics;

// Called after Santa has finished initializing itself.
// This is an optimal place to subscribe to ES events
- (void)enable;

@end

/// Base protocol for FAA-related clients
@protocol SNTFileAccessAuthorizer <NSObject>

typedef void (^SNTFileAccessDeniedBlock)(SNTFileAccessEvent *event, NSString *customMsg,
                                         NSString *customURL, NSString *customText);

@property SNTFileAccessDeniedBlock fileAccessDeniedBlock;

@end

// Protocol for an object that implements the necessary interfaces
// for handling updates to Data FAA rules.
@protocol SNTDataFileAccessAuthorizer <SNTFileAccessAuthorizer>

- (void)watchItemsCount:(size_t)count
               newPaths:(const santa::SetPairPathAndType &)newPaths
           removedPaths:(const santa::SetPairPathAndType &)removedPaths;

@end

// Protocol for an object that implements the necessary interfaces
// for handling updates to Data FAA rules.
@protocol SNTProcessFileAccessAuthorizer <SNTFileAccessAuthorizer>

- (void)processWatchItemsCount:(size_t)count;

@end

namespace santa {

enum class ProbeInterest {
  kInterested,
  kUninterested,
};

}  // namespace santa

@protocol SNTEndpointSecurityProbe <NSObject>

- (santa::ProbeInterest)probeInterest:(const santa::Message &)esMsg;

@end
