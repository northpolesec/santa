/// Copyright 2022 Google Inc. All rights reserved.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///    http://www.apache.org/licenses/LICENSE-2.0
///
///    Unless required by applicable law or agreed to in writing, software
///    distributed under the License is distributed on an "AS IS" BASIS,
///    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
///    See the License for the specific language governing permissions and
///    limitations under the License.

#import <Foundation/Foundation.h>

#include <memory>

#include "src/santad/event_providers/endpoint_security/EndpointSecurityAPI.h"
#import "src/santad/event_providers/SNTEndpointSecurityClient.h"
#import "src/santad/event_providers/SNTEndpointSecurityEventHandler.h"
#include "src/santad/logs/endpoint_security/Logger.h"
#include "src/santad/Metrics.h"

/// ES Client focused on mitigating accidental or malicious tampering of Santa and its components.
@interface SNTEndpointSecurityTamperResistance
    : SNTEndpointSecurityClient <SNTEndpointSecurityEventHandler>

- (instancetype)initWithESAPI:(std::shared_ptr<santa::EndpointSecurityAPI>)esApi
                      metrics:(std::shared_ptr<santa::Metrics>)metrics
                       logger:(std::shared_ptr<santa::Logger>)logger;

@end
