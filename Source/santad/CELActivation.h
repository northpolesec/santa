/// Copyright 2026 North Pole Security, Inc.
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

#ifndef SANTA__SANTAD__CELACTIVATION_H
#define SANTA__SANTAD__CELACTIVATION_H

#import <Foundation/Foundation.h>

#include <memory>

#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/ProcessTree/process_tree.h"
#import "Source/santad/SNTPolicyProcessor.h"

@class MOLCodesignChecker;

namespace santa {

// Create a block that returns a santa::cel::Activation object for the given
// Message and MOLCodesignChecker object. The block defines a bool parameter
// that determines whether to create a v1 or v2 activation object.
//
// Note: The returned block captures a reference to the Message object and must
// not use it after the Message object is destroyed. Care must be taken to not
// use this in an asynchronous context outside of the evaluation of that
// execution.
ActivationCallbackBlock _Nonnull CreateCELActivationBlock(
    const Message &esMsg, MOLCodesignChecker *_Nullable csInfo,
    std::shared_ptr<santad::process_tree::ProcessTree> processTree);

}  // namespace santa

#endif  // SANTA__SANTAD__CELACTIVATION_H
