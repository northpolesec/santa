/// Copyright 2015 Google Inc. All rights reserved.
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
#import <SystemExtensions/SystemExtensions.h>

///
/// Delegate for managing system extension activation/deactivation requests.
///
/// This class encapsulates the entire lifecycle of a system extension request,
/// including creating the request, submitting it, and handling callbacks.
/// For network extensions, it also manages filter configuration.
///
@interface SNTSystemExtensionDelegate : NSObject <OSSystemExtensionRequestDelegate>

@property(readonly) OSSystemExtensionRequest *request;
@property(readonly) BOOL isNetworkExtension;
@property(readonly) BOOL isActivation;

///
/// Factory method to create a delegate for activating the Santa daemon system extension.
///
+ (instancetype)delegateForSantadActivation;

///
/// Factory method to create a delegate for deactivating the Santa daemon system extension.
///
+ (instancetype)delegateForSantadDeactivation;

///
/// Factory method to create a delegate for activating the santanetd network extension.
///
+ (instancetype)delegateForSantanetdActivation;

///
/// Factory method to create a delegate for deactivating the santanetd network extension.
///
+ (instancetype)delegateForSantanetdDeactivation;

///
/// Submit the system extension request to the system.
///
- (void)submit;

@end
