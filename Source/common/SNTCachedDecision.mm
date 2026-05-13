
/// Copyright 2015-2022 Google Inc. All rights reserved.
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

#import "Source/common/SNTCachedDecision.h"

@implementation SNTCachedDecision

- (instancetype)init {
  return [self initWithVnode:(SantaVnode){}];
}

- (instancetype)initWithEndpointSecurityFile:(const es_file_t*)esFile {
  return [self initWithVnode:SantaVnode::VnodeForFile(esFile)];
}

- (instancetype)initWithVnode:(SantaVnode)vnode {
  self = [super init];
  if (self) {
    _vnodeId = vnode;
    _cacheable = YES;
  }
  return self;
}

- (instancetype)initWithCachedIdentity:(SNTCachedDecision*)previous {
  self = [self init];
  if (self) {
    _sha256 = previous.sha256;
    _cdhash = previous.cdhash;
    _teamID = previous.teamID;
    _signingID = previous.signingID;
    _rawSigningID = previous.rawSigningID;
    _certSHA256 = previous.certSHA256;
    _certCommonName = previous.certCommonName;
    _certChain = previous.certChain;
    _entitlements = previous.entitlements;
    _rawEntitlements = previous.rawEntitlements;
    _entitlementsFiltered = previous.entitlementsFiltered;
    _secureSigningTime = previous.secureSigningTime;
    _signingTime = previous.signingTime;
  }
  return self;
}

- (id)copyWithZone:(NSZone*)zone {
  SNTCachedDecision* copy = [[SNTCachedDecision alloc] initWithVnode:_vnodeId];
  copy.decision = _decision;
  copy.decisionClientMode = _decisionClientMode;
  copy.decisionExtra = _decisionExtra;
  copy.sha256 = _sha256;
  copy.certSHA256 = _certSHA256;
  copy.certCommonName = _certCommonName;
  copy.certChain = _certChain;
  copy.teamID = _teamID;
  copy.signingID = _signingID;
  copy.rawSigningID = _rawSigningID;
  copy.cdhash = _cdhash;
  copy.entitlements = _entitlements;
  copy.rawEntitlements = _rawEntitlements;
  copy.entitlementsFiltered = _entitlementsFiltered;
  copy.platformBinary = _platformBinary;
  copy.codesigningFlags = _codesigningFlags;
  copy.signingStatus = _signingStatus;
  copy.secureSigningTime = _secureSigningTime;
  copy.signingTime = _signingTime;
  copy.quarantineURL = _quarantineURL;
  copy.customMsg = _customMsg;
  copy.customURL = _customURL;
  copy.silentBlock = _silentBlock;
  copy.seatbeltRequired = _seatbeltRequired;
  copy.staticRule = _staticRule;
  copy.ruleId = _ruleId;
  copy.cacheable = _cacheable;
  copy.holdAndAsk = _holdAndAsk;
  copy.silentTouchID = _silentTouchID;
  copy.touchIDCooldownMinutes = _touchIDCooldownMinutes;
  return copy;
}

@end
