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

// System Integrity Protection configuration flags, matching the CSR_ALLOW_* flags in bsd/sys/csr.h
// in the XNU sources. A status of 0 means every protection is enforced (SIP fully enabled); each
// set bit disables one protection.
typedef NS_OPTIONS(uint32_t, SNTSIPStatusFlags) {
  SNTSIPStatusFlagAllowUntrustedKexts = (1u << 0),
  SNTSIPStatusFlagAllowUnrestrictedFS = (1u << 1),
  SNTSIPStatusFlagAllowTaskForPID = (1u << 2),
  SNTSIPStatusFlagAllowUnrestrictedDtrace = (1u << 5),
  SNTSIPStatusFlagAllowUnrestrictedNVRAM = (1u << 6),
};

// The set of protections that `csrutil disable` clears on every macOS version we support. Compare a
// status against this mask to distinguish a full disable from a partial/custom configuration. This
// is a best-effort label; the raw status value is authoritative.
static const uint32_t kSNTSIPFullDisableMask =
    SNTSIPStatusFlagAllowUntrustedKexts | SNTSIPStatusFlagAllowUnrestrictedFS |
    SNTSIPStatusFlagAllowTaskForPID | SNTSIPStatusFlagAllowUnrestrictedDtrace |
    SNTSIPStatusFlagAllowUnrestrictedNVRAM;

///
///  Simple class for fetching SIP status
///
@interface SNTSIPStatus : NSObject

///
///  @return current SIP status
///
+ (uint32_t)currentStatus;

@end
