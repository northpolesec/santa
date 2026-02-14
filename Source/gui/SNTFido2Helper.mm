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

#import "Source/gui/SNTFido2Helper.h"

#import <Cocoa/Cocoa.h>
#import <CommonCrypto/CommonDigest.h>

#import "Source/gui/SNTMessageView-Swift.h"

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTLogging.h"
#import "Source/gui/SNTMessageWindowController.h"

#include <fido.h>
#include <fido/eddsa.h>
#include <fido/es256.h>
#include <fido/rs256.h>

static const size_t kMaxFido2Devices = 8;

// Guarded by sActiveDevLock. Written on the FIDO2 background thread before the
// blocking fido_dev_get_assert call, read on the main thread by the cancel button.
static fido_dev_t* sActiveDev = nil;
static NSLock* sActiveDevLock;

@implementation SNTFido2Helper

+ (void)initialize {
  if (self == [SNTFido2Helper class]) {
    sActiveDevLock = [[NSLock alloc] init];
  }
}

+ (BOOL)isFido2DeviceAvailable {
  // Do NOT call libfido2/IOKit here — this method is called on the main thread
  // during SwiftUI rendering.  Always return YES so the FIDO2 path is available;
  // actual device enumeration happens on a background thread in authorizeWithReason:.
  return YES;
}

+ (void)authorizeWithReason:(NSString*)reason
                 replyBlock:(void (^)(BOOL success, BOOL deviceWasFound))replyBlock {
  // All FIDO2/IOKit work runs on a background thread. The prompt window is
  // shown/hidden via dispatch_async to main — the main thread is free because
  // callers use async XPC (TMM) or return immediately (execution auth).
  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    BOOL deviceWasFound = NO;
    BOOL success = [self performFido2Authorization:reason deviceWasFound:&deviceWasFound];
    replyBlock(success, deviceWasFound);
  });
}

#pragma mark - Prompt Window

+ (void)cancelActiveDevice {
  [sActiveDevLock lock];
  fido_dev_t* dev = sActiveDev;
  if (dev) {
    fido_dev_cancel(dev);
  }
  [sActiveDevLock unlock];
}

+ (NSWindow*)showPromptWindowWithReason:(NSString*)reason {
  NSString* detail =
      [NSString stringWithFormat:NSLocalizedString(@"To %@", @"FIDO2 prompt reason prefix"),
                                 reason ?: @"authorize"];

  NSWindow* window = [SNTMessageWindowController defaultWindow];
  window.releasedWhenClosed = NO;
  window.canHide = NO;
  window.hidesOnDeactivate = NO;
  window.contentViewController =
      [SNTFido2PromptViewFactory makePromptViewControllerWithDetail:detail
                                                           onCancel:^{
                                                             [self cancelActiveDevice];
                                                           }];

  // Above Santa's notification windows (NSModalPanelWindowLevel).
  [window setContentSize:window.contentViewController.view.fittingSize];
  window.level = NSPopUpMenuWindowLevel;
  [window center];
  [window makeKeyAndOrderFront:nil];
  [NSApp activateIgnoringOtherApps:YES];
  return window;
}

#pragma mark - Private

+ (NSData*)clientDataHashForReason:(NSString*)reason {
  // Build a client data JSON similar to WebAuthn spec for context binding.
  NSDictionary* clientData = @{
    @"type" : @"santa.authorize",
    @"challenge" : reason ?: @"",
    @"origin" : @"com.northpolesec.santa",
  };
  NSData* jsonData = [NSJSONSerialization dataWithJSONObject:clientData options:0 error:nil];
  if (!jsonData) {
    return nil;
  }

  uint8_t hash[CC_SHA256_DIGEST_LENGTH];
  CC_SHA256(jsonData.bytes, (CC_LONG)jsonData.length, hash);
  return [NSData dataWithBytes:hash length:CC_SHA256_DIGEST_LENGTH];
}

+ (BOOL)performFido2Authorization:(NSString*)reason deviceWasFound:(BOOL*)deviceWasFound {
  // Enumerate devices.
  fido_dev_info_t* devlist = fido_dev_info_new(kMaxFido2Devices);
  if (!devlist) {
    LOGE(@"FIDO2: Failed to allocate device info list");
    return NO;
  }

  size_t found = 0;
  int r = fido_dev_info_manifest(devlist, kMaxFido2Devices, &found);
  if (r != FIDO_OK || found == 0) {
    LOGE(@"FIDO2: No devices found (error: %d)", r);
    fido_dev_info_free(&devlist, kMaxFido2Devices);
    return NO;
  }

  // Open the first available device.
  const fido_dev_info_t* di = fido_dev_info_ptr(devlist, 0);
  const char* path = fido_dev_info_path(di);

  fido_dev_t* dev = fido_dev_new();
  if (!dev) {
    fido_dev_info_free(&devlist, kMaxFido2Devices);
    return NO;
  }

  r = fido_dev_open(dev, path);
  fido_dev_info_free(&devlist, kMaxFido2Devices);
  if (r != FIDO_OK) {
    LOGE(@"FIDO2: Failed to open device at %s (error: %d)", path, r);
    fido_dev_free(&dev);
    return NO;
  }

  *deviceWasFound = YES;

  // Device found and opened — show the "touch your key" prompt window.
  __block NSWindow* promptWindow = nil;
  dispatch_async(dispatch_get_main_queue(), ^{
    promptWindow = [self showPromptWindowWithReason:reason];
  });

  // If credentials are configured, perform full assertion with verification.
  // Otherwise, just require user presence (touch) on any attached key.
  SNTConfigurator* config = [SNTConfigurator configurator];
  NSString* rpID = config.fido2RelyingPartyID;
  NSArray<NSDictionary*>* credentials = config.fido2Credentials;
  BOOL success;

  if (rpID.length > 0 && credentials.count > 0) {
    success = [self performAssertionOnDevice:dev reason:reason rpID:rpID credentials:credentials];
  } else {
    success = [self performUserPresenceOnDevice:dev];
  }

  fido_dev_close(dev);
  fido_dev_free(&dev);

  // Dismiss the prompt window.
  dispatch_async(dispatch_get_main_queue(), ^{
    [promptWindow close];
  });

  return success;
}

+ (BOOL)performUserPresenceOnDevice:(fido_dev_t*)dev {
  // Simple user-presence check: send a dummy FIDO2 assertion that only
  // requires the user to touch the key. No credential verification.
  LOGI(@"FIDO2: Waiting for security key touch (user presence)...");

  fido_assert_t* assert = fido_assert_new();
  if (!assert) {
    return NO;
  }

  // Use a dummy RP ID — we don't care about verification, only UP.
  int r = fido_assert_set_rp(assert, "localhost");
  if (r != FIDO_OK) {
    fido_assert_free(&assert);
    return NO;
  }

  // Set a dummy client data hash.
  uint8_t cdh[32] = {0};
  r = fido_assert_set_clientdata_hash(assert, cdh, sizeof(cdh));
  if (r != FIDO_OK) {
    fido_assert_free(&assert);
    return NO;
  }

  // Require user presence (touch).
  fido_assert_set_up(assert, FIDO_OPT_TRUE);

  // This blocks until the user touches the key (or cancel is called).
  [sActiveDevLock lock];
  sActiveDev = dev;
  [sActiveDevLock unlock];
  r = fido_dev_get_assert(dev, assert, NULL);
  [sActiveDevLock lock];
  sActiveDev = nil;
  [sActiveDevLock unlock];
  fido_assert_free(&assert);

  // FIDO_ERR_NO_CREDENTIALS is expected since we used a dummy RP — but if
  // the device returned it, the user still touched the key (UP was satisfied).
  // Some keys return FIDO_ERR_INVALID_CREDENTIAL or FIDO_ERR_NO_CREDENTIALS
  // after the touch. Accept these as success.
  if (r == FIDO_OK || r == FIDO_ERR_NO_CREDENTIALS) {
    LOGI(@"FIDO2: User presence confirmed");
    return YES;
  }

  LOGE(@"FIDO2: User presence check failed (error: %d)", r);
  return NO;
}

+ (BOOL)performAssertionOnDevice:(fido_dev_t*)dev
                          reason:(NSString*)reason
                            rpID:(NSString*)rpID
                     credentials:(NSArray<NSDictionary*>*)credentials {
  fido_assert_t* assert = fido_assert_new();
  if (!assert) {
    return NO;
  }

  // Set relying party ID.
  int r = fido_assert_set_rp(assert, rpID.UTF8String);
  if (r != FIDO_OK) {
    LOGE(@"FIDO2: Failed to set RP ID (error: %d)", r);
    fido_assert_free(&assert);
    return NO;
  }

  // Set client data hash.
  NSData* cdh = [self clientDataHashForReason:reason];
  if (!cdh) {
    fido_assert_free(&assert);
    return NO;
  }
  r = fido_assert_set_clientdata_hash(assert, (const unsigned char*)cdh.bytes, cdh.length);
  if (r != FIDO_OK) {
    LOGE(@"FIDO2: Failed to set client data hash (error: %d)", r);
    fido_assert_free(&assert);
    return NO;
  }

  // Add allowed credentials.
  for (NSDictionary* cred in credentials) {
    NSString* credIDBase64 = cred[@"credential_id"];
    if (!credIDBase64) continue;

    NSData* credID = [[NSData alloc] initWithBase64EncodedString:credIDBase64 options:0];
    if (!credID) continue;

    r = fido_assert_allow_cred(assert, (const unsigned char*)credID.bytes, credID.length);
    if (r != FIDO_OK) {
      LOGW(@"FIDO2: Failed to add credential (error: %d)", r);
    }
  }

  // Request user presence (touch).
  r = fido_assert_set_up(assert, FIDO_OPT_TRUE);
  if (r != FIDO_OK) {
    LOGW(@"FIDO2: Failed to set UP option (error: %d)", r);
  }

  // Perform the assertion — this blocks until the user touches the key (or cancel is called).
  LOGI(@"FIDO2: Waiting for security key touch...");
  [sActiveDevLock lock];
  sActiveDev = dev;
  [sActiveDevLock unlock];
  r = fido_dev_get_assert(dev, assert, NULL);
  [sActiveDevLock lock];
  sActiveDev = nil;
  [sActiveDevLock unlock];
  if (r != FIDO_OK) {
    LOGE(@"FIDO2: Assertion failed (error: %d)", r);
    fido_assert_free(&assert);
    return NO;
  }

  // Verify the assertion against stored public keys.
  BOOL verified = [self verifyAssertion:assert credentials:credentials];
  fido_assert_free(&assert);
  return verified;
}

+ (BOOL)verifyAssertion:(fido_assert_t*)assert credentials:(NSArray<NSDictionary*>*)credentials {
  if (fido_assert_count(assert) == 0) {
    LOGE(@"FIDO2: No assertions returned");
    return NO;
  }

  // Get the credential ID from the assertion response.
  const unsigned char* assertCredID = fido_assert_id_ptr(assert, 0);
  size_t assertCredIDLen = fido_assert_id_len(assert, 0);

  // Find the matching credential and verify with its public key.
  for (NSDictionary* cred in credentials) {
    NSString* credIDBase64 = cred[@"credential_id"];
    NSString* pubKeyBase64 = cred[@"public_key"];
    NSString* type = cred[@"type"];

    if (!credIDBase64 || !pubKeyBase64) continue;

    NSData* credID = [[NSData alloc] initWithBase64EncodedString:credIDBase64 options:0];
    if (!credID) continue;

    // Match credential ID.
    if (credID.length != assertCredIDLen ||
        memcmp(credID.bytes, assertCredID, assertCredIDLen) != 0) {
      continue;
    }

    NSData* pubKeyData = [[NSData alloc] initWithBase64EncodedString:pubKeyBase64 options:0];
    if (!pubKeyData) continue;

    int coseAlg = COSE_ES256;  // Default to ES256.
    if ([type isEqualToString:@"eddsa"]) {
      coseAlg = COSE_EDDSA;
    } else if ([type isEqualToString:@"rs256"]) {
      coseAlg = COSE_RS256;
    }

    const unsigned char* pkBytes = (const unsigned char*)pubKeyData.bytes;
    size_t pkLen = pubKeyData.length;
    int r = FIDO_ERR_INVALID_ARGUMENT;

    if (coseAlg == COSE_ES256) {
      es256_pk_t* pk = es256_pk_new();
      if (pk && es256_pk_from_ptr(pk, pkBytes, pkLen) == FIDO_OK) {
        r = fido_assert_verify(assert, 0, coseAlg, pk);
      }
      es256_pk_free(&pk);
    } else if (coseAlg == COSE_EDDSA) {
      eddsa_pk_t* edpk = eddsa_pk_new();
      if (edpk && eddsa_pk_from_ptr(edpk, pkBytes, pkLen) == FIDO_OK) {
        r = fido_assert_verify(assert, 0, coseAlg, edpk);
      }
      eddsa_pk_free(&edpk);
    } else if (coseAlg == COSE_RS256) {
      rs256_pk_t* rspk = rs256_pk_new();
      if (rspk && rs256_pk_from_ptr(rspk, pkBytes, pkLen) == FIDO_OK) {
        r = fido_assert_verify(assert, 0, coseAlg, rspk);
      }
      rs256_pk_free(&rspk);
    }

    if (r == FIDO_OK) {
      LOGI(@"FIDO2: Assertion verified successfully");
      return YES;
    } else {
      LOGE(@"FIDO2: Assertion verification failed for credential (error: %d)", r);
    }
  }

  LOGE(@"FIDO2: No matching credential could verify the assertion");
  return NO;
}

@end
