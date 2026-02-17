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

#include "Source/common/NKeyTokenValidator.h"

#include <dispatch/dispatch.h>
#include <ctime>
#include <optional>

#include <openssl/curve25519.h>

#import "Source/common/SNTLogging.h"
#import "Source/common/String.h"

__BEGIN_DECLS

#include "src/util.h"

__END_DECLS

namespace santa {

NKeyTokenValidator::NKeyTokenValidator(std::set<std::string> trustedNKeys, NSString *accountJWT,
                                       NSString *userJWT)
    : trustedNKeys_(std::move(trustedNKeys)), accountJWT_(accountJWT), userJWT_(userJWT) {}

namespace {

struct JWTParts {
  std::string_view header;
  std::string_view payload;
  std::string_view signature;
};

// JWTs use Base64URL encoding (RFC 7515 §3.1, RFC 4648 §5) which differs from
// standard Base64: '-' replaces '+', '_' replaces '/', and padding is omitted.
// Foundation's initWithBase64EncodedString only handles standard Base64, so we
// convert back before decoding.
std::vector<uint8_t> Base64URLDecode(std::string_view in) {
  NSMutableString *b64 = [[NSMutableString alloc] initWithBytes:in.data()
                                                         length:in.size()
                                                       encoding:NSUTF8StringEncoding];
  [b64 replaceOccurrencesOfString:@"-" withString:@"+" options:0 range:NSMakeRange(0, b64.length)];
  [b64 replaceOccurrencesOfString:@"_" withString:@"/" options:0 range:NSMakeRange(0, b64.length)];

  // Pad to a multiple of 4
  while (b64.length % 4) {
    [b64 appendString:@"="];
  }

  NSData *data = [[NSData alloc] initWithBase64EncodedString:b64 options:0];
  if (!data) {
    return {};
  }
  const auto *bytes = static_cast<const uint8_t *>(data.bytes);
  return {bytes, bytes + data.length};
}

// Base32 decoding uses nats_Base32_DecodeString from the nats.c library because
// there is no system API for Base32 on Apple platforms (SecTransform's
// kSecBase32Encoding was deprecated in macOS 13 with no replacement, and
// Foundation only provides Base64).
//
// nats_Base32_Init populates the library's internal decode lookup table. It is
// normally called during nats_Open(), but since we use the util functions
// directly without initializing the full NATS client, we call it ourselves.
void EnsureBase32Initialized() {
  static dispatch_once_t once;
  dispatch_once(&once, ^{
    nats_Base32_Init();
  });
}

// Decode a NATS NKey (public key) into its 32-byte Ed25519 public key.
// The nats.c library only exposes seed decoding (_decodeSeed in nkeys.c) which
// rejects public key prefixes, so we implement public key decoding ourselves.
// Based on the Go reference implementation:
// https://github.com/nats-io/nkeys/blob/0f430772b63004155287d5f3c061d41995f74b15/strkey.go#L131
std::optional<std::vector<uint8_t>> NKeyDecode(const std::string &nkey) {
  EnsureBase32Initialized();

  char raw[64];
  int rawLen = 0;
  if (nats_Base32_DecodeString(nkey.c_str(), raw, sizeof(raw), &rawLen) != NATS_OK ||
      rawLen != 35) {
    return std::nullopt;
  }

  auto *data = reinterpret_cast<unsigned char *>(raw);

  // CRC16 over first 33 bytes, stored little-endian in last 2
  uint16_t expected = static_cast<uint16_t>(data[33]) | (static_cast<uint16_t>(data[34]) << 8);
  if (!nats_CRC16_Validate(data, 33, expected)) {
    return std::nullopt;
  }

  // bytes 1..32 are the Ed25519 public key (byte 0 is the prefix type byte)
  return std::vector<uint8_t>(data + 1, data + 33);
}

bool SplitJWT(std::string_view jwt, JWTParts &parts) {
  auto p1 = jwt.find('.');
  if (p1 == std::string_view::npos) return false;
  auto p2 = jwt.find('.', p1 + 1);
  if (p2 == std::string_view::npos) return false;
  // Ensure no additional dots
  if (jwt.find('.', p2 + 1) != std::string_view::npos) return false;

  parts.header = jwt.substr(0, p1);
  parts.payload = jwt.substr(p1 + 1, p2 - p1 - 1);
  parts.signature = jwt.substr(p2 + 1);
  return true;
}

bool VerifyJWTSignature(std::string_view jwt, const std::vector<uint8_t> &ed25519Pubkey) {
  if (ed25519Pubkey.size() != 32) {
    return false;
  }

  JWTParts parts;
  if (!SplitJWT(jwt, parts)) {
    return false;
  }

  auto sig = Base64URLDecode(parts.signature);
  if (sig.size() != 64) {
    return false;
  }

  // Reconstruct "header.payload" for signature verification
  std::string signed_data;
  signed_data.reserve(parts.header.size() + 1 + parts.payload.size());
  signed_data.append(parts.header);
  signed_data.push_back('.');
  signed_data.append(parts.payload);
  return ED25519_verify(reinterpret_cast<const uint8_t *>(signed_data.data()), signed_data.size(),
                        sig.data(), ed25519Pubkey.data()) == 1;
}

NSDictionary *ParseJWTPayload(std::string_view jwt) {
  JWTParts parts;
  if (!SplitJWT(jwt, parts)) {
    return nil;
  }

  auto payload_bytes = Base64URLDecode(parts.payload);
  if (payload_bytes.empty()) {
    return nil;
  }

  NSData *jsonData = [NSData dataWithBytesNoCopy:payload_bytes.data()
                                          length:payload_bytes.size()
                                    freeWhenDone:NO];
  NSError *jsonError;
  NSDictionary *payload = [NSJSONSerialization JSONObjectWithData:jsonData
                                                          options:0
                                                            error:&jsonError];
  if (jsonError || ![payload isKindOfClass:[NSDictionary class]]) {
    return nil;
  }

  return payload;
}

}  // namespace

bool NKeyTokenValidator::Validate() {
  if (!accountJWT_.length || !userJWT_.length) {
    return false;
  }

  std::string accountJWTStr = santa::NSStringToUTF8String(accountJWT_);

  // 1. Parse account JWT payload -> extract iss and sub
  NSDictionary *accountPayload = ParseJWTPayload(accountJWTStr);
  if (!accountPayload) {
    LOGW(@"NKeyTokenValidator: failed to parse account JWT payload");
    return false;
  }

  NSString *accountIssuer = accountPayload[@"iss"];
  if (![accountIssuer isKindOfClass:[NSString class]] || !accountIssuer.length) {
    LOGW(@"NKeyTokenValidator: missing or invalid account 'iss' claim");
    return false;
  }

  NSString *accountSubject = accountPayload[@"sub"];
  if (![accountSubject isKindOfClass:[NSString class]] || !accountSubject.length) {
    LOGW(@"NKeyTokenValidator: missing or invalid account 'sub' claim");
    return false;
  }

  // 2. Verify account iss is in trusted keys
  std::string accountIssuerStr = santa::NSStringToUTF8String(accountIssuer);
  if (!trustedNKeys_.count(accountIssuerStr)) {
    LOGW(@"NKeyTokenValidator: account issuer '%@' not in trusted keys", accountIssuer);
    return false;
  }

  // 3. NKeyDecode(iss) -> operator pubkey
  auto operatorPubkey = NKeyDecode(accountIssuerStr);
  if (!operatorPubkey.has_value() || operatorPubkey->size() != 32) {
    LOGW(@"NKeyTokenValidator: failed to decode operator NKey");
    return false;
  }

  // 4. Verify account JWT signature against operator pubkey
  if (!VerifyJWTSignature(accountJWTStr, operatorPubkey.value())) {
    LOGW(@"NKeyTokenValidator: account JWT signature verification failed");
    return false;
  }

  // 5. Check account JWT expiration
  NSNumber *accountExp = accountPayload[@"exp"];
  if ([accountExp isKindOfClass:[NSNumber class]]) {
    int64_t exp = [accountExp longLongValue];
    int64_t now = static_cast<int64_t>(std::time(nullptr));
    if (exp > 0 && now > exp) {
      LOGW(@"NKeyTokenValidator: account JWT expired (exp=%lld, now=%lld)", exp, now);
      return false;
    }
  }

  // 6. NKeyDecode(sub) -> account pubkey (32 bytes)
  std::string accountSubjectStr = santa::NSStringToUTF8String(accountSubject);
  auto accountPubkey = NKeyDecode(accountSubjectStr);
  if (!accountPubkey.has_value() || accountPubkey->size() != 32) {
    LOGW(@"NKeyTokenValidator: failed to decode account subject NKey");
    return false;
  }

  // 7. Parse user JWT payload -> extract iss
  std::string userJWTStr = santa::NSStringToUTF8String(userJWT_);
  NSDictionary *userPayload = ParseJWTPayload(userJWTStr);
  if (!userPayload) {
    LOGW(@"NKeyTokenValidator: failed to parse user JWT payload");
    return false;
  }

  NSString *userIssuer = userPayload[@"iss"];
  if (![userIssuer isKindOfClass:[NSString class]] || !userIssuer.length) {
    LOGW(@"NKeyTokenValidator: missing or invalid user 'iss' claim");
    return false;
  }

  // 8. Verify user iss == account sub
  if (![userIssuer isEqualToString:accountSubject]) {
    LOGW(@"NKeyTokenValidator: user issuer '%@' does not match account subject '%@'", userIssuer,
         accountSubject);
    return false;
  }

  // 9. Verify user JWT signature against account pubkey
  if (!VerifyJWTSignature(userJWTStr, *accountPubkey)) {
    LOGW(@"NKeyTokenValidator: user JWT signature verification failed");
    return false;
  }

  // 10. Check user JWT expiration
  NSNumber *userExp = userPayload[@"exp"];
  if ([userExp isKindOfClass:[NSNumber class]]) {
    int64_t exp = [userExp longLongValue];
    int64_t now = static_cast<int64_t>(std::time(nullptr));
    if (exp > 0 && now > exp) {
      LOGW(@"NKeyTokenValidator: user JWT expired (exp=%lld, now=%lld)", exp, now);
      return false;
    }
  }

  // 11. Full chain validated
  return true;
}

}  // namespace santa
