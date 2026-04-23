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

#ifdef __cplusplus
extern "C" {
#endif

#include "src/nats.h"

#ifdef __cplusplus
}
#endif

NS_ASSUME_NONNULL_BEGIN

/// Parsed components of a proxy URL.
@interface SNTProxyConfig : NSObject
@property(nonatomic, copy) NSString *host;
@property(nonatomic) int port;
@property(nonatomic) BOOL useTLS;
/// Base64-encoded "user:pass" for Proxy-Authorization header. Nil if no credentials.
@property(nullable, nonatomic, copy) NSString *basicAuth;
/// PEM-encoded custom CA certificate data. Nil if using system trust store.
@property(nullable, nonatomic, copy) NSData *customCAData;
@end

NS_ASSUME_NONNULL_END

/// Parse a proxy URL string into its components.
/// Accepted formats: http://host:port, https://host:port,
/// http://user:pass@host:port, https://user:pass@host:port.
/// Returns nil if the URL is malformed or has an unsupported scheme.
SNTProxyConfig *_Nullable SNTParseProxyURL(NSString *_Nonnull proxyURL);

/// Parse an HTTP response status line (e.g. "HTTP/1.1 200 Connection established").
/// Returns the status code, or -1 if the line is malformed.
/// Accepts both HTTP/1.0 and HTTP/1.1.
int SNTParseHTTPStatusLine(NSString *_Nonnull statusLine);

/// Closure structure passed to the NATS proxy connection handler callback.
/// Heap-allocated; caller is responsible for freeing with SNTProxyClosureDestroy().
typedef struct {
  char *_Nonnull proxyHost;
  int proxyPort;
  bool proxyUseTLS;
  char *_Nullable basicAuth;      // Base64-encoded "user:pass", or NULL
  char *_Nullable customCAPEM;    // PEM CA data as C string, or NULL
} SNTProxyClosure;

/// Create a closure struct from an SNTProxyConfig. Caller must free with SNTProxyClosureDestroy().
SNTProxyClosure *_Nullable SNTProxyClosureCreate(SNTProxyConfig *_Nonnull config);

/// Free a closure struct and all its owned strings.
void SNTProxyClosureDestroy(SNTProxyClosure *_Nullable closure);

/// NATS proxy connection handler callback. Register with natsOptions_SetProxyConnHandler().
/// The closure parameter must be a SNTProxyClosure*.
///
/// For http:// proxies: returns the raw tunnel socket directly.
/// For https:// proxies: performs TLS to the proxy, creates a socketpair, and
/// spawns a detached bridge thread that shuttles bytes between the socketpair
/// and the SSL connection. Returns one end of the socketpair to NATS.
natsStatus SNTNATSProxyConnHandler(natsSock *_Nonnull fd, char *_Nonnull host, int port,
                                    void *_Nullable closure);
