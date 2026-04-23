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

#import "Source/santasyncservice/SNTNATSProxyConnect.h"

#import "Source/common/SNTLogging.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

@implementation SNTProxyConfig
@end

SNTProxyConfig *_Nullable SNTParseProxyURL(NSString *proxyURL) {
  if (!proxyURL.length) return nil;

  NSURL *url = [NSURL URLWithString:proxyURL];
  if (!url || !url.host || !url.port) return nil;

  NSString *scheme = url.scheme.lowercaseString;
  if (![scheme isEqualToString:@"http"] && ![scheme isEqualToString:@"https"]) return nil;

  SNTProxyConfig *config = [[SNTProxyConfig alloc] init];
  config.host = url.host;
  config.port = url.port.intValue;
  config.useTLS = [scheme isEqualToString:@"https"];

  if (url.user && url.password) {
    NSString *user = url.user.stringByRemovingPercentEncoding;
    NSString *password = url.password.stringByRemovingPercentEncoding;
    NSString *credentials = [NSString stringWithFormat:@"%@:%@", user, password];
    NSData *credData = [credentials dataUsingEncoding:NSUTF8StringEncoding];
    config.basicAuth = [credData base64EncodedStringWithOptions:0];
  }

  return config;
}

int SNTParseHTTPStatusLine(NSString *statusLine) {
  if (!statusLine.length) return -1;

  NSArray<NSString *> *parts = [statusLine componentsSeparatedByString:@" "];
  if (parts.count < 2) return -1;

  NSString *version = parts[0];
  if (![version hasPrefix:@"HTTP/"]) return -1;

  NSInteger code = parts[1].integerValue;
  if (code < 100 || code > 599) return -1;

  return (int)code;
}

SNTProxyClosure *_Nullable SNTProxyClosureCreate(SNTProxyConfig *config) {
  if (!config) return NULL;

  SNTProxyClosure *closure = (SNTProxyClosure *)calloc(1, sizeof(SNTProxyClosure));
  if (!closure) return NULL;

  closure->proxyHost = strdup(config.host.UTF8String);
  closure->proxyPort = config.port;
  closure->proxyUseTLS = config.useTLS;

  if (config.basicAuth) {
    closure->basicAuth = strdup(config.basicAuth.UTF8String);
  }

  if (config.customCAData) {
    NSString *pemStr = [[NSString alloc] initWithData:config.customCAData
                                             encoding:NSUTF8StringEncoding];
    if (pemStr) {
      closure->customCAPEM = strdup(pemStr.UTF8String);
    }
  }

  return closure;
}

void SNTProxyClosureDestroy(SNTProxyClosure *closure) {
  if (!closure) return;
  free(closure->proxyHost);
  free(closure->basicAuth);
  free(closure->customCAPEM);
  free(closure);
}

#pragma mark - I/O Helpers

static ssize_t ProxyRead(int fd, SSL *ssl, void *buf, size_t len) {
  return ssl ? SSL_read(ssl, buf, (int)len) : read(fd, buf, len);
}

static ssize_t ProxyWrite(int fd, SSL *ssl, const void *buf, size_t len) {
  return ssl ? SSL_write(ssl, buf, (int)len) : write(fd, buf, len);
}

static NSString *ReadLineFromProxy(int fd, SSL *ssl, int timeoutSecs) {
  NSMutableData *lineData = [NSMutableData data];
  char c;
  struct timeval tv = {.tv_sec = timeoutSecs, .tv_usec = 0};
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  while (lineData.length < 8192) {
    ssize_t n = ProxyRead(fd, ssl, &c, 1);
    if (n <= 0) return nil;
    if (c == '\n') {
      NSString *line = [[NSString alloc] initWithData:lineData encoding:NSUTF8StringEncoding];
      if ([line hasSuffix:@"\r"]) line = [line substringToIndex:line.length - 1];
      return line;
    }
    [lineData appendBytes:&c length:1];
  }
  return nil;
}

static bool SendAllToProxy(int fd, SSL *ssl, const void *data, size_t len) {
  const char *p = (const char *)data;
  size_t remaining = len;
  while (remaining > 0) {
    ssize_t n = ProxyWrite(fd, ssl, p, remaining);
    if (n <= 0) return false;
    p += n;
    remaining -= (size_t)n;
  }
  return true;
}

#pragma mark - SSL Bridge for HTTPS Proxies

typedef struct {
  int localFd;
  int proxySock;
  SSL *ssl;
  SSL_CTX *sslCtx;
} SSLBridgeCtx;

static void *SSLBridgeThread(void *arg) {
  SSLBridgeCtx *ctx = (SSLBridgeCtx *)arg;
  char buf[16384];
  fd_set readfds;

  while (true) {
    FD_ZERO(&readfds);
    FD_SET(ctx->localFd, &readfds);
    FD_SET(ctx->proxySock, &readfds);
    int maxfd = (ctx->localFd > ctx->proxySock ? ctx->localFd : ctx->proxySock) + 1;

    if (SSL_pending(ctx->ssl) > 0) {
      int n = SSL_read(ctx->ssl, buf, sizeof(buf));
      if (n <= 0) break;
      if (write(ctx->localFd, buf, n) <= 0) break;
      continue;
    }

    struct timeval tv = {.tv_sec = 300, .tv_usec = 0};
    int ready = select(maxfd, &readfds, NULL, NULL, &tv);
    if (ready <= 0) break;

    if (FD_ISSET(ctx->localFd, &readfds)) {
      ssize_t n = read(ctx->localFd, buf, sizeof(buf));
      if (n <= 0) break;
      if (SSL_write(ctx->ssl, buf, (int)n) <= 0) break;
    }

    if (FD_ISSET(ctx->proxySock, &readfds)) {
      int n = SSL_read(ctx->ssl, buf, sizeof(buf));
      if (n <= 0) break;
      if (write(ctx->localFd, buf, n) <= 0) break;
    }
  }

  SSL_shutdown(ctx->ssl);
  SSL_free(ctx->ssl);
  SSL_CTX_free(ctx->sslCtx);
  close(ctx->localFd);
  close(ctx->proxySock);
  free(ctx);
  return NULL;
}

#pragma mark - HTTP CONNECT Handler

static SSL_CTX *CreateProxySSLContext(const char *customCAPEM) {
  SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
  if (!ctx) return NULL;

  if (customCAPEM) {
    BIO *bio = BIO_new_mem_buf(customCAPEM, -1);
    if (bio) {
      X509_STORE *store = SSL_CTX_get_cert_store(ctx);
      X509 *cert;
      while ((cert = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
        X509_STORE_add_cert(store, cert);
        X509_free(cert);
      }
      BIO_free(bio);
    }
  } else {
    SSL_CTX_set_default_verify_paths(ctx);
  }

  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
  return ctx;
}

natsStatus SNTNATSProxyConnHandler(natsSock *fd, char *host, int port, void *closure) {
  SNTProxyClosure *proxy = (SNTProxyClosure *)closure;
  if (!proxy) return NATS_ERR;

  struct addrinfo hints = {};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  char portStr[16];
  snprintf(portStr, sizeof(portStr), "%d", proxy->proxyPort);

  struct addrinfo *res = NULL;
  int gaiErr = getaddrinfo(proxy->proxyHost, portStr, &hints, &res);
  if (gaiErr != 0 || !res) {
    LOGE(@"NATS proxy: Failed to resolve %s:%d: %s", proxy->proxyHost, proxy->proxyPort,
         gai_strerror(gaiErr));
    return NATS_ERR;
  }

  int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if (sock < 0) {
    LOGE(@"NATS proxy: Failed to create socket: %s", strerror(errno));
    freeaddrinfo(res);
    return NATS_ERR;
  }

  struct timeval tv = {.tv_sec = 30, .tv_usec = 0};
  setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

  if (connect(sock, res->ai_addr, res->ai_addrlen) != 0) {
    LOGE(@"NATS proxy: Failed to connect to %s:%d: %s", proxy->proxyHost, proxy->proxyPort,
         strerror(errno));
    close(sock);
    freeaddrinfo(res);
    return NATS_ERR;
  }
  freeaddrinfo(res);

  SSL_CTX *sslCtx = NULL;
  SSL *ssl = NULL;

  if (proxy->proxyUseTLS) {
    sslCtx = CreateProxySSLContext(proxy->customCAPEM);
    if (!sslCtx) {
      LOGE(@"NATS proxy: Failed to create SSL context for proxy TLS");
      close(sock);
      return NATS_ERR;
    }

    ssl = SSL_new(sslCtx);
    if (!ssl) {
      LOGE(@"NATS proxy: Failed to create SSL object");
      SSL_CTX_free(sslCtx);
      close(sock);
      return NATS_ERR;
    }

    SSL_set_fd(ssl, sock);
    SSL_set_tlsext_host_name(ssl, proxy->proxyHost);

    if (SSL_connect(ssl) != 1) {
      uint32_t sslErr = (uint32_t)ERR_get_error();
      char errBuf[256];
      ERR_error_string_n(sslErr, errBuf, sizeof(errBuf));
      LOGE(@"NATS proxy: TLS handshake with proxy %s:%d failed: %s", proxy->proxyHost,
           proxy->proxyPort, errBuf);
      SSL_free(ssl);
      SSL_CTX_free(sslCtx);
      close(sock);
      return NATS_ERR;
    }
    LOGD(@"NATS proxy: TLS established with proxy %s:%d", proxy->proxyHost, proxy->proxyPort);
  }

  NSMutableString *request = [NSMutableString stringWithFormat:@"CONNECT %s:%d HTTP/1.1\r\n"
                                                               @"Host: %s:%d\r\n",
                                                               host, port, host, port];
  if (proxy->basicAuth) {
    [request appendFormat:@"Proxy-Authorization: Basic %s\r\n", proxy->basicAuth];
  }
  [request appendString:@"\r\n"];

  const char *reqBytes = request.UTF8String;
  if (!SendAllToProxy(sock, ssl, reqBytes, strlen(reqBytes))) {
    LOGE(@"NATS proxy: Failed to send CONNECT request to %s:%d", proxy->proxyHost,
         proxy->proxyPort);
    if (ssl) { SSL_free(ssl); SSL_CTX_free(sslCtx); }
    close(sock);
    return NATS_ERR;
  }

  NSString *statusLine = ReadLineFromProxy(sock, ssl, 30);
  if (!statusLine) {
    LOGE(@"NATS proxy: No response from proxy %s:%d", proxy->proxyHost, proxy->proxyPort);
    if (ssl) { SSL_free(ssl); SSL_CTX_free(sslCtx); }
    close(sock);
    return NATS_ERR;
  }

  int statusCode = SNTParseHTTPStatusLine(statusLine);

  NSString *headerLine;
  while ((headerLine = ReadLineFromProxy(sock, ssl, 30)) != nil) {
    if (headerLine.length == 0) break;
  }

  if (statusCode < 200 || statusCode > 299) {
    if (statusCode == 407) {
      LOGE(@"NATS proxy: Authentication required by proxy %s:%d -- check PushProxyURL credentials",
           proxy->proxyHost, proxy->proxyPort);
    } else {
      LOGE(@"NATS proxy: CONNECT failed with status %d from %s:%d: %@", statusCode,
           proxy->proxyHost, proxy->proxyPort, statusLine);
    }
    if (ssl) { SSL_free(ssl); SSL_CTX_free(sslCtx); }
    close(sock);
    return NATS_ERR;
  }

  LOGI(@"NATS proxy: CONNECT tunnel established through %s:%d to %s:%d", proxy->proxyHost,
       proxy->proxyPort, host, port);

  if (!ssl) {
    *fd = (natsSock)sock;
    return NATS_OK;
  }

  int pair[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) {
    LOGE(@"NATS proxy: socketpair failed: %s", strerror(errno));
    SSL_free(ssl);
    SSL_CTX_free(sslCtx);
    close(sock);
    return NATS_ERR;
  }

  SSLBridgeCtx *bridgeCtx = (SSLBridgeCtx *)calloc(1, sizeof(SSLBridgeCtx));
  bridgeCtx->localFd = pair[1];
  bridgeCtx->proxySock = sock;
  bridgeCtx->ssl = ssl;
  bridgeCtx->sslCtx = sslCtx;

  pthread_t thread;
  if (pthread_create(&thread, NULL, SSLBridgeThread, bridgeCtx) != 0) {
    LOGE(@"NATS proxy: Failed to create bridge thread: %s", strerror(errno));
    free(bridgeCtx);
    SSL_free(ssl);
    SSL_CTX_free(sslCtx);
    close(sock);
    close(pair[0]);
    close(pair[1]);
    return NATS_ERR;
  }
  pthread_detach(thread);

  *fd = (natsSock)pair[0];
  return NATS_OK;
}
