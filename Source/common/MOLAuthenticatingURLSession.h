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

/**
  A wrapper around `NSURLSession` providing validation of server certificates and easy-to-use
  client certificate authentication.
*/
@interface MOLAuthenticatingURLSession : NSObject <NSURLSessionDelegate, NSURLSessionDataDelegate>

/**
  Returns a new NSURLSession configured with the correct delegate and session configuration.

  You can either retrieve this instance and re-use it or keep calling session to get a new session
  every time. The properties below, with the exception of userAgent, will be updated even in
  already-created session objects.
*/
@property(readonly) NSURLSession *session;

/**
  If set, this is the user-agent to send with requests, otherwise remains the default
  CFNetwork-based name.

  This property does not update existing session objects retrieved with the session property.
*/
@property(copy, nonatomic) NSString *userAgent;

/**  If set to YES, this session refuses redirect requests. Defaults to NO. */
@property(nonatomic) BOOL refusesRedirects;

/**
  If set, the server that we connect to _must_ match this string. Redirects to other
  hosts will not be allowed.
*/
@property(copy, nonatomic) NSString *serverHostname;

/**  If set and client certificate authentication is needed, the pkcs#12 file will be loaded */
@property(copy, nonatomic) NSString *clientCertFile;

/**
  If set and client certificate authentication is needed, the password being used for
  loading the clientCertFile
*/
@property(copy, nonatomic) NSString *clientCertPassword;

/**
  If set and client certificate authentication is needed, will search the keychain for a
  certificate matching this common name and use that for authentication.

  @note Not case sensitive
  @note If multiple matching certificates are found, the first one is used.
  @note If this property is not set and neither is |clientCertIssuerCn|, the allowed issuers
  provided by the server will be used to find a matching certificate.
*/
@property(copy, nonatomic) NSString *clientCertCommonName;

/**
  If set and client certificate authentication is needed, will search the keychain for a
  certificate issued by an issuer with this name and use that for authentication.

  @note Not case sensitive
  @note If multiple matching certificates are found, the first one is used.
  @note If this property is not set and neither is |clientCertCommonName|, the allowed issuers
        provided by the server will be used to find a matching certificate.
*/
@property(copy, nonatomic) NSString *clientCertIssuerCn;

/**
  If set, this block will be called with a string argument during authentication and when
  certain authentication issues occur.
*/
@property(copy) void (^loggingBlock)(NSString *);

/**
  If set, this block will be called when the URLSession:task:didCompleteWithError: delegate
  method is called.
*/
@property(copy) void (^taskDidCompleteWithErrorBlock)(NSURLSession *, NSURLSessionTask *, NSError *)
    ;

/**
  If set, this block will be called when the URLSession:dataTask:didReceiveData: delegate
  method is called.
*/
@property(copy) void (^dataTaskDidReceiveDataBlock)
    (NSURLSession *, NSURLSessionDataTask *, NSData *);

/**
  If set, this block will be called when a redirect is attempted. This overrides the
  refusesRedirects property as you are taking responsibility for handling redirects.

  param: task, The task this redirect is related to.
  param: request, The new request, pre-filled.
  param: response, The response from the server to the request that caused the redirect.
  returns: request, A valid request to make or nil to refuse the redirect. Returning the request
      passed as the third parameter is valid.
*/
@property(copy) NSURLRequest * (^redirectHandlerBlock)
    (NSURLSessionTask *, NSHTTPURLResponse *, NSURLRequest *);

/**
  This method should be called with PEM data containing one or more certificates to use to verify
  the server's certificate chain. This will override the trusted system roots. If there are no
  usable certificates within the data, the trusted system roots will be used.
*/
- (void)setServerRootsPemData:(NSData *)serverRootsPemData;

/**
  This method should be called with the path to a PEM file containing one or more certificates to
  use to verify the server's certificate chain. This will override the trusted system roots. If
  there are no usable certificates within the file, the trusted system roots will be used.
*/
- (void)setServerRootsPemFile:(NSString *)serverRootsPemFile;

/**  Designated initializer */
- (instancetype)initWithSessionConfiguration:(NSURLSessionConfiguration *)configuration;

@end
