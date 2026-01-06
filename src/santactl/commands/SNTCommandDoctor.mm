/// Copyright 2025 North Pole Security, Inc.
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

#import <Foundation/Foundation.h>

#include <libproc.h>
#include <unistd.h>

#include <optional>
#include <vector>

#include "absl/cleanup/cleanup.h"

#import "src/common/MOLAuthenticatingURLSession.h"
#import "src/common/SNTConfigurator.h"
#import "src/common/SNTLogging.h"
#import "src/common/SystemResources.h"
#import "src/santactl/SNTCommand.h"
#import "src/santactl/SNTCommandController.h"

@interface SNTCommandDoctor : SNTCommand <SNTCommandProtocol>
@end

void print(NSString *format, ...) {
  va_list args;
  va_start(args, format);

  if (isatty(STDOUT_FILENO)) {
    if ([format hasPrefix:@"[-]"]) {
      format = [NSString stringWithFormat:@"\033[31m%@\033[0m\n", format];
    } else if ([format hasPrefix:@"[+]"]) {
      format = [NSString stringWithFormat:@"\033[32m%@\033[0m\n", format];
    } else {
      format = [NSString stringWithFormat:@"%@\n", format];
    }
  }
  vfprintf(stdout, format.UTF8String, args);
  va_end(args);
}

@implementation SNTCommandDoctor

REGISTER_COMMAND_NAME(@"doctor")

+ (BOOL)requiresRoot {
  // This command requires root in order to retrieve all the data it needs.
  return YES;
}

+ (BOOL)requiresDaemonConn {
  return NO;
}

+ (NSString *)shortHelpText {
  return @"Check your system for potential problems.";
}

+ (NSString *)longHelpText {
  return @"Doctor checks your system for potential problems and prints out details of any problems "
         @"that it finds.\n"
         @"\n"
         @"Will exit with a non-zero exit code if any problems are found.\n"
         @"\n"
         @"Note that this is intended to help debug support personnel issues which Santa is unable "
         @"to resolve itself.";
}

- (void)runWithArguments:(NSArray *)arguments {
  BOOL err = NO;
  err |= [self validateProcesses];
  err |= [self validateConfiguration];
  err |= [self validateSync];
  exit(err);
}

- (BOOL)validateProcesses {
  print(@"=> Validating processes...");

  BOOL foundSanta = NO, foundSantad = NO, foundSantaSyncService = NO;

  std::optional<std::vector<pid_t>> pidList = GetPidList();
  if (!pidList.has_value()) {
    print(@"[-] Failed to retrieve processes");
    return YES;
  }

  for (pid_t pid : pidList.value()) {
    // Copies the contents of info.pbi_name or info.pbi_comm into buffer.
    // Since pbi_comm is limited to first 15 chars, pbi_name is preferred.
    char name[2 * MAXCOMLEN];
    proc_name(pid, name, sizeof(name));

    NSString *nsName = @(name);
    if ([nsName isEqualToString:@"Santa"]) foundSanta = YES;
    if ([nsName isEqualToString:@"com.northpolesec.santa.daemon"]) foundSantad = YES;
    if ([nsName isEqualToString:@"santasyncservice"]) foundSantaSyncService = YES;
  }

  if (!foundSanta) {
    print(@"[-] Santa GUI process doesn't seem to be running");
  }
  if (!foundSantad) {
    print(@"[-] Santa system extension doesn't seem to be running");
  }
  if ([SNTConfigurator configurator].syncBaseURL.absoluteString.length && !foundSantaSyncService) {
    print(@"[-] Santa sync service doesn't seem to be running");
  }
  if (foundSanta && foundSantad && foundSantaSyncService) {
    print(@"[+] No issues detected");
  }

  print(@"");

  return (!foundSanta || !foundSantad || !foundSantaSyncService);
}

- (BOOL)validateConfiguration {
  print(@"=> Validating configuration...");
  NSArray *errors = [[SNTConfigurator configurator] validateConfiguration];
  if (!errors.count) {
    print(@"[+] No configuration errors detected");
    print(@"");
    return NO;
  }

  for (NSString *e in errors) {
    print(@"[-] %s", [e UTF8String]);
  }

  print(@"");
  return YES;
}

- (BOOL)validateSync {
  print(@"=> Validating sync...");

  SNTConfigurator *config = [SNTConfigurator configurator];

  NSURL *syncBaseURL = config.syncBaseURL;
  if (!syncBaseURL) {
    print(@"[+] Sync is disabled");
    print(@"");
    // Don't treat this as an error.
    return YES;
  }
  print(@"[+] Sync is enabled");

  if (![syncBaseURL.scheme isEqualToString:@"https"]) {
    print(@"[-] Sync is not using HTTPS");
  } else {
    print(@"[+] Sync is using HTTPS");
  }

  NSURLSessionConfiguration *sessConfig = [NSURLSessionConfiguration defaultSessionConfiguration];
  sessConfig.connectionProxyDictionary = [[SNTConfigurator configurator] syncProxyConfig];

  MOLAuthenticatingURLSession *authURLSession =
      [[MOLAuthenticatingURLSession alloc] initWithSessionConfiguration:sessConfig];
  authURLSession.userAgent = @"santactl-sync/";
  NSString *santactlVersion = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleVersion"];
  if (santactlVersion) {
    authURLSession.userAgent = [authURLSession.userAgent stringByAppendingString:santactlVersion];
  }
  authURLSession.refusesRedirects = YES;
  authURLSession.serverHostname = syncBaseURL.host;
  authURLSession.loggingBlock = ^(NSString *line) {
    print(@"%s", [line UTF8String]);
  };

  // Configure server auth
  if ([config syncServerAuthRootsFile]) {
    authURLSession.serverRootsPemFile = [config syncServerAuthRootsFile];
  } else if ([config syncServerAuthRootsData]) {
    authURLSession.serverRootsPemData = [config syncServerAuthRootsData];
  }

  // Configure client auth
  if ([config syncClientAuthCertificateFile]) {
    NSString *certFile = [config syncClientAuthCertificateFile];
    authURLSession.clientCertFile = certFile;
    authURLSession.clientCertPassword = [config syncClientAuthCertificatePassword];
  } else if ([config syncClientAuthCertificateCn]) {
    authURLSession.clientCertCommonName = [config syncClientAuthCertificateCn];
  } else if ([config syncClientAuthCertificateIssuer]) {
    authURLSession.clientCertIssuerCn = [config syncClientAuthCertificateIssuer];
  }

  dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
  // Disable user-interaction for Keychain APIs in this process.
  // If the settings on the identity's private key are not set to provide access to this process
  // the user will be prompted for their password, which we don't want because santasyncservice
  // would *not* do this and would instead fail the attempt.
  SecKeychainSetUserInteractionAllowed(false);
#pragma clang diagnostic pop

  NSMutableURLRequest *req = [[NSMutableURLRequest alloc]
      initWithURL:[syncBaseURL URLByAppendingPathComponent:@"preflight/santactl-doctor-test"]];
  req.HTTPMethod = @"POST";
  NSURLSessionDataTask *task = [[authURLSession session]
      dataTaskWithRequest:req
        completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
          absl::Cleanup cleanup = ^{
            dispatch_semaphore_signal(semaphore);
          };

          if (error) {
            print(@"[-] Failed to retrieve preflight data");
            return;
          }

          NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse *)response;
          switch (httpResponse.statusCode) {
            case 301: {
              NSString *location = [httpResponse valueForHTTPHeaderField:@"Location"];
              print(@"[?] HTTP 301, new location: %s", location.UTF8String);
              break;
            }
            case 200:
            case 400:  // Treat a 400 as OK: we didn't populate any data or set an appropriate
                       // Content-Type.
              print(@"[+] Preflight request succeeded");
              break;
            default: print(@"[-] HTTP response code: %d", httpResponse.statusCode);
          }
        }];
  [task resume];
  dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);

  print(@"");

  return NO;
}

@end
