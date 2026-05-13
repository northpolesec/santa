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

#include <errno.h>
#include <fcntl.h>
#include <sandbox.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <memory>
#include <vector>

#import "Source/common/MOLCodesignChecker.h"
#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTFileInfo.h"
#import "Source/common/SNTRuleIdentifiers.h"
#import "Source/common/SNTSandboxExecRequest.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/common/SigningIDHelpers.h"
#import "Source/santactl/SNTCommand.h"
#import "Source/santactl/SNTCommandController.h"

@interface SNTCommandSandbox : SNTCommand <SNTCommandProtocol>
@end

@implementation SNTCommandSandbox

REGISTER_COMMAND_NAME(@"sandbox")

+ (BOOL)requiresRoot {
  return NO;
}

+ (BOOL)requiresDaemonConn {
  return YES;
}

+ (NSString*)shortHelpText {
  return @"Run a command under a seatbelt sandbox profile.";
}

+ (NSString*)longHelpText {
  return (
#ifdef DEBUG
      @"Usage: santactl sandbox [--print-profile] <command> [arguments...]\n"
#else
      @"Usage: santactl sandbox <command> [arguments...]\n"
#endif
      @"\n"
      @"  Looks up the seatbelt policy for the given command from Santa's rule\n"
      @"  database. If a rule with a seatbelt policy exists, applies the sandbox\n"
      @"  profile via sandbox_init and then executes the command. If no matching\n"
      @"  rule is found or the matched rule has no seatbelt policy, santactl\n"
      @"  refuses to run the command and exits with a non-zero status.\n"
#ifdef DEBUG
      @"\n"
      @"  Options:\n"
      @"    --print-profile: Print the sandbox profile to stderr before applying it.\n"
#endif
  );
}

+ (NSSet<NSString*>*)aliases {
  return [NSSet setWithArray:@[ @"sb" ]];
}

/// Resolve a command name to its full path by searching PATH.
/// Returns nil if the command cannot be found.
- (NSString*)resolveCommand:(NSString*)command {
  if (command.length == 0) return nil;

  BOOL (^isExecutableFile)(NSString*) = ^BOOL(NSString* path) {
    const char* cPath = path.fileSystemRepresentation;
    struct stat sb;
    return stat(cPath, &sb) == 0 && S_ISREG(sb.st_mode) && access(cPath, X_OK) == 0;
  };

  // If the command contains a slash, treat it as a path.
  if ([command containsString:@"/"]) {
    return isExecutableFile(command) ? command : nil;
  }

  const char* pathEnv = getenv("PATH");
  if (!pathEnv) return nil;

  for (NSString* dir in [@(pathEnv) componentsSeparatedByString:@":"]) {
    // Skip empty or non-absolute PATH entries to avoid resolving relative to cwd.
    if (dir.length == 0 || ![dir hasPrefix:@"/"]) continue;

    NSString* fullPath = [dir stringByAppendingPathComponent:command];
    if (isExecutableFile(fullPath)) return fullPath;
  }
  return nil;
}

- (void)runWithArguments:(NSArray*)arguments {
#ifdef DEBUG
  BOOL printProfile = NO;
#endif
  NSUInteger idx = 0;
  while (idx < arguments.count) {
    NSString* arg = arguments[idx];
#ifdef DEBUG
    if ([arg isEqualToString:@"--print-profile"]) {
      printProfile = YES;
      idx++;
      continue;
    }
#endif
    // `--` consumes itself; any other arg is the command name and is left in place.
    if ([arg isEqualToString:@"--"]) idx++;
    break;
  }
  if (idx >= arguments.count) {
    [self printErrorUsageAndExit:@"No command specified."];
  }

  NSArray* commandArgs = [arguments subarrayWithRange:NSMakeRange(idx, arguments.count - idx)];
  NSString* command = commandArgs[0];

  NSString* resolvedPath = [self resolveCommand:command];
  if (!resolvedPath) {
    fprintf(stderr, "Error: command not found: %s\n", command.UTF8String);
    exit(EXIT_FAILURE);
  }

  // O_RDONLY | O_CLOEXEC pins the file for the duration of this flow:
  //   * the kernel will not reuse inode number st_ino on this volume while
  //     the fd is open, so the (fsDev, fsIno) we register with santad
  //     unambiguously identifies the vnode we hashed;
  //   * cdhash and sha256 are computed off /dev/fd/N so they reflect the
  //     pinned file's content, not whatever the path resolves to later;
  //   * the fd closes automatically at execve, so the pin lasts exactly
  //     as long as needed.
  // santad's AUTH_EXEC handler verifies the expectation against the
  // kernel-reported vnode and cdhash at exec time.
  int fd = open(resolvedPath.fileSystemRepresentation, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    fprintf(stderr, "Error: unable to open %s: %s\n", resolvedPath.UTF8String, strerror(errno));
    exit(EXIT_FAILURE);
  }
  struct stat sb;
  if (fstat(fd, &sb) != 0 || !S_ISREG(sb.st_mode)) {
    fprintf(stderr, "Error: %s is not a regular file\n", resolvedPath.UTF8String);
    exit(EXIT_FAILURE);
  }
  NSString* fdPath = [NSString stringWithFormat:@"/dev/fd/%d", fd];

  NSError* fileInfoError;
  SNTFileInfo* fileInfo = [[SNTFileInfo alloc] initWithResolvedPath:fdPath error:&fileInfoError];
  if (!fileInfo) {
    fprintf(stderr, "Error: unable to read binary at %s: %s\n", resolvedPath.UTF8String,
            fileInfoError.localizedDescription.UTF8String);
    exit(EXIT_FAILURE);
  }
  MOLCodesignChecker* csc = [fileInfo codesignCheckerWithError:nil];

  SNTRuleIdentifiers* ruleIds = [[SNTRuleIdentifiers alloc]
      initWithRuleIdentifiers:{.cdhash = csc.cdhash,
                               .binarySHA256 = fileInfo.SHA256,
                               .signingID = FormatSigningID(csc),
                               .certificateSHA256 = csc.leafCertificate.SHA256,
                               .teamID = csc.teamID}];

  SNTSandboxExecRequest* req =
      [[SNTSandboxExecRequest alloc] initWithIdentifiers:ruleIds
                                                   fsDev:static_cast<uint64_t>(sb.st_dev)
                                                   fsIno:static_cast<uint64_t>(sb.st_ino)
                                            resolvedPath:resolvedPath];

  // Atomic flag raised by the XPC invalidation handler — checked below
  // before sandbox_init. If santad dies between the RPC reply and execv,
  // santad's AUTH_EXEC handler denies the exec as a fail-safe (no expectation
  // registered → deny), so the worst outcome is a clear failure message.
  //
  // The flag is owned by a shared_ptr captured by both the invalidation
  // block and the enclosing scope; either side may outlive the other
  // (e.g. the connection can fire its handler on a background thread after
  // the main flow returns from the RPC), so reference-counted storage keeps
  // the atomic alive until both release it.
  auto daemonGone = std::make_shared<std::atomic<bool>>(false);
  self.daemonConn.invalidationHandler = ^{
    daemonGone->store(true, std::memory_order_release);
  };

  __block NSString* profile = nil;
  __block NSError* rpcError = nil;
  [[self.daemonConn synchronousRemoteObjectProxy] prepareSandboxExec:req
                                                               reply:^(NSString* p, NSError* err) {
                                                                 profile = p;
                                                                 rpcError = err;
                                                               }];

  if (daemonGone->load(std::memory_order_acquire)) {
    fprintf(stderr, "Error: santad is unavailable\n");
    exit(EXIT_FAILURE);
  }
  if (rpcError || profile.length == 0) {
    fprintf(stderr, "Error: %s\n",
            rpcError.localizedDescription.UTF8String ?: "no seatbelt policy returned");
    exit(EXIT_FAILURE);
  }

#ifdef DEBUG
  if (printProfile) {
    fprintf(stderr, "--- seatbelt profile ---\n%s\n--- end profile ---\n", profile.UTF8String);
  }
#endif

  const char* policyCStr = profile.UTF8String;
  if (!policyCStr) {
    fprintf(stderr, "Error: seatbelt policy cannot be represented as UTF-8\n");
    exit(EXIT_FAILURE);
  }
  const char* execPathCStr = resolvedPath.fileSystemRepresentation;
  NSUInteger argc = commandArgs.count;
  std::vector<const char*> argv(argc + 1);
  for (NSUInteger i = 0; i < argc; i++) {
    argv[i] = [commandArgs[i] fileSystemRepresentation];
  }
  argv[argc] = nullptr;

  char* errorbuf = NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
  if (sandbox_init(policyCStr, 0, &errorbuf) != 0) {
    fprintf(stderr, "sandbox_init failed: %s\n", errorbuf ? errorbuf : "unknown error");
    sandbox_free_error(errorbuf);
    exit(EXIT_FAILURE);
  }
#pragma clang diagnostic pop

  // fd is O_CLOEXEC; execve closes it atomically. Execute by real path so
  // _NSGetExecutablePath / NSBundle / @executable_path behave correctly for
  // both CLI binaries and .app bundles. santad's AUTH_EXEC handler verifies
  // the kernel-reported cdhash against the expectation registered above.
  execv(execPathCStr, const_cast<char* const*>(argv.data()));
  perror("execv");
  exit(EXIT_FAILURE);
}

@end
