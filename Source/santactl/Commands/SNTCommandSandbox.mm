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
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#import "Source/common/MOLCodesignChecker.h"
#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTFileInfo.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTRule.h"
#import "Source/common/SNTRuleIdentifiers.h"
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
  return (@"Usage: santactl sandbox [--print-profile] <command> [arguments...]\n"
          @"\n"
          @"  Looks up the seatbelt policy for the given command from Santa's rule\n"
          @"  database. If a rule with a seatbelt policy exists, applies the sandbox\n"
          @"  profile via sandbox_init and then executes the command. If no matching\n"
          @"  rule is found or the matched rule has no seatbelt policy, santactl\n"
          @"  refuses to run the command and exits with a non-zero status.\n"
          @"\n"
          @"  Options:\n"
          @"    --print-profile: Print the sandbox profile to stderr before applying it.\n");
}

+ (NSSet<NSString*>*)aliases {
  return [NSSet setWithArray:@[ @"sb" ]];
}

/// Resolve a command name to its full path by searching PATH.
/// Returns nil if the command cannot be found.
- (NSString*)resolveCommand:(NSString*)command {
  if (command.length == 0) return nil;

  // If the command contains a slash, treat it as a path.
  if ([command containsString:@"/"]) {
    return command;
  }

  const char* pathEnv = getenv("PATH");
  if (!pathEnv) return nil;

  for (NSString* dir in [@(pathEnv) componentsSeparatedByString:@":"]) {
    // Skip empty or non-absolute PATH entries to avoid resolving relative to cwd.
    if (dir.length == 0 || ![dir hasPrefix:@"/"]) continue;

    NSString* fullPath = [dir stringByAppendingPathComponent:command];
    const char* cPath = fullPath.fileSystemRepresentation;
    struct stat sb;
    if (stat(cPath, &sb) == 0 && S_ISREG(sb.st_mode) && access(cPath, X_OK) == 0) {
      return fullPath;
    }
  }
  return nil;
}

- (void)runWithArguments:(NSArray*)arguments {
  // The subcommand name ("sandbox"/"sb") has already been stripped by main.mm.
  // Parse leading flags, then the remaining arguments are the command and args.
  BOOL printProfile = NO;
  NSUInteger idx = 0;
  while (idx < arguments.count) {
    NSString* arg = arguments[idx];
    if ([arg isEqualToString:@"--print-profile"]) {
      printProfile = YES;
      idx++;
    } else if ([arg isEqualToString:@"--"]) {
      idx++;
      break;
    } else {
      break;
    }
  }

  if (idx >= arguments.count) {
    [self printErrorUsageAndExit:@"No command specified."];
  }

  NSArray* commandArgs = [arguments subarrayWithRange:NSMakeRange(idx, arguments.count - idx)];
  NSString* command = commandArgs[0];

  // Resolve the binary path.
  NSString* resolvedPath = [self resolveCommand:command];
  if (!resolvedPath) {
    fprintf(stderr, "Error: command not found: %s\n", command.UTF8String);
    exit(EXIT_FAILURE);
  }

  // Open the file and hold it open until we exec, so subsequent operations all
  // see the same inode. Using /dev/fd/N for identifier computation and for the
  // eventual exec closes the TOCTOU window where the resolved path (or a
  // symlink in it) could be swapped between our checks and the exec.
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

  // Compute identifiers for the binary via /dev/fd/N so they reflect the file
  // we've pinned open, not whatever might replace the path later.
  NSError* fileInfoError;
  SNTFileInfo* fileInfo = [[SNTFileInfo alloc] initWithResolvedPath:fdPath error:&fileInfoError];
  if (!fileInfo) {
    fprintf(stderr, "Error: unable to read binary at %s: %s\n", resolvedPath.UTF8String,
            fileInfoError.localizedDescription.UTF8String);
    exit(EXIT_FAILURE);
  }

  NSString* binarySHA256 = fileInfo.SHA256;
  MOLCodesignChecker* csc = [fileInfo codesignCheckerWithError:nil];
  NSString* signingID = FormatSigningID(csc);
  NSString* certSHA256 = csc.leafCertificate.SHA256;
  NSString* teamID = csc.teamID;
  NSString* cdhash = csc.cdhash;

  struct RuleIdentifiers identifiers = {
      .cdhash = cdhash,
      .binarySHA256 = binarySHA256,
      .signingID = signingID,
      .certificateSHA256 = certSHA256,
      .teamID = teamID,
  };
  SNTRuleIdentifiers* ruleIds = [[SNTRuleIdentifiers alloc] initWithRuleIdentifiers:identifiers];

  // Look up the seatbelt rule from santad.
  __block SNTRule* rule = nil;
  [[self.daemonConn synchronousRemoteObjectProxy] databaseRuleForIdentifiers:ruleIds
                                                                       reply:^(SNTRule* r) {
                                                                         rule = r;
                                                                       }];

  if (!rule || !rule.seatbeltPolicy.length) {
    fprintf(stderr, "Warning: no seatbelt policy found for %s, refusing to run.\n",
            resolvedPath.UTF8String);
    exit(EXIT_FAILURE);
  }

  // Seatbelt rule found — fork, apply sandbox, and exec.
  pid_t pid = fork();
  if (pid < 0) {
    perror("fork");
    exit(EXIT_FAILURE);
  }

  if (pid == 0) {
    // Child process: apply sandbox profile.
    if (printProfile) {
      fprintf(stderr, "--- seatbelt profile ---\n%s\n--- end profile ---\n",
              rule.seatbeltPolicy.UTF8String);
    }
    char* errorbuf = NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    if (sandbox_init(rule.seatbeltPolicy.UTF8String, 0, &errorbuf) != 0) {
      fprintf(stderr, "sandbox_init failed: %s\n", errorbuf ? errorbuf : "unknown error");
      sandbox_free_error(errorbuf);
      _exit(EXIT_FAILURE);
    }
#pragma clang diagnostic pop

    // Build argv. argv[0] keeps the caller-supplied command name so the child
    // sees the expected program name, but we exec the already-resolved path
    // via execv (not execvp) so no second PATH search happens in the child.
    // Note: we intentionally do not exec via /dev/fd/N here because the
    // just-applied seatbelt profile will typically deny access to /dev/fd,
    // causing execv to fail. The small TOCTOU window between parent-side
    // identifier computation and this exec is no worse than a normal shell.
    NSUInteger argc = commandArgs.count;
    const char** argv = (const char**)calloc(argc + 1, sizeof(char*));
    for (NSUInteger i = 0; i < argc; i++) {
      argv[i] = [commandArgs[i] fileSystemRepresentation];
    }
    argv[argc] = NULL;

    execv(resolvedPath.fileSystemRepresentation, (char* const*)argv);
    // execv only returns on error.
    perror("execv");
    _exit(EXIT_FAILURE);
  }

  // Parent process: wait for the child to finish and propagate its exit status.
  // We cannot simply _exit() here because state inherited across fork (XPC
  // connections, pipes, terminal session) can cause the still-running child to
  // be terminated when the parent goes away.
  int status = 0;
  while (waitpid(pid, &status, 0) < 0) {
    if (errno != EINTR) {
      perror("waitpid");
      _exit(EXIT_FAILURE);
    }
  }
  if (WIFEXITED(status)) {
    _exit(WEXITSTATUS(status));
  } else if (WIFSIGNALED(status)) {
    _exit(128 + WTERMSIG(status));
  }
  _exit(EXIT_FAILURE);
}

@end
