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

#import <Security/Security.h>

#include <errno.h>
#include <fcntl.h>
#include <mach-o/utils.h>
#include <sandbox.h>
#include <string.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <unistd.h>

// Not declared in the public <sandbox.h> but exported by libSystem.
// Profile authors reference parameters as (param "NAME").
extern "C" int sandbox_init_with_parameters(const char* profile, uint64_t flags,
                                            const char* const parameters[], char** errorbuf);

#include <atomic>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#import "Source/common/AccountLookup.h"
#import "Source/common/MOLCodesignChecker.h"
#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTFileInfo.h"
#import "Source/common/SNTRuleIdentifiers.h"
#import "Source/common/SNTSandboxExecRequest.h"
#import "Source/common/SNTXPCControlInterface.h"
#include "Source/common/ScopedCFTypeRef.h"
#import "Source/common/SigningIDHelpers.h"
#import "Source/santactl/SNTCommand.h"
#import "Source/santactl/SNTCommandController.h"

@interface SNTCommandSandbox : SNTCommand <SNTCommandProtocol>
@end

/// The kernel's path for an open descriptor, which is the form seatbelt matches
/// against. Returns std::nullopt and sets errorCode to an errno value on failure.
static std::optional<std::string> PathForFD(int fd, int* errorCode) {
  char buf[MAXPATHLEN];
  if (fcntl(fd, F_GETPATH, buf) != 0) {
    *errorCode = errno;
    return std::nullopt;
  }
  return std::string(buf);
}

using ScopedSecStaticCode = santa::ScopedCFTypeRef<SecStaticCodeRef>;

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

/// The cdhash of the Mach-O slice the kernel will execute, read from the pinned
/// descriptor. santad compares this against the kernel-reported cdhash of the
/// exec'd image, so it has to name the slice that actually runs, and
/// SecStaticCode's own pick is not that slice: macOS 26 ships Apple platform
/// binaries with an arm64e.x1 slice that Security.framework grades above
/// arm64e, while the kernel still executes arm64e. Rather than restate the
/// kernel's grading here, ask the loader: macho_best_slice_in_fd documents its
/// answer for a main executable as "the slice the kernel would execute", so it
/// tracks any subtype Apple adds later.
///
/// A file offset of 0 is passed through rather than special-cased: a thin
/// binary's only slice starts at 0, and Security reads an offset of 0 as the
/// whole file, which for a thin binary is that slice.
///
/// Returns nil when the file is not a Mach-O at all (a script), is malformed,
/// has no loadable slice, or carries no readable signature.
+ (NSString*)cdhashForExecutedSliceOfFD:(int)fd path:(NSString*)path {
  __block uint64_t sliceOffset = 0;
  if (macho_best_slice_in_fd(
          fd, ^(const struct mach_header* slice, uint64_t sliceFileOffset, size_t sliceSize) {
            sliceOffset = sliceFileOffset;
          }) != 0) {
    return nil;
  }

  NSDictionary* attributes =
      @{(__bridge NSString*)kSecCodeAttributeUniversalFileOffset : @(sliceOffset)};
  SecStaticCodeRef codeRef = NULL;
  if (SecStaticCodeCreateWithPathAndAttributes(
          (__bridge CFURLRef)[NSURL fileURLWithPath:path], kSecCSDefaultFlags,
          (__bridge CFDictionaryRef)attributes, &codeRef) != errSecSuccess ||
      !codeRef) {
    return nil;
  }
  ScopedSecStaticCode scopedCodeRef = ScopedSecStaticCode::Assume(codeRef);
  return [[MOLCodesignChecker alloc] initWithSecStaticCodeRef:codeRef error:NULL].cdhash;
}

/// Resolve an absolute directory path for use as a seatbelt parameter. Seatbelt
/// matches rules against resolved paths, so /var/folders/... must be passed as
/// /private/var/folders/.... Symlinks above the last component are resolved;
/// the last component itself must be a directory, not a symlink, and may not be
/// "." or "..". If nothing exists at the last component (e.g. a home directory
/// that has not been created), the result is the resolved parent with that name
/// appended. The result has no trailing slash. Returns std::nullopt and sets
/// errorCode to an errno value on failure.
+ (std::optional<std::string>)resolvedDirectoryPath:(const char*)path errorCode:(int*)errorCode {
  std::string p(path);
  if (!p.starts_with('/')) {
    *errorCode = EINVAL;
    return std::nullopt;
  }
  while (p.size() > 1 && p.ends_with('/')) {
    p.pop_back();
  }
  if (p == "/") return p;

  size_t slash = p.rfind('/');
  std::string parent = slash == 0 ? "/" : p.substr(0, slash);
  std::string leaf = p.substr(slash + 1);
  if (leaf == "." || leaf == "..") {
    *errorCode = EINVAL;
    return std::nullopt;
  }

  int parentFD = open(parent.c_str(), O_SEARCH | O_CLOEXEC);
  if (parentFD < 0) {
    *errorCode = errno;
    return std::nullopt;
  }
  std::optional<std::string> resolved;
  int fd = openat(parentFD, leaf.c_str(), O_SEARCH | O_NOFOLLOW | O_CLOEXEC);
  if (fd >= 0) {
    resolved = PathForFD(fd, errorCode);
    close(fd);
  } else if (errno == ENOENT) {
    resolved = PathForFD(parentFD, errorCode);
    if (resolved) {
      if (!resolved->ends_with('/')) resolved->push_back('/');
      resolved->append(leaf);
    }
  } else {
    *errorCode = errno;
  }
  close(parentFD);
  return resolved;
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
  // BINARY_PATH must be the path seatbelt sees at exec, which resolvedPath is not
  // when it is relative or passes through a symlink (e.g. Homebrew's bin/). Take
  // it from the pinned descriptor instead.
  int binaryPathError = 0;
  std::optional<std::string> binaryPath = PathForFD(fd, &binaryPathError);
  if (!binaryPath) {
    fprintf(stderr, "Error: unable to resolve the path of %s: %s\n", resolvedPath.UTF8String,
            strerror(binaryPathError));
    exit(EXIT_FAILURE);
  }
  NSString* fdPath = [NSString stringWithFormat:@"/dev/fd/%d", fd];

  // Hand over the stat just read from the pinned descriptor rather than letting
  // the initializer take one from fdPath: devfs reports a synthetic st_dev for
  // an fdesc node, which describes no volume and matches nothing in any cache.
  // The stat above is the authoritative one, and supplying it also ties the two
  // halves of the expectation together -- fsDev/fsIno below come from it, while
  // cdhash and sha256 come from reopening fdPath, and nothing else establishes
  // that both describe the same vnode.
  NSError* fileInfoError;
  SNTFileInfo* fileInfo = [[SNTFileInfo alloc] initWithResolvedPath:fdPath
                                                               stat:&sb
                                                              error:&fileInfoError];
  if (!fileInfo) {
    fprintf(stderr, "Error: unable to read binary at %s: %s\n", resolvedPath.UTF8String,
            fileInfoError.localizedDescription.UTF8String);
    exit(EXIT_FAILURE);
  }
  if (fileInfo.identityVerification == SNTFileInfoIdentityMismatch) {
    fprintf(stderr, "Error: unable to confirm the identity of %s\n", resolvedPath.UTF8String);
    exit(EXIT_FAILURE);
  }
  MOLCodesignChecker* csc = [fileInfo codesignCheckerWithError:nil];
  // csc describes the whole file, which is what every identifier below wants
  // except the cdhash: that one has to name the single slice the kernel will
  // execute, because that is what santad is handed at AUTH_EXEC.
  NSString* cdhash = [SNTCommandSandbox cdhashForExecutedSliceOfFD:fd path:fdPath] ?: csc.cdhash;

  SNTRuleIdentifiers* ruleIds = [[SNTRuleIdentifiers alloc]
      initWithRuleIdentifiers:{.cdhash = cdhash,
                               .binarySHA256 = fileInfo.SHA256,
                               .signingID = FormatSigningID(csc),
                               .certificateSHA256 = csc.leafCertificate.SHA256,
                               .teamID = csc.teamID}];

  SNTSandboxExecRequest* req =
      [[SNTSandboxExecRequest alloc] initWithIdentifiers:ruleIds
                                                   fsDev:static_cast<uint64_t>(sb.st_dev)
                                                   fsIno:static_cast<uint64_t>(sb.st_ino)
                                            resolvedPath:resolvedPath];

  // Build the sandbox parameters before registering the exec with santad, so a
  // slow lookup here (e.g. an automounted home directory) cannot outlive the
  // registration.
  //
  // Only pass parameters whose values are actually defined; substituting empty
  // strings for unset env vars would silently alter profile semantics (e.g. a
  // path like (param "HOME") becoming "").  sandbox_init_with_parameters fails
  // if the profile references an unset parameter; `unsetParams` records why
  // each one was left out so that failure can be explained.
  std::vector<std::pair<std::string, std::string>> paramValues;
  std::vector<std::pair<std::string, std::string>> unsetParams;
  auto addDirectoryParam = [&](const char* name, const char* path) {
    int err = 0;
    std::optional<std::string> resolved = [SNTCommandSandbox resolvedDirectoryPath:path
                                                                         errorCode:&err];
    if (resolved) {
      paramValues.emplace_back(name, *resolved);
    } else {
      unsetParams.emplace_back(
          name,
          std::string("cannot resolve ") + path + ": " +
              (err == ENOTDIR ? "not a directory; symlinks are not followed" : strerror(err)));
    }
  };
  // currentDirectoryPath comes from getcwd(3), which already returns a resolved path.
  NSString* cwd = [NSFileManager defaultManager].currentDirectoryPath;
  if (cwd.length > 0) {
    paramValues.emplace_back("CWD", cwd.fileSystemRepresentation);
  } else {
    unsetParams.emplace_back("CWD", "cannot determine the current directory");
  }
  // Look up HOME from the password database rather than $HOME so the placeholder
  // resolves to the calling uid's canonical home (e.g. /private/var/root under
  // sudo) instead of whatever the shell happened to inherit.
  std::optional<std::string> homeDir = santa::account::HomeDirForUID(getuid());
  if (homeDir.has_value()) {
    addDirectoryParam("HOME", homeDir->c_str());
  } else {
    unsetParams.emplace_back("HOME", "no home directory found for this user");
  }
  // Read the per-user darwin temp dir directly rather than $TMPDIR so the
  // placeholder is consistent under sudo / inherited environments.
  char tmpdirBuf[PATH_MAX];
  size_t tmpdirLen = confstr(_CS_DARWIN_USER_TEMP_DIR, tmpdirBuf, sizeof(tmpdirBuf));
  if (tmpdirLen > 0 && tmpdirLen <= sizeof(tmpdirBuf)) {
    addDirectoryParam("TMPDIR", tmpdirBuf);
  } else {
    unsetParams.emplace_back("TMPDIR", "cannot determine the user temporary directory");
  }
  paramValues.emplace_back("UID", std::to_string(getuid()));
  // The full path to the binary being evaluated, so profiles can reference the
  // executable they are sandboxing via (param "BINARY_PATH").
  paramValues.emplace_back("BINARY_PATH", *binaryPath);

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

  std::vector<const char*> params;
  for (const auto& [name, value] : paramValues) {
    params.push_back(name.c_str());
    params.push_back(value.c_str());
  }
  params.push_back(nullptr);

  char* errorbuf = NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
  if (sandbox_init_with_parameters(policyCStr, 0, params.data(), &errorbuf) != 0) {
    fprintf(stderr, "sandbox_init failed: %s\n", errorbuf ? errorbuf : "unknown error");
    // Only mention parameters the profile names, so an unrelated failure is not
    // attributed to them.
    for (const auto& [name, reason] : unsetParams) {
      if ([profile containsString:[NSString stringWithFormat:@"\"%s\"", name.c_str()]]) {
        fprintf(stderr, "Note: %s was not set: %s\n", name.c_str(), reason.c_str());
      }
    }
    sandbox_free_error(errorbuf);
    exit(EXIT_FAILURE);
  }
#pragma clang diagnostic pop

  // fd is O_CLOEXEC; execve closes it atomically. Execute by resolvedPath (not
  // /dev/fd/N) so _NSGetExecutablePath / NSBundle / @executable_path behave
  // correctly for both CLI binaries and .app bundles. santad's AUTH_EXEC
  // handler verifies the kernel-reported cdhash against the expectation
  // registered above.
  execv(execPathCStr, const_cast<char* const*>(argv.data()));
  perror("execv");
  exit(EXIT_FAILURE);
}

@end
