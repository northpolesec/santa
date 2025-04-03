/// Copyright 2015 Google Inc. All rights reserved.
/// Copyright 2025 North Pole Security, Inc.
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

#import <CommonCrypto/CommonDigest.h>
#import <Foundation/Foundation.h>
#import <Kernel/kern/cs_blobs.h>

#import "Source/common/MOLCertificate.h"
#import "Source/common/MOLCodesignChecker.h"
#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTDropRootPrivs.h"
#import "Source/common/SNTFileInfo.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTRule.h"
#import "Source/common/SNTRuleIdentifiers.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/santactl/Commands/SNTCommandRule.h"
#import "Source/santactl/SNTCommand.h"
#import "Source/santactl/SNTCommandController.h"

@implementation SNTCommandRule

REGISTER_COMMAND_NAME(@"rule")

+ (BOOL)requiresRoot {
  return YES;
}

+ (BOOL)requiresDaemonConn {
  return YES;
}

+ (NSString *)shortHelpText {
  return @"Manually add/remove/check rules.";
}

+ (NSString *)longHelpText {
  return (@"Usage: santactl rule [options]\n"
          @"  One of:\n"
          @"    --allow: add to allow\n"
          @"    --block: add to block\n"
          @"    --silent-block: add to silent block\n"
          @"    --compiler: allow and mark as a compiler\n"
          @"    --remove: remove existing rule\n"
          @"    --check: check for an existing rule\n"
          @"    --import {path}: import rules from a JSON file\n"
          @"    --export {path}: export rules to a JSON file\n"
          @"\n"
          @"  One of:\n"
          @"    --path {path}: path of binary/bundle to add/remove.\n"
          @"                   Will add an appropriate rule for the file currently at that path.\n"
          @"                   Defaults to a SHA-256 rule unless overridden with another flag.\n"
          @"                   Does not work with --check. Use the fileinfo verb to check.\n"
          @"                   the rule state of a file.\n"
          @"    --identifier {sha256|teamID|signingID|cdhash}: identifier to add/remove/check\n"
          @"    --sha256 {sha256}: hash to add/remove/check [deprecated]\n"
          @"\n"
          @"  Optionally:\n"
          @"    --teamid: add or check a team ID rule instead of binary\n"
          @"    --signingid: add or check a signing ID rule instead of binary (see notes)\n"
          @"    --certificate: add or check a certificate sha256 rule instead of binary\n"
          @"    --cdhash: add or check a cdhash rule instead of binary\n"
#ifdef DEBUG
          @"    --force: allow manual changes even when SyncBaseUrl is set\n"
#endif
          @"    --message {message}: custom message to show when binary is blocked\n"
          @"    --comment {comment}: comment to attach to a new rule\n"
          @"    --clean: when importing rules via JSON clear all non-transitive rules before "
          @"importing\n"
          @"    --clean-all: when importing rules via JSON clear all rules before importing\n"
          @"\n"
          @"  Notes:\n"
          @"    The format of `identifier` when adding/checking a `signingid` rule is:\n"
          @"\n"
          @"      `TeamID:SigningID`\n"
          @"\n"
          @"    Because signing IDs are controlled by the binary author, this ensures\n"
          @"    that the signing ID is properly scoped to a developer. For the special\n"
          @"    case of platform binaries, `TeamID` should be replaced with the string\n"
          @"    \"platform\" (e.g. `platform:SigningID`). This allows for rules\n"
          @"    targeting Apple-signed binaries that do not have a team ID.\n"
          @"\n"
          @"  Importing / Exporting Rules:\n"
          @"    If santa is not configured to use a sync server one can export\n"
          @"    & import its non-static rules to and from JSON files using the \n"
          @"    --export/--import flags. These files have the following form:\n"
          @"\n"
          @"    {\"rules\": [{rule-dictionaries}]}\n"
          @"    e.g. {\"rules\": [\n"
          @"                      {\"policy\": \"BLOCKLIST\",\n"
          @"                       \"identifier\": "
          @"\"84de9c61777ca36b13228e2446d53e966096e78db7a72c632b5c185b2ffe68a6\"\n"
          @"                       \"custom_url\" : \"\",\n"
          @"                       \"custom_msg\": \"/bin/ls block for demo\"}\n"
          @"                      ]}\n"
          @"\n"
          @"    By default rules are not cleared when importing. To clear the\n"
          @"    database you must use either --clean or --clean-all\n"
          @"\n");
}

- (void)runWithArguments:(NSArray *)arguments {
  SNTConfigurator *config = [SNTConfigurator configurator];
  if ((config.syncBaseURL || config.staticRules.count) &&
      ![arguments containsObject:@"--check"]
#ifdef DEBUG
      // DEBUG builds add a --force flag to allow manually adding/removing rules during testing.
      && ![arguments containsObject:@"--force"]) {
#else
  ) {
#endif
    printf("(SyncBaseURL/StaticRules is set, rules are managed centrally.)\n");
    exit(1);
  }

  SNTRule *newRule = [[SNTRule alloc] init];
  newRule.state = SNTRuleStateUnknown;
  newRule.type = SNTRuleTypeBinary;

  NSString *path;
  NSString *jsonFilePath;
  BOOL check = NO;
  SNTRuleCleanup cleanupType = SNTRuleCleanupNone;
  BOOL importRules = NO;
  BOOL exportRules = NO;

  // Parse arguments
  for (NSUInteger i = 0; i < arguments.count; ++i) {
    NSString *arg = arguments[i];

    if ([arg caseInsensitiveCompare:@"--allow"] == NSOrderedSame ||
        [arg caseInsensitiveCompare:@"--whitelist"] == NSOrderedSame) {
      newRule.state = SNTRuleStateAllow;
    } else if ([arg caseInsensitiveCompare:@"--block"] == NSOrderedSame ||
               [arg caseInsensitiveCompare:@"--blacklist"] == NSOrderedSame) {
      newRule.state = SNTRuleStateBlock;
    } else if ([arg caseInsensitiveCompare:@"--silent-block"] == NSOrderedSame ||
               [arg caseInsensitiveCompare:@"--silent-blacklist"] == NSOrderedSame) {
      newRule.state = SNTRuleStateSilentBlock;
    } else if ([arg caseInsensitiveCompare:@"--compiler"] == NSOrderedSame) {
      newRule.state = SNTRuleStateAllowCompiler;
    } else if ([arg caseInsensitiveCompare:@"--remove"] == NSOrderedSame) {
      newRule.state = SNTRuleStateRemove;
    } else if ([arg caseInsensitiveCompare:@"--check"] == NSOrderedSame) {
      check = YES;
    } else if ([arg caseInsensitiveCompare:@"--certificate"] == NSOrderedSame) {
      newRule.type = SNTRuleTypeCertificate;
    } else if ([arg caseInsensitiveCompare:@"--teamid"] == NSOrderedSame) {
      newRule.type = SNTRuleTypeTeamID;
    } else if ([arg caseInsensitiveCompare:@"--signingid"] == NSOrderedSame) {
      newRule.type = SNTRuleTypeSigningID;
    } else if ([arg caseInsensitiveCompare:@"--cdhash"] == NSOrderedSame) {
      newRule.type = SNTRuleTypeCDHash;
    } else if ([arg caseInsensitiveCompare:@"--path"] == NSOrderedSame) {
      if (++i > arguments.count - 1) {
        [self printErrorUsageAndExit:@"--path requires an argument"];
      }
      path = arguments[i];
    } else if ([arg caseInsensitiveCompare:@"--identifier"] == NSOrderedSame) {
      if (++i > arguments.count - 1) {
        [self printErrorUsageAndExit:@"--identifier requires an argument"];
      }
      newRule.identifier = arguments[i];
    } else if ([arg caseInsensitiveCompare:@"--sha256"] == NSOrderedSame) {
      if (++i > arguments.count - 1) {
        [self printErrorUsageAndExit:@"--sha256 requires an argument"];
      }
      newRule.identifier = arguments[i];
    } else if ([arg caseInsensitiveCompare:@"--message"] == NSOrderedSame) {
      if (++i > arguments.count - 1) {
        [self printErrorUsageAndExit:@"--message requires an argument"];
      }
      newRule.customMsg = arguments[i];
    } else if ([arg caseInsensitiveCompare:@"--comment"] == NSOrderedSame) {
      if (++i > arguments.count - 1) {
        [self printErrorUsageAndExit:@"--comment requires an argument"];
      }
      newRule.comment = arguments[i];
#ifdef DEBUG
    } else if ([arg caseInsensitiveCompare:@"--force"] == NSOrderedSame) {
      // Don't do anything special.
#endif
    } else if ([arg caseInsensitiveCompare:@"--import"] == NSOrderedSame) {
      if (exportRules) {
        [self printErrorUsageAndExit:@"--import and --export are mutually exclusive"];
      }
      importRules = YES;
      if (++i > arguments.count - 1) {
        [self printErrorUsageAndExit:@"--import requires an argument"];
      }
      jsonFilePath = arguments[i];
    } else if ([arg caseInsensitiveCompare:@"--clean"] == NSOrderedSame) {
      cleanupType = SNTRuleCleanupNonTransitive;
    } else if ([arg caseInsensitiveCompare:@"--clean-all"] == NSOrderedSame) {
      cleanupType = SNTRuleCleanupAll;
    } else if ([arg caseInsensitiveCompare:@"--export"] == NSOrderedSame) {
      if (importRules) {
        [self printErrorUsageAndExit:@"--import and --export are mutually exclusive"];
      }
      exportRules = YES;
      if (++i > arguments.count - 1) {
        [self printErrorUsageAndExit:@"--export requires an argument"];
      }
      jsonFilePath = arguments[i];
    } else if ([arg caseInsensitiveCompare:@"--help"] == NSOrderedSame ||
               [arg caseInsensitiveCompare:@"-h"] == NSOrderedSame) {
      printf("%s\n", self.class.longHelpText.UTF8String);
      exit(0);
    } else {
      [self printErrorUsageAndExit:[@"Unknown argument: " stringByAppendingString:arg]];
    }
  }

  if (!importRules && cleanupType != SNTRuleCleanupNone) {
    switch (cleanupType) {
      case SNTRuleCleanupNonTransitive:
        [self printErrorUsageAndExit:@"--clean can only be used with --import"];
        break;
      case SNTRuleCleanupAll:
        [self printErrorUsageAndExit:@"--clean-all can only be used with --import"];
        break;
      default:
        // This is a programming error.
        LOGE(@"Unexpected SNTRuleCleanupType %ld", cleanupType);
        exit(EXIT_FAILURE);
    }
  }

  if (jsonFilePath.length > 0) {
    if (importRules) {
      if (newRule.identifier != nil || path != nil || check) {
        [self printErrorUsageAndExit:@"--import can only be used by itself"];
      }
      [self importJSONFile:jsonFilePath with:cleanupType];
    } else if (exportRules) {
      if (newRule.identifier != nil || path != nil || check) {
        [self printErrorUsageAndExit:@"--export can only be used by itself"];
      }
      [self exportJSONFile:jsonFilePath];
    }
    return;
  }

  if (path) {
    SNTFileInfo *fi = [[SNTFileInfo alloc] initWithPath:path];
    if (!fi.path) {
      [self printErrorUsageAndExit:@"Provided path was not a plain file"];
    }

    if (newRule.type == SNTRuleTypeBinary) {
      newRule.identifier = fi.SHA256;
    } else if (newRule.type == SNTRuleTypeCertificate) {
      MOLCodesignChecker *cs = [fi codesignCheckerWithError:NULL];
      newRule.identifier = cs.leafCertificate.SHA256;
    } else if (newRule.type == SNTRuleTypeCDHash) {
      MOLCodesignChecker *cs = [fi codesignCheckerWithError:NULL];
      newRule.identifier = cs.cdhash;
    } else if (newRule.type == SNTRuleTypeTeamID) {
      MOLCodesignChecker *cs = [fi codesignCheckerWithError:NULL];
      newRule.identifier = cs.teamID;
    } else if (newRule.type == SNTRuleTypeSigningID) {
      MOLCodesignChecker *cs = [fi codesignCheckerWithError:NULL];
      if (cs.teamID.length) {
        newRule.identifier = [NSString stringWithFormat:@"%@:%@", cs.teamID, cs.signingID];
      } else if (cs.platformBinary) {
        newRule.identifier = [NSString stringWithFormat:@"platform:%@", cs.signingID];
      }
    }

    if (!newRule.comment) {
      newRule.comment = [NSString stringWithFormat:@"Rule created from %@", path];
    }
  }

  if (newRule.type == SNTRuleTypeBinary || newRule.type == SNTRuleTypeCertificate ||
      newRule.type == SNTRuleTypeCDHash) {
    NSCharacterSet *nonHex =
        [[NSCharacterSet characterSetWithCharactersInString:@"0123456789ABCDEF"] invertedSet];
    NSUInteger length =
        [[newRule.identifier uppercaseString] stringByTrimmingCharactersInSet:nonHex].length;

    if ((newRule.type == SNTRuleTypeBinary || newRule.type == SNTRuleTypeCertificate) &&
        length != CC_SHA256_DIGEST_LENGTH * 2) {
      [self printErrorUsageAndExit:@"BINARY or CERTIFICATE rules require a valid SHA-256"];
    } else if (newRule.type == SNTRuleTypeCDHash && length != CS_CDHASH_LEN * 2) {
      [self printErrorUsageAndExit:
                [NSString stringWithFormat:@"CDHASH rules require a valid hex string of length %d",
                                           CS_CDHASH_LEN * 2]];
    }
  }

  if (check) {
    if (!newRule.identifier) return [self printErrorUsageAndExit:@"--check requires --identifier"];
    return [self printStateOfRule:newRule daemonConnection:self.daemonConn];
  }

  if (newRule.state == SNTRuleStateUnknown) {
    [self printErrorUsageAndExit:@"No state specified"];
  } else if (!newRule.identifier) {
    [self printErrorUsageAndExit:
              @"A valid SHA-256, CDHash, Signing ID, team ID, or path to file must be specified"];
  }

  [[self.daemonConn remoteObjectProxy]
      databaseRuleAddRules:@[ newRule ]
               ruleCleanup:SNTRuleCleanupNone
                    source:SNTRuleAddSourceSantactl
                     reply:^(NSError *error) {
                       if (error) {
                         printf("Failed to modify rules: %s\n",
                                [error.localizedDescription UTF8String]);
                         LOGD(@"Failure reason: %@", error.localizedFailureReason);
                         exit(1);
                       } else {
                         NSString *ruleType;
                         switch (newRule.type) {
                           case SNTRuleTypeCertificate: ruleType = @"Certificate SHA-256"; break;
                           case SNTRuleTypeBinary: {
                             ruleType = @"SHA-256";
                             break;
                           }
                           case SNTRuleTypeTeamID: {
                             ruleType = @"Team ID";
                             break;
                           }
                           case SNTRuleTypeSigningID: {
                             ruleType = @"Signing ID";
                             break;
                           }
                           case SNTRuleTypeCDHash: {
                             ruleType = @"CDHash";
                             break;
                           }
                           default: ruleType = @"(Unknown type)";
                         }
                         if (newRule.state == SNTRuleStateRemove) {
                           printf("Removed rule for %s: %s.\n", [ruleType UTF8String],
                                  [newRule.identifier UTF8String]);
                         } else {
                           printf("Added rule for %s: %s.\n", [ruleType UTF8String],
                                  [newRule.identifier UTF8String]);
                         }
                         exit(0);
                       }
                     }];
}

// IMPORTANT: This method makes no attempt to validate whether or not the data
// in a rule is valid. It merely constructs a string with the given data.
// E.g., TeamID compiler rules are not currently supproted, but if a test rule
// is provided with that state, an appropriate string will be returned.
+ (NSString *)stringifyRule:(SNTRule *)rule withColor:(BOOL)colorize {
  NSMutableString *output;
  // Rule state is saved as eventState for output colorization down below
  SNTEventState eventState = SNTEventStateUnknown;

  switch (rule.state) {
    case SNTRuleStateUnknown:
      output = [@"No rule exists with the given parameters" mutableCopy];
      break;
    case SNTRuleStateAllow: OS_FALLTHROUGH;
    case SNTRuleStateAllowCompiler: OS_FALLTHROUGH;
    case SNTRuleStateAllowTransitive:
      output = [@"Allowed" mutableCopy];
      eventState = SNTEventStateAllow;
      break;
    case SNTRuleStateBlock: OS_FALLTHROUGH;
    case SNTRuleStateSilentBlock:
      output = [@"Blocked" mutableCopy];
      eventState = SNTEventStateBlock;
      break;
    case SNTRuleStateRemove: OS_FALLTHROUGH;
    default:
      output = [NSMutableString stringWithFormat:@"Unexpected rule state: %ld", rule.state];
      break;
  }

  if (rule.state == SNTRuleStateUnknown) {
    // No more output to append
    return output;
  }

  [output appendString:@" ("];

  switch (rule.type) {
    case SNTRuleTypeUnknown: [output appendString:@"Unknown"]; break;
    case SNTRuleTypeCDHash: [output appendString:@"CDHash"]; break;
    case SNTRuleTypeBinary: [output appendString:@"Binary"]; break;
    case SNTRuleTypeSigningID: [output appendString:@"SigningID"]; break;
    case SNTRuleTypeCertificate: [output appendString:@"Certificate"]; break;
    case SNTRuleTypeTeamID: [output appendString:@"TeamID"]; break;
    default:
      output = [NSMutableString stringWithFormat:@"Unexpected rule type: %ld", rule.type];
      break;
  }

  // Add additional attributes
  switch (rule.state) {
    case SNTRuleStateAllowCompiler: [output appendString:@", Compiler"]; break;
    case SNTRuleStateAllowTransitive: [output appendString:@", Transitive"]; break;
    case SNTRuleStateSilentBlock: [output appendString:@", Silent"]; break;
    default: break;
  }

  [output appendString:@")"];

  // Colorize
  if (colorize) {
    if ((SNTEventStateAllow & eventState)) {
      [output insertString:@"\033[32m" atIndex:0];
      [output appendString:@"\033[0m"];
    } else if ((SNTEventStateBlock & eventState)) {
      [output insertString:@"\033[31m" atIndex:0];
      [output appendString:@"\033[0m"];
    } else {
      [output insertString:@"\033[33m" atIndex:0];
      [output appendString:@"\033[0m"];
    }
  }

  if (rule.state == SNTRuleStateAllowTransitive) {
    NSDate *date = [NSDate dateWithTimeIntervalSinceReferenceDate:rule.timestamp];
    [output appendString:[NSString stringWithFormat:@"\nlast access date: %@", [date description]]];
  }
  return output;
}

- (void)printStateOfRule:(SNTRule *)rule daemonConnection:(MOLXPCConnection *)daemonConn {
  id<SNTDaemonControlXPC> rop = [daemonConn synchronousRemoteObjectProxy];
  __block NSString *output;

  struct RuleIdentifiers identifiers = {
      .cdhash = (rule.type == SNTRuleTypeCDHash) ? rule.identifier : nil,
      .binarySHA256 = (rule.type == SNTRuleTypeBinary) ? rule.identifier : nil,
      .certificateSHA256 = (rule.type == SNTRuleTypeCertificate) ? rule.identifier : nil,
      .teamID = (rule.type == SNTRuleTypeTeamID) ? rule.identifier : nil,
      .signingID = (rule.type == SNTRuleTypeSigningID) ? rule.identifier : nil,
  };

  [rop databaseRuleForIdentifiers:[[SNTRuleIdentifiers alloc] initWithRuleIdentifiers:identifiers]
                            reply:^(SNTRule *r) {
                              output = [SNTCommandRule stringifyRule:r
                                                           withColor:(isatty(STDOUT_FILENO) == 1)];
                            }];

  printf("%s\n", output.UTF8String);
  exit(0);
}

- (void)importJSONFile:(NSString *)jsonFilePath with:(SNTRuleCleanup)cleanupType {
  // If the file exists parse it and then add the rules one at a time.
  NSError *error;
  NSData *data = [NSData dataWithContentsOfFile:jsonFilePath options:0 error:&error];
  if (error) {
    [self printErrorUsageAndExit:[NSString stringWithFormat:@"Failed to read %@: %@", jsonFilePath,
                                                            error.localizedDescription]];
  }

  // We expect a JSON object with one key "rules". This is an array of rule
  // objects.
  // e.g.
  // {"rules": [{
  //  "policy" : "BLOCKLIST",
  //    "rule_type" : "BINARY",
  //    "identifier" : "84de9c61777ca36b13228e2446d53e966096e78db7a72c632b5c185b2ffe68a6"
  //    "custom_url" : "",
  //    "custom_msg" : "/bin/ls block for demo"
  //  }]}
  NSDictionary *rules = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
  if (error) {
    [self printErrorUsageAndExit:[NSString stringWithFormat:@"Failed to parse %@: %@", jsonFilePath,
                                                            error.localizedDescription]];
  }

  NSMutableArray<SNTRule *> *parsedRules = [[NSMutableArray alloc] init];

  for (NSDictionary *jsonRule in rules[@"rules"]) {
    NSError *error;
    SNTRule *rule = [[SNTRule alloc] initWithDictionary:jsonRule error:&error];
    if (!rule) {
      [self printErrorUsageAndExit:[NSString
                                       stringWithFormat:@"Invalid rule: %@ = %@", jsonRule, error]];
    }
    [parsedRules addObject:rule];
  }

  [[self.daemonConn remoteObjectProxy]
      databaseRuleAddRules:parsedRules
               ruleCleanup:cleanupType
                    source:SNTRuleAddSourceSantactl
                     reply:^(NSError *error) {
                       if (error) {
                         printf("Failed to modify rules: %s",
                                [error.localizedDescription UTF8String]);
                         LOGD(@"Failure reason: %@", error.localizedFailureReason);
                         exit(1);
                       }
                       exit(0);
                     }];
}

- (void)exportJSONFile:(NSString *)jsonFilePath {
  // Get the rules from the daemon and then write them to the file.
  id<SNTDaemonControlXPC> rop = [self.daemonConn synchronousRemoteObjectProxy];
  [rop retrieveAllRules:^(NSArray<SNTRule *> *rules, NSError *error) {
    if (error) {
      printf("Failed to get rules: %s", [error.localizedDescription UTF8String]);
      LOGD(@"Failure reason: %@", error.localizedFailureReason);
      exit(1);
    }

    if (rules.count == 0) {
      printf("No rules to export.\n");
      exit(1);
    }
    // Convert Rules to an NSDictionary.
    NSMutableArray *rulesAsDicts = [[NSMutableArray alloc] init];

    for (SNTRule *rule in rules) {
      // Omit transitive and remove rules as they're not relevant.
      if (rule.state == SNTRuleStateAllowTransitive || rule.state == SNTRuleStateRemove) {
        continue;
      }

      [rulesAsDicts addObject:[rule dictionaryRepresentation]];
    }

    NSOutputStream *outputStream = [[NSOutputStream alloc] initToFileAtPath:jsonFilePath append:NO];
    [outputStream open];

    // Write the rules to the file.
    // File should look like the following JSON:
    // {"rules": [{"policy": "ALLOWLIST", "identifier": hash, "rule_type: "BINARY"},}]}
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:@{@"rules" : rulesAsDicts}
                                                       options:NSJSONWritingPrettyPrinted
                                                         error:&error];
    // Print error
    if (error) {
      printf("Failed to jsonify rules: %s", [error.localizedDescription UTF8String]);
      LOGD(@"Failure reason: %@", error.localizedFailureReason);
      exit(1);
    }
    // Write jsonData to the file
    [outputStream write:jsonData.bytes maxLength:jsonData.length];
    [outputStream close];
    exit(0);
  }];
}

@end
