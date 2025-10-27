/// Copyright 2015 Google Inc. All rights reserved.
/// Copyright 2024 North Pole Security, Inc.
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

#import "Source/santactl/SNTCommandController.h"

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTXPCControlInterface.h"

@implementation SNTCommandController

/// A dictionary to hold all of the available commands.
/// Key is the name of the command
/// Value is the Class
static NSMutableDictionary *registeredCommands;
static NSMutableDictionary *registeredAliases;

+ (void)registerCommand:(Class<SNTCommandProtocol, SNTCommandRunProtocol>)command
                  named:(NSString *)name {
  if (!registeredCommands) {
    registeredCommands = [NSMutableDictionary dictionary];
  }
  registeredCommands[name] = command;

  if ([command respondsToSelector:@selector(aliases)]) {
    if (!registeredAliases) {
      registeredAliases = [NSMutableDictionary dictionary];
    }

    NSSet<NSString *> *aliases = [command aliases];
    if (!aliases) {
      return;
    }

    for (NSString *alias in aliases) {
      if (registeredAliases[alias]) {
        TEE_LOGE(@"Duplicate alias registered: %@", alias);
        exit(EXIT_FAILURE);
      }

      registeredAliases[alias] = name;
    }
  }
}

+ (NSString *)usage {
  NSMutableString *helpText = [[NSMutableString alloc] init];

  int longestCommandName = 0;
  for (NSString *cmdName in registeredCommands) {
    if ((int)[cmdName length] > longestCommandName) {
      longestCommandName = (int)[cmdName length];
    }
  }

  for (NSString *cmdName in
       [[registeredCommands allKeys] sortedArrayUsingSelector:@selector(caseInsensitiveCompare:)]) {
    Class<SNTCommandProtocol> command = registeredCommands[cmdName];

    BOOL hidden = [command respondsToSelector:@selector(isHidden)] && [command isHidden];

    if (!hidden) {
      [helpText appendFormat:@"\t%*s - %@\n", longestCommandName, [cmdName UTF8String],
                             [command shortHelpText]];
    }
  }

  [helpText appendFormat:@"\nSee 'santactl help <command>' to read about a specific subcommand."];
  return helpText;
}

+ (NSString *)helpForCommandWithName:(NSString *)commandName {
  Class<SNTCommandProtocol> command = registeredCommands[commandName];
  if (command) {
    NSString *shortHelp = [command shortHelpText];
    NSString *longHelp = [command longHelpText];
    if (longHelp || shortHelp) {
      longHelp = [NSString stringWithFormat:@"Help for '%@':\n%@", commandName, longHelp ?: shortHelp];
    } else {
      longHelp = @"This command does not have any help information.";
    }

    // Normalize trailing whitespace so as not to rely on all commands conforming to a style.
    longHelp = [longHelp stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    longHelp = [longHelp stringByAppendingString:@"\n"];

    if ([command respondsToSelector:@selector(aliases)]) {
      NSSet<NSString *> *aliases = [command aliases];
      if (aliases.count > 0) {
        longHelp = [NSString stringWithFormat:@"%@\nAliases: %@\n", longHelp,
                                              [[aliases allObjects] componentsJoinedByString:@", "]];
      }
    }

    return longHelp;
  }
  return nil;
}

+ (MOLXPCConnection *)connectToDaemonRequired:(BOOL)required {
  MOLXPCConnection *daemonConn = [SNTXPCControlInterface configuredConnection];

  if (required) {
    daemonConn.invalidationHandler = ^{
      printf("An error occurred communicating with the Santa daemon. Check to make sure\n"
             "the process is running and has been granted Full Disk Access permissions.\n"
             "\n"
             "For detailed steps, see: https://northpole.dev/deployment/troubleshooting\n");
      exit(1);
    };
    [daemonConn resume];
  }
  return daemonConn;
}

+ (BOOL)hasCommandWithName:(NSString *)commandName {
  return ([registeredCommands objectForKey:commandName] != nil);
}

+ (NSString *)resolveCommandName:(NSString *)name {
  // Remove hyphens and underscores
  NSString *normalized = [[name stringByReplacingOccurrencesOfString:@"-" withString:@""]
      stringByReplacingOccurrencesOfString:@"_"
                                withString:@""];

  return registeredAliases[normalized] ?: normalized;
}

+ (void)runCommandWithName:(NSString *)commandName arguments:(NSArray *)arguments {
  Class<SNTCommandProtocol, SNTCommandRunProtocol> command = registeredCommands[commandName];

  if ([command requiresRoot] && getuid() != 0) {
    printf("The command '%s' requires root privileges.\n", [commandName UTF8String]);
    exit(2);
  }

  MOLXPCConnection *daemonConn = [self connectToDaemonRequired:[command requiresDaemonConn]];
  [command runWithArguments:arguments daemonConnection:daemonConn];

  // The command is responsible for quitting.
  [[NSRunLoop mainRunLoop] run];
}

@end
