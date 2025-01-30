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

#import <MOLXPCConnection/MOLXPCConnection.h>

#import "Source/common/SNTXPCControlInterface.h"

@implementation SNTCommandController

/// A dictionary to hold all of the available commands.
/// Key is the name of the command
/// Value is the Class
static NSMutableDictionary *registeredCommands;

+ (void)registerCommand:(Class<SNTCommandProtocol, SNTCommandRunProtocol>)command
                  named:(NSString *)name {
  if (!registeredCommands) {
    registeredCommands = [NSMutableDictionary dictionary];
  }
  registeredCommands[name] = command;
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
    if (longHelp) {
      return [NSString stringWithFormat:@"Help for '%@':\n%@", commandName, longHelp];
    } else if (shortHelp) {
      return [NSString stringWithFormat:@"Help for '%@':\n%@", commandName, shortHelp];
    } else {
      return @"This command does not have any help information.";
    }
  }
  return nil;
}

+ (MOLXPCConnection *)connectToDaemonRequired:(BOOL)required {
  MOLXPCConnection *daemonConn = [SNTXPCControlInterface configuredConnection];

  if (required) {
    daemonConn.invalidationHandler = ^{
      // Disabling clang format to make desired formatting more apparent
      // clang-format off
      printf("An error occurred communicating with the Santa daemon, is it running?\n"
             "\n"
             "Common troubleshooting steps:\n"
             "\n"
             "    1. Check that the Santa system extension is properly loaded. Run the following\n"
             "       command in a terminal and verify a line item exists for \"com.northpolesec.santa.daemon\"\n"
             "       and it is in the \"activated enabled\" state:\n"
             "\n"
             "       systemextensionsctl list com.apple.system_extension.endpoint_security\n"
             "\n"
             "       If the expected data isn't found, reinstall Santa.\n"
             "\n"
             "    2. Ensure the Santa daemon has been granted Full Disk Access permissions:\n"
             "        * Open System Settings and navigate to \"Privacy & Security > Full Disk Access\"\n"
             "        * Ensure \"com.northpolesec.santa.daemon\" is enabled\n"
             "\n"
             "    3. Check system logs. The daemon will attempt to start about every 10 seconds and\n"
             "       will log if any errors are encountered. In a terminal, run the following command\n"
             "       to view the Santa daemon logs:\n"
             "\n"
             "       log stream --level debug --predicate 'sender == \"com.northpolesec.santa.daemon\"'\n");
      // clang-format on

      exit(1);
    };
    [daemonConn resume];
  }
  return daemonConn;
}

+ (BOOL)hasCommandWithName:(NSString *)commandName {
  return ([registeredCommands objectForKey:commandName] != nil);
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
