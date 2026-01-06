/// Copyright 2025 North Pole Security, Inc.
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

/// This utility is used to generate a plist containing SNTFileAccessRule objects.
/// The output can be used for "rule download" testing.
///
/// To run (use arg "-h" for complete usage):
///   bazel run //Testing/OneOffs:file_access_rule_generator -- <args>
///
/// This will put output in `/tmp/file_access_rule_archive.plist`

#include <Foundation/Foundation.h>

#include <stdlib.h>
#include <unistd.h>

#include <cstdlib>
#include <iostream>
#include <string>

#import "src/common/SNTFileAccessRule.h"
#include "src/common/faa/WatchItems.h"

static NSString *const kDefaultOutputPath = @"/tmp/file_access_rule_archive.plist";

void PrintUsage() {
  std::cout << "Usage: " << getprogname() << " [OPTIONS]\n"
            << "Options:\n"
            << "  -a         Generate \"Add\" rules (default)\n"
            << "  -r         Generate \"Remove\" rules\n"
            << "  -n <num>   Number of rules to generate (default: 5)\n"
            << "  -o <path>  Path to output (default: \"/tmp/file_access_rule_archive.plist\")\n"
            << "  -h         Show this help message\n";
}

NSArray<SNTFileAccessRule *> *GenerateFileAccessAddRules(long numRules) {
  NSMutableArray<SNTFileAccessRule *> *rules = [[NSMutableArray alloc] init];

  for (long i = 0; i < numRules; i++) {
    [rules addObject:[[SNTFileAccessRule alloc]
                         initAddRuleWithName:[NSString stringWithFormat:@"WatcherCat%ld", i]
                                     details:@{
                                       kWatchItemConfigKeyPaths : @[ @{
                                         kWatchItemConfigKeyPathsPath : [NSString
                                             stringWithFormat:@"/private/tmp/watcher%ld", i],
                                         kWatchItemConfigKeyPathsIsPrefix : @(YES),
                                       } ],
                                       kWatchItemConfigKeyOptions : @{
                                         kWatchItemConfigKeyOptionsVersion : @"1",
                                         kWatchItemConfigKeyOptionsAuditOnly : @(NO),
                                         kWatchItemConfigKeyOptionsAllowReadAccess : @(NO),
                                       },
                                       kWatchItemConfigKeyProcesses : @[
                                         @{
                                           kWatchItemConfigKeyProcessesSigningID :
                                               @"platform:com.apple.cat",
                                         },
                                       ],
                                     }]];
  }

  return rules;
}

NSArray<SNTFileAccessRule *> *GenerateFileAccessRemoveRules(long numRules) {
  NSMutableArray<SNTFileAccessRule *> *rules = [[NSMutableArray alloc] init];

  for (long i = 0; i < numRules; i++) {
    [rules addObject:[[SNTFileAccessRule alloc]
                         initRemoveRuleWithName:[NSString stringWithFormat:@"WatcherCat%ld", i]]];
  }

  return rules;
}

int main(int argc, char *argv[]) {
  int opt;
  bool addRules = true;
  NSString *outputPath = kDefaultOutputPath;
  long numRules = 5;

  while ((opt = getopt(argc, argv, "arn:o:h")) != -1) {
    switch (opt) {
      case 'a': addRules = true; break;
      case 'r': addRules = false; break;
      case 'n': {
        char *endptr;
        numRules = strtol(optarg, &endptr, 10);

        if (*endptr != '\0' || numRules <= 0) {
          std::cerr << "Error: Invalid number of iterations: " << optarg << std::endl;
          exit(EXIT_FAILURE);
        }

        break;
      }
      case 'o': {
        outputPath = [NSString stringWithUTF8String:optarg];
        break;
      }
      case 'h': PrintUsage(); return 0;
      case '?': PrintUsage(); return 1;
      default: PrintUsage(); return 1;
    }
  }

  NSArray<SNTFileAccessRule *> *rules =
      addRules ? GenerateFileAccessAddRules(numRules) : GenerateFileAccessRemoveRules(numRules);

  NSError *err;
  NSData *data = [NSKeyedArchiver archivedDataWithRootObject:rules
                                       requiringSecureCoding:YES
                                                       error:&err];
  if (!data) {
    NSLog(@"Failed to archive stored events: %@", err);
    exit(EXIT_FAILURE);
  }

  if (![data writeToFile:outputPath atomically:YES]) {
    NSLog(@"Failed to write archive to disk");
    exit(EXIT_FAILURE);
  }

  NSLog(@"Archived events to file: %@", outputPath);

  return 0;
}
