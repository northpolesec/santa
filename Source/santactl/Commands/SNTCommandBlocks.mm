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

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/santactl/SNTCommand.h"
#import "Source/santactl/SNTCommandController.h"

// Matches the keys santad fills in, see Source/santad/RecentBlocks.h.
static NSString* const kTimestamp = @"timestamp";
static NSString* const kPath = @"path";
static NSString* const kReason = @"reason";
static NSString* const kPID = @"pid";

static const int64_t kDefaultSinceSeconds = 60;

@interface SNTCommandBlocks : SNTCommand <SNTCommandProtocol>
@end

@implementation SNTCommandBlocks

REGISTER_COMMAND_NAME(@"blocks")

+ (BOOL)requiresRoot {
  return NO;
}

+ (BOOL)requiresDaemonConn {
  return YES;
}

+ (NSString*)shortHelpText {
  return @"Prints the executions Santa recently blocked.";
}

+ (NSString*)longHelpText {
  return (@"Prints the executions Santa recently blocked, oldest first.\n"
          @"\n"
          @"Useful for finding out whether Santa is the reason a process was killed: a blocked\n"
          @"execution is killed with SIGKILL, which a script or a tool that has no terminal to\n"
          @"read Santa's message on sees only as exit status 137.\n"
          @"\n"
          @"Santa remembers a small number of the most recent blocks and forgets them all when\n"
          @"the daemon restarts. Unless run as root, only blocks of your own executions are\n"
          @"shown.\n"
          @"\n"
          @"Usage: santactl blocks [options]\n"
          @"  Options:\n"
          @"    --since {duration}: How far back to look: 30s, 5m, 1h. Defaults to 60s.\n"
          @"    --json: Print the blocks as JSON.\n"
          @"\n");
}

- (void)runWithArguments:(NSArray*)arguments {
  int64_t sinceSeconds = kDefaultSinceSeconds;
  BOOL jsonOutput = NO;

  for (NSUInteger i = 0; i < arguments.count; ++i) {
    NSString* arg = arguments[i];

    if ([arg caseInsensitiveCompare:@"--since"] == NSOrderedSame) {
      if (++i > arguments.count - 1) {
        [self printErrorUsageAndExit:@"--since requires an argument"];
      }

      NSError* err = nil;
      std::optional<int64_t> seconds = [SNTCommand parseTimeInterval:arguments[i]
                                                         defaultUnit:SNTDurationUnitSeconds
                                                               error:&err];
      if (!seconds.has_value()) {
        [self printErrorUsageAndExit:err.localizedDescription];
      }
      if (*seconds <= 0) {
        [self printErrorUsageAndExit:@"--since must be positive"];
      }
      sinceSeconds = *seconds;
    } else if ([arg caseInsensitiveCompare:@"--json"] == NSOrderedSame) {
      jsonOutput = YES;
    } else {
      [self printErrorUsageAndExit:[NSString stringWithFormat:@"Unknown argument: %@", arg]];
    }
  }

  NSDate* since = [NSDate dateWithTimeIntervalSinceNow:-(NSTimeInterval)sinceSeconds];

  [[self.daemonConn synchronousRemoteObjectProxy]
      recentBlocksSince:since
                  reply:^(NSArray<NSDictionary*>* blocks) {
                    if (jsonOutput) {
                      [self printJSON:blocks];
                    } else {
                      [self printText:blocks];
                    }
                    exit(EXIT_SUCCESS);
                  }];
}

- (void)printJSON:(NSArray<NSDictionary*>*)blocks {
  NSError* err = nil;
  NSData* json =
      [NSJSONSerialization dataWithJSONObject:blocks ?: @[]
                                      options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys
                                        error:&err];
  if (!json) {
    TEE_LOGE(@"Failed to serialize blocks: %@", err.localizedDescription);
    exit(EXIT_FAILURE);
  }

  printf("%s\n", [[[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding] UTF8String]);
}

- (void)printText:(NSArray<NSDictionary*>*)blocks {
  NSISO8601DateFormatter* formatter = [[NSISO8601DateFormatter alloc] init];

  for (NSDictionary* block in blocks) {
    NSDate* date = [NSDate dateWithTimeIntervalSince1970:[block[kTimestamp] doubleValue]];
    printf("%s  %s  %s  pid=%s\n", [[formatter stringFromDate:date] UTF8String],
           [block[kPath] UTF8String], [block[kReason] UTF8String],
           [[block[kPID] stringValue] UTF8String]);
  }
}

@end
