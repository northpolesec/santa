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

// This command currently only exists in debug builds
#ifdef DEBUG

#import "Source/santactl/SNTCommand.h"

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/santactl/SNTCommandController.h"

@interface SNTCommandTelemetry : SNTCommand <SNTCommandProtocol>
@end

@implementation SNTCommandTelemetry

REGISTER_COMMAND_NAME(@"telemetry")

+ (BOOL)requiresRoot {
  return NO;
}

+ (BOOL)requiresDaemonConn {
  return YES;
}

+ (NSString *)shortHelpText {
  return @"Interact with Santa telemetry.";
}

+ (NSString *)longHelpText {
  return (@"Usage: santactl telemetry [options]\n"
          @"  One of:\n"
          @"    --export: Export current telemetry.\n"
          @"\n");
}

- (void)runWithArguments:(NSArray *)arguments {
  if (!arguments.count) {
    [self printErrorUsageAndExit:@"No arguments"];
  }

  enum class TelemetryOperation {
    kUnknown,
    kExport,
  };

  TelemetryOperation operation = TelemetryOperation::kUnknown;

  // Parse arguments
  for (NSUInteger i = 0; i < arguments.count; ++i) {
    NSString *arg = arguments[i];

    if ([arg caseInsensitiveCompare:@"--export"] == NSOrderedSame) {
      operation = TelemetryOperation::kExport;
    } else {
      [self printErrorUsageAndExit:[@"Unknown argument: " stringByAppendingString:arg]];
    }
  }

  switch (operation) {
    case TelemetryOperation::kExport: {
      [self exportTelemetry];
      break;
    }
    default: [self printErrorUsageAndExit:@"No operation provided"];
  }

  // Individual operation handlers control exiting with success or failure
  exit(EXIT_FAILURE);
}

- (void)exportTelemetry {
  int64_t secondsToWait = 300;
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);

  [[self.daemonConn synchronousRemoteObjectProxy] exportTelemetryWithReply:^(BOOL success) {
    if (success) {
      TEE_LOGI(@"Telemetry exported successfully.");
    } else {
      TEE_LOGE(@"Telemetry export failed. Please consult logs for more information.");
    }

    dispatch_semaphore_signal(sema);
  }];

  if (dispatch_semaphore_wait(sema,
                              dispatch_time(DISPATCH_TIME_NOW, secondsToWait * NSEC_PER_SEC)) > 0) {
    TEE_LOGW(@"Timed out waiting for export to complete.");
    exit(EXIT_FAILURE);
  }

  exit(EXIT_SUCCESS);
}

@end

#endif  // DEBUG
