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

#import "src/common/CertificateHelpers.h"
#import "src/common/MOLCodesignChecker.h"
#import "src/common/MOLXPCConnection.h"
#import "src/common/SNTConfigurator.h"
#import "src/common/SNTFileInfo.h"
#import "src/common/SNTLogging.h"
#import "src/common/SNTStoredExecutionEvent.h"
#import "src/common/SNTXPCBundleServiceInterface.h"
#import "src/common/SNTXPCControlInterface.h"
#import "src/common/SNTXPCSyncServiceInterface.h"
#import "src/common/SigningIDHelpers.h"
#import "src/santactl/SNTCommand.h"
#import "src/santactl/SNTCommandController.h"

@interface SNTCommandEventUpload : SNTCommand <SNTCommandProtocol, SNTBundleServiceProgressXPC>
@property(atomic) uint64_t currentBinaryCount;
@property(atomic) uint64_t currentFileCount;
@property(atomic) uint64_t currentHashedCount;
@end

@implementation SNTCommandEventUpload

REGISTER_COMMAND_NAME(@"eventupload")

+ (BOOL)requiresRoot {
  return NO;
}

+ (BOOL)requiresDaemonConn {
  return YES;
}

+ (NSString *)shortHelpText {
  return @"Generate and upload non-execution events to the sync server.";
}

+ (NSString *)longHelpText {
  return @"Generates a non-execution event containing the metadata of the provided bundle or file."
         @"\n"
         @"Usage: santactl eventupload [options] [file-or-bundle-paths]\n"
         @"    --binary-only: Create a single event for the provided files only. No surrounding\n"
         @"                   bundle information will be uploaded.\n"
         @"\n"
         @"Examples: santactl eventupload /Applications/Google\\ Chrome.app\n"
         @"          santactl eventupload /usr/bin/yes /usr/bin/cal\n"
         @"          santactl eventupload --binary-only /Applications/Google\\ "
         @"Chrome.app/Contents/MacOS/Google\\ Chrome\n"
         @"\n"
         @"Note: A sync server must be configured. To generate and upload bundle events, the sync\n"
         @"server must support bundle hashing.";
}

+ (BOOL)isHidden {
  return NO;
}

- (NSArray *)pathsFromArguments:(NSArray *)arguments skipBundles:(BOOL *)skipBundles {
  NSUInteger noBundleIndex = [arguments indexOfObject:@"--binary-only"];
  if (noBundleIndex != NSNotFound) {
    if (skipBundles) *skipBundles = YES;
    NSMutableArray *newArguments = arguments.mutableCopy;
    [newArguments removeObjectAtIndex:noBundleIndex];
    arguments = [newArguments copy];
  }
  return arguments;
}

- (void)runWithArguments:(NSArray *)arguments {
  if (![SNTConfigurator configurator].syncBaseURL) {
    TEE_LOGE(@"Missing SyncBaseURL. Exiting.");
    exit(1);
  }

  // Parse arguments
  if (!arguments.count) [self printErrorUsageAndExit:@"No arguments"];
  BOOL skipBundles = NO;
  NSArray *paths = [self pathsFromArguments:arguments skipBundles:&skipBundles];
  NSMutableArray *events = [NSMutableArray arrayWithCapacity:paths.count];

  // Hash the bundle if the server declares support and if the caller has not explicitly disabled
  // bundle hashing.
  __block BOOL enableBundles = !skipBundles;
  if (enableBundles) {
    [self.daemonConn.synchronousRemoteObjectProxy enableBundles:^(BOOL response) {
      enableBundles = response;
    }];
  }

  MOLXPCConnection *bs = [SNTXPCBundleServiceInterface configuredConnection];
  bs.invalidationHandler = ^(void) {
    TEE_LOGE(@"Failed to connect to the bundle service.");
    exit(1);
  };
  [bs resume];

  for (NSString *path in paths) {
    NSError *error;
    SNTFileInfo *fi = [[SNTFileInfo alloc] initWithPath:path error:&error];
    if (!fi) {
      TEE_LOGE(@"Skipping %@: %@", path, error.description);
      continue;
    }

    SNTStoredExecutionEvent *se = [[SNTStoredExecutionEvent alloc] initWithFileInfo:fi];
    se.decision = SNTEventStateBundleBinary;
    if (fi.bundle && enableBundles) {
      se.fileBundlePath = fi.bundlePath;

      printf("Hashing %s\n", se.fileBundlePath.UTF8String);
      printf("\tSearching for files...");

      self.currentBinaryCount = 0;
      self.currentFileCount = 0;
      self.currentHashedCount = 0;

      // There are two streams of progress the bundle service reports.
      // The first is over SNTBundleServiceProgressXPC. This reports stages and counts of files.
      NSXPCListener *al = [NSXPCListener anonymousListener];
      MOLXPCConnection *pl = [[MOLXPCConnection alloc] initServerWithListener:al];
      pl.exportedObject = self;
      pl.privilegedInterface =
          [NSXPCInterface interfaceWithProtocol:@protocol(SNTBundleServiceProgressXPC)];
      [pl resume];

      // The second stream is "overall progress", via an XPC proxied NSProgress object. This starts
      // reporting progress once all of the bundle's files have been discovered.
      NSProgress *progress = [NSProgress discreteProgressWithTotalUnitCount:1];
      [progress addObserver:self
                 forKeyPath:@"fractionCompleted"
                    options:NSKeyValueObservingOptionNew
                    context:NULL];
      [progress becomeCurrentWithPendingUnitCount:100];

      [[bs synchronousRemoteObjectProxy]
          hashBundleBinariesForEvent:se
                            listener:al.endpoint
                               reply:^(NSString *hash,
                                       NSArray<SNTStoredExecutionEvent *> *bundleEvents,
                                       NSNumber *time) {
                                 printf("\tHashing time: %llu ms\n", time.unsignedLongLongValue);
                                 printf("\tEvents found: %lu\n", bundleEvents.count);
                                 printf("\tBundleHash: %s\n", hash.UTF8String);
                                 for (SNTStoredExecutionEvent *e in bundleEvents) {
                                   e.fileBundleHash = hash;
                                   e.fileBundleHashMilliseconds = time;
                                   e.fileBundleBinaryCount = @(bundleEvents.count);
                                 }
                                 [events addObjectsFromArray:bundleEvents];
                               }];

      [progress removeObserver:self forKeyPath:@"fractionCompleted"];
    }

    if (se) [events addObject:se];
  }

  MOLXPCConnection *ss = [SNTXPCSyncServiceInterface configuredConnection];
  ss.invalidationHandler = ^(void) {
    TEE_LOGE(@"Failed to connect to the sync service.");
    exit(1);
  };
  [ss resume];
  printf("Uploading %lu events...\n", events.count);
  [[ss synchronousRemoteObjectProxy] postEventsToSyncServer:events
                                                      reply:^(BOOL){
                                                      }];
  printf("Done\n");
  exit(0);
}

- (void)observeValueForKeyPath:(NSString *)keyPath
                      ofObject:(id)object
                        change:(NSDictionary *)change
                       context:(void *)context {
  if ([keyPath isEqualToString:@"fractionCompleted"]) {
    NSProgress *progress = object;
    NSString *fileLabel =
        [NSString stringWithFormat:@"Complete: %d%% | %llu binaries / %llu files",
                                   (int)(progress.fractionCompleted * 100), self.currentBinaryCount,
                                   self.currentFileCount];
    NSString *hashedLabel =
        [NSString stringWithFormat:@"Complete: %d%% | %llu hashed / %llu binaries",
                                   (int)(progress.fractionCompleted * 100), self.currentHashedCount,
                                   self.currentBinaryCount];
    NSString *status = self.currentHashedCount ? hashedLabel : fileLabel;
    printf("\33[2K\r\t%s", status.UTF8String);
    if (progress.fractionCompleted == 100.0) {
      // Clear and return to the start of the line.
      printf("\33[2K\r");
    }
  }
}

- (void)updateCountsForEvent:(SNTStoredExecutionEvent *)event
                 binaryCount:(uint64_t)binaryCount
                   fileCount:(uint64_t)fileCount
                 hashedCount:(uint64_t)hashedCount {
  self.currentBinaryCount = binaryCount;
  self.currentFileCount = fileCount;
  self.currentHashedCount = hashedCount;
}

@end
