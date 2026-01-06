/// Copyright 2017 Google Inc. All rights reserved.
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

#import "src/common/MOLXPCConnection.h"
#import "src/common/SNTFileInfo.h"
#import "src/common/SNTLogging.h"
#import "src/common/SNTStoredExecutionEvent.h"
#import "src/common/SNTXPCBundleServiceInterface.h"
#import "src/santactl/SNTCommand.h"
#import "src/santactl/SNTCommandController.h"

#ifdef DEBUG

@interface SNTCommandBundleInfo : SNTCommand <SNTCommandProtocol>
@end

@implementation SNTCommandBundleInfo

REGISTER_COMMAND_NAME(@"bundleinfo")

+ (BOOL)requiresRoot {
  return NO;
}

+ (BOOL)requiresDaemonConn {
  return NO;
}

+ (NSString *)shortHelpText {
  return @"Searches a bundle for binaries.";
}

+ (NSString *)longHelpText {
  return @"Searches a bundle for binaries.";
}

- (void)runWithArguments:(NSArray *)arguments {
  NSError *error;
  SNTFileInfo *fi = [[SNTFileInfo alloc] initWithPath:arguments.firstObject error:&error];
  if (!fi) {
    TEE_LOGE(@"%@", error.description);
    exit(1);
  } else if (!fi.bundle) {
    TEE_LOGE(@"Not a bundle");
    exit(2);
  }

  SNTStoredExecutionEvent *se = [[SNTStoredExecutionEvent alloc] init];
  se.fileBundlePath = fi.bundlePath;

  MOLXPCConnection *bc = [SNTXPCBundleServiceInterface configuredConnection];
  [bc resume];

  [[bc remoteObjectProxy]
      hashBundleBinariesForEvent:se
                        listener:nil
                           reply:^(NSString *hash, NSArray<SNTStoredExecutionEvent *> *events,
                                   NSNumber *time) {
                             printf("Hashing time: %llu ms\n", time.unsignedLongLongValue);
                             printf("%lu events found\n", events.count);
                             printf("BundleHash: %s\n", hash.UTF8String);

                             for (SNTStoredExecutionEvent *event in events) {
                               printf("BundleID: %s \n\tSHA-256: %s \n\tPath: %s\n",
                                      event.fileBundleID.UTF8String, event.fileSHA256.UTF8String,
                                      event.filePath.UTF8String);
                             }
                             exit(0);
                           }];
}

@end

#endif
