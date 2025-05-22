/// Copyright 2017 Google Inc. All rights reserved.
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

#import "Source/santabundleservice/SNTBundleService.h"

#import <CommonCrypto/CommonDigest.h>
#import <pthread/pthread.h>

#import <atomic>
#import <memory>
#import <vector>

#import "Source/common/MOLCodesignChecker.h"
#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTFileInfo.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTStoredEvent.h"
#import "Source/common/SNTXPCNotifierInterface.h"
#import "Source/common/SigningIDHelpers.h"
#import "Source/common/StoredEventHelpers.h"

@interface SNTBundleService ()
@property(nonatomic) dispatch_queue_t queue;
@property(nonatomic) dispatch_source_t spindownTimer;
@end

@implementation SNTBundleService {
  std::atomic<uint64_t> _current_events;
}

- (instancetype)init {
  self = [super init];
  if (self) {
    _queue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0);
  }
  return self;
}

#pragma mark SNTBundleServiceXPC Methods

- (void)hashBundleBinariesForEvent:(SNTStoredEvent *)event
                          listener:(NSXPCListenerEndpoint *)listener
                             reply:(SNTBundleHashBlock)reply {
  // Start a new hashing operation. Cancel any previously scheduled spindowns.
  // If a spindown was scheduled, it was from the main run loop - do the cancellation from there.
  ++_current_events;
  dispatch_async(dispatch_get_main_queue(), ^{
    [NSObject cancelPreviousPerformRequestsWithTarget:self selector:@selector(spindown) object:nil];
  });

  NSProgress *progress =
      [NSProgress currentProgress] ? [NSProgress progressWithTotalUnitCount:100] : nil;

  NSDate *startTime = [NSDate date];

  dispatch_semaphore_t sema = dispatch_semaphore_create(0);

  // Connect back to the client.
  MOLXPCConnection *clientListener;
  if (listener) {
    clientListener = [[MOLXPCConnection alloc] initClientWithListener:listener];
    clientListener.remoteInterface =
        [NSXPCInterface interfaceWithProtocol:@protocol(SNTBundleServiceProgressXPC)];
    clientListener.invalidationHandler = ^{
      [progress cancel];
    };
    [clientListener resume];
  }

  dispatch_async(self.queue, ^{
    // Use the highest bundle we can find.
    SNTFileInfo *b = [[SNTFileInfo alloc] initWithPath:event.fileBundlePath];
    b.useAncestorBundle = YES;
    event.fileBundlePath = b.bundlePath;

    // If path to the bundle is unavailable, stop. SantaGUI will revert to
    // using the offending blockable.
    if (!event.fileBundlePath) {
      reply(nil, nil, 0);
      dispatch_semaphore_signal(sema);
      return;
    }

    // Reuse the bundle infomation when creating the related binary events.
    event.fileBundleID = b.bundleIdentifier;
    event.fileBundleName = b.bundleName;
    event.fileBundleVersion = b.bundleVersion;
    event.fileBundleVersionString = b.bundleShortVersionString;

    // For most apps this should be "Contents/MacOS/AppName"
    if (b.bundle.executablePath.length > b.bundlePath.length) {
      event.fileBundleExecutableRelPath =
          [b.bundle.executablePath substringFromIndex:b.bundlePath.length + 1];
    }

    NSDictionary *relatedEvents = [self findRelatedBinaries:event
                                                   progress:progress
                                             clientListener:clientListener];
    NSString *bundleHash = [self calculateBundleHashFromSHA256Hashes:relatedEvents.allKeys
                                                            progress:progress];
    NSNumber *ms = [NSNumber numberWithDouble:[startTime timeIntervalSinceNow] * -1000.0];

    reply(bundleHash, relatedEvents.allValues, ms);
    dispatch_semaphore_signal(sema);
  });

  // Master timeout of 10 min. Don't block the calling thread. NSProgress updates will be coming
  // in over this thread.
  dispatch_async(self.queue, ^{
    if (dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 600 * NSEC_PER_SEC))) {
      [progress cancel];
    }

    // If there are no more active hashing events, schedule a spindown of this service. The GUI or
    // santactl clients may call this method back to back, add a delay of 10 seconds before spinning
    // down to allow for new requests to come in and be handled by this process.
    // -performSelector:withObject:afterDelay: depends on a run loop, shove this over to the main
    // run loop.
    if (--_current_events == 0) {
      dispatch_async(dispatch_get_main_queue(), ^{
        [self performSelector:@selector(spindown) withObject:nil afterDelay:10.0f];
      });
    }
  });
}

#pragma mark Internal Methods

- (void)spindown {
  if (_current_events == 0) {
    LOGI(@"Spinning down");
    exit(0);
  }
}

/**
  Find binaries within a bundle given the bundle's event. It will run until a timeout occurs,
  or until the NSProgress is cancelled. Search is done within the bundle concurrently.

  @param event The SNTStoredEvent to begin searching.
  @return An NSDictionary object with keys of fileSHA256 and values of SNTStoredEvent objects.
*/
- (NSDictionary *)findRelatedBinaries:(SNTStoredEvent *)event
                             progress:(NSProgress *)progress
                       clientListener:(MOLXPCConnection *)clientListener {
  // Find all files and folders within the fileBundlePath
  NSFileManager *fm = [NSFileManager defaultManager];
  NSArray *subpaths = [fm subpathsOfDirectoryAtPath:event.fileBundlePath error:NULL];

  // This array is used to store pointers to executable SNTFileInfo objects. There will be one block
  // dispatched per file in dirEnum. These blocks will write pointers to this array concurrently.
  // No locks are used since every file has a slot.
  //
  // Xcode.app has roughly 500k files, 8bytes per pointer is ~4MB for this array. This size to space
  // ratio seems appropriate as Xcode.app is in the upper bounds of bundle size.
  // Using a shared pointer to make block capture easy.
  __block auto fis = std::make_shared<std::vector<SNTFileInfo *>>(subpaths.count);

  // Counts used as additional progress information in SantaGUI
  __block auto binaryCount = std::make_shared<std::atomic<int64_t>>(0);
  __block auto completedUnits = std::make_shared<std::atomic<int64_t>>(0);

  // Account for 80% of the work
  NSProgress *p;
  if (progress) {
    [progress becomeCurrentWithPendingUnitCount:80];
    p = [NSProgress progressWithTotalUnitCount:subpaths.count * 100];
  }

  // Dispatch a block for every file in dirEnum.
  dispatch_apply(subpaths.count, self.queue, ^(size_t i) {
    @autoreleasepool {
      if (progress.isCancelled) return;

      dispatch_sync(dispatch_get_main_queue(), ^{
        // Update the UI for every 1% of work completed.
        completedUnits->fetch_add(1);
        if ((((double)completedUnits->load() / subpaths.count) -
             ((double)p.completedUnitCount / subpaths.count)) > 0.01) {
          p.completedUnitCount = completedUnits->load();
          [[clientListener remoteObjectProxy] updateCountsForEvent:event
                                                       binaryCount:binaryCount->load()
                                                         fileCount:i
                                                       hashedCount:0];
        }
      });

      NSString *subpath = subpaths[i];

      NSString *file =
          [event.fileBundlePath stringByAppendingPathComponent:subpath].stringByStandardizingPath;
      SNTFileInfo *fi = [[SNTFileInfo alloc] initWithResolvedPath:file error:NULL];
      if (!fi.isExecutable) return;

      fis->at(i) = fi;
      binaryCount->fetch_add(1);
    }
  });

  [progress resignCurrent];

  NSMutableArray *fileInfos = [NSMutableArray arrayWithCapacity:binaryCount->load()];
  for (NSUInteger i = 0; i < subpaths.count; i++) {
    if (fis->at(i)) [fileInfos addObject:fis->at(i)];
  }

  return [self generateEventsFromBinaries:fileInfos
                            blockingEvent:event
                                 progress:progress
                           clientListener:clientListener];
}

- (NSDictionary *)generateEventsFromBinaries:(NSArray *)fis
                               blockingEvent:(SNTStoredEvent *)event
                                    progress:(NSProgress *)progress
                              clientListener:(MOLXPCConnection *)clientListener {
  if (progress.isCancelled) return nil;

  NSMutableDictionary *relatedEvents = [NSMutableDictionary dictionaryWithCapacity:fis.count];

  // Account for 15% of the work
  NSProgress *p;
  if (progress) {
    [progress becomeCurrentWithPendingUnitCount:15];
    p = [NSProgress progressWithTotalUnitCount:fis.count * 100];
  }

  dispatch_apply(fis.count, self.queue, ^(size_t i) {
    @autoreleasepool {
      if (progress.isCancelled) return;

      SNTFileInfo *fi = fis[i];

      SNTStoredEvent *se = StoredEventFromFileInfo(fi);
      se.decision = SNTEventStateBundleBinary;
      se.fileBundlePath = event.fileBundlePath;
      se.fileBundleExecutableRelPath = event.fileBundleExecutableRelPath;
      se.fileBundleID = event.fileBundleID;
      se.fileBundleName = event.fileBundleName;
      se.fileBundleVersion = event.fileBundleVersion;
      se.fileBundleVersionString = event.fileBundleVersionString;

      dispatch_sync(dispatch_get_main_queue(), ^{
        relatedEvents[se.fileSHA256] = se;
        p.completedUnitCount++;
        if (progress) {
          [[clientListener remoteObjectProxy] updateCountsForEvent:event
                                                       binaryCount:fis.count
                                                         fileCount:0
                                                       hashedCount:i];
        }
      });
    }
  });

  [progress resignCurrent];

  return relatedEvents;
}

- (NSString *)calculateBundleHashFromSHA256Hashes:(NSArray *)hashes
                                         progress:(NSProgress *)progress {
  if (!hashes.count) return nil;

  // Account for 5% of the work
  NSProgress *p;
  if (progress) {
    [progress becomeCurrentWithPendingUnitCount:5];
    p = [NSProgress progressWithTotalUnitCount:5 * 100];
  }

  NSMutableArray *sortedHashes = [hashes mutableCopy];
  [sortedHashes sortUsingSelector:@selector(localizedCaseInsensitiveCompare:)];
  NSString *sha256Hashes = [sortedHashes componentsJoinedByString:@""];

  CC_SHA256_CTX c256;
  CC_SHA256_Init(&c256);
  CC_SHA256_Update(&c256, (const void *)sha256Hashes.UTF8String, (CC_LONG)sha256Hashes.length);
  unsigned char digest[CC_SHA256_DIGEST_LENGTH];
  CC_SHA256_Final(digest, &c256);

  NSString *const SHA256FormatString =
      @"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
       "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x";

  NSString *sha256 = [[NSString alloc]
      initWithFormat:SHA256FormatString, digest[0], digest[1], digest[2], digest[3], digest[4],
                     digest[5], digest[6], digest[7], digest[8], digest[9], digest[10], digest[11],
                     digest[12], digest[13], digest[14], digest[15], digest[16], digest[17],
                     digest[18], digest[19], digest[20], digest[21], digest[22], digest[23],
                     digest[24], digest[25], digest[26], digest[27], digest[28], digest[29],
                     digest[30], digest[31]];

  p.completedUnitCount++;
  [progress resignCurrent];
  return sha256;
}

@end
