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

#import "Source/santabundleservice/SNTBundleService.h"

#import <CommonCrypto/CommonDigest.h>
#import <pthread/pthread.h>

#import <algorithm>
#import <atomic>
#import <vector>

#include "Source/common/Glob.h"
#import "Source/common/MOLCodesignChecker.h"
#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTFileInfo.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTStoredExecutionEvent.h"
#import "Source/common/SNTXPCNotifierInterface.h"
#import "Source/common/SigningIDHelpers.h"

@interface SNTBundleService ()
@property(nonatomic) dispatch_queue_t queue;
// Serializes the shared mutable state the concurrent bundle scan writes to. Previously the main
// queue was used for this, which made bundle hashing contend with -- and stall -- this process's
// UI thread for no reason. A private serial queue gives the same mutual exclusion off it.
@property(nonatomic) dispatch_queue_t stateQueue;
@end

@implementation SNTBundleService

- (instancetype)init {
  self = [super init];
  if (self) {
    _queue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0);
    _stateQueue =
        dispatch_queue_create_with_target("com.northpolesec.santa.bundleservice.state",
                                          DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL, _queue);
  }
  return self;
}

#pragma mark SNTBundleServiceXPC Methods

- (void)hashBundleBinariesForEvent:(SNTStoredExecutionEvent*)event
                          listener:(NSXPCListenerEndpoint*)listener
                             reply:(SNTBundleHashBlock)reply {
  NSProgress* progress =
      [NSProgress currentProgress] ? [NSProgress progressWithTotalUnitCount:100] : nil;

  NSDate* startTime = [NSDate date];

  dispatch_semaphore_t sema = dispatch_semaphore_create(0);

  // Connect back to the client.
  MOLXPCConnection* clientListener;
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
    SNTFileInfo* b = [[SNTFileInfo alloc] initWithPath:event.fileBundlePath];
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

    NSDictionary* relatedEvents = [self findRelatedBinaries:event
                                                   progress:progress
                                             clientListener:clientListener];
    NSString* bundleHash = [self calculateBundleHashFromSHA256Hashes:relatedEvents.allKeys
                                                            progress:progress];
    NSNumber* ms = [NSNumber numberWithDouble:[startTime timeIntervalSinceNow] * -1000.0];

    reply(bundleHash, relatedEvents.allValues, ms);
    dispatch_semaphore_signal(sema);
  });

  // Master timeout of 10 min. Don't block the calling thread. NSProgress updates will be coming
  // in over this thread.
  dispatch_async(self.queue, ^{
    if (dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 600 * NSEC_PER_SEC))) {
      [progress cancel];
    }
  });
}

- (void)generateEventsFromPath:(NSString*)path
                 enableBundles:(BOOL)enableBundles
                         reply:(void (^)(NSArray<SNTStoredExecutionEvent*>* events))reply {
  dispatch_async(self.queue, ^{
    NSMutableArray<SNTStoredExecutionEvent*>* allEvents = [NSMutableArray array];

    std::vector<std::string> matches = santa::FindMatches(path);
    for (const auto& match : matches) {
      @autoreleasepool {
        NSString* matchPath = @(match.c_str());
        SNTFileInfo* fi = [[SNTFileInfo alloc] initWithPath:matchPath];
        if (!fi) continue;

        SNTStoredExecutionEvent* se = [[SNTStoredExecutionEvent alloc] initWithFileInfo:fi];
        if (!se) continue;
        se.decision = SNTEventStateBundleBinary;

        BOOL includePrimaryEvent = YES;
        if (enableBundles && fi.bundle) {
          se.fileBundlePath = fi.bundlePath;

          // Use the highest bundle we can find.
          SNTFileInfo* b = [[SNTFileInfo alloc] initWithPath:se.fileBundlePath];
          b.useAncestorBundle = YES;
          se.fileBundlePath = b.bundlePath;

          if (se.fileBundlePath) {
            se.fileBundleID = b.bundleIdentifier;
            se.fileBundleName = b.bundleName;
            se.fileBundleVersion = b.bundleVersion;
            se.fileBundleVersionString = b.bundleShortVersionString;

            if (b.bundle.executablePath.length > b.bundlePath.length) {
              se.fileBundleExecutableRelPath =
                  [b.bundle.executablePath substringFromIndex:b.bundlePath.length + 1];
            }

            NSDate* startTime = [NSDate date];
            NSDictionary* relatedEvents = [self findRelatedBinaries:se
                                                           progress:nil
                                                     clientListener:nil];
            NSString* bundleHash = [self calculateBundleHashFromSHA256Hashes:relatedEvents.allKeys
                                                                    progress:nil];
            NSNumber* ms = [NSNumber numberWithDouble:[startTime timeIntervalSinceNow] * -1000.0];

            NSNumber* bundleCount = @(relatedEvents.count);
            for (SNTStoredExecutionEvent* e in relatedEvents.allValues) {
              e.fileBundleHash = bundleHash;
              e.fileBundleHashMilliseconds = ms;
              e.fileBundleBinaryCount = bundleCount;
            }
            if (relatedEvents[se.fileSHA256]) {
              includePrimaryEvent = NO;
            } else {
              se.fileBundleHash = bundleHash;
              se.fileBundleHashMilliseconds = ms;
              se.fileBundleBinaryCount = bundleCount;
            }
            [allEvents addObjectsFromArray:relatedEvents.allValues];
          }
        }

        if (includePrimaryEvent) {
          [allEvents addObject:se];
        }
      }
    }

    reply(allEvents);
  });
}

#pragma mark Internal Methods

/**
  Find binaries within a bundle given the bundle's event. It will run until a timeout occurs,
  or until the NSProgress is cancelled. Search is done within the bundle concurrently.

  @param event The SNTStoredExecutionEvent to begin searching.
  @return An NSDictionary object with keys of fileSHA256 and values of SNTStoredExecutionEvent
  objects.
*/
- (NSDictionary*)findRelatedBinaries:(SNTStoredExecutionEvent*)event
                            progress:(NSProgress*)progress
                      clientListener:(MOLXPCConnection*)clientListener {
  // Find all files and folders within the fileBundlePath
  NSFileManager* fm = [NSFileManager defaultManager];
  NSArray* subpaths = [fm subpathsOfDirectoryAtPath:event.fileBundlePath error:NULL];

  // This array is used to store pointers to executable SNTFileInfo objects. There will be one block
  // dispatched per file in dirEnum. These blocks will write pointers to this array concurrently.
  // No locks are used since every file has a slot.
  //
  // Xcode.app has roughly 500k files, 8bytes per pointer is ~4MB for this array. This size to space
  // ratio seems appropriate as Xcode.app is in the upper bounds of bundle size.
  //
  // dispatch_apply is synchronous, so the block cannot outlive this scope: these are plain locals
  // captured by pointer rather than __block shared_ptrs. The vector still keeps its elements on the
  // heap, so nothing large lands on the stack. (Removing the per-file main-queue hop below also
  // removed the synchronization edge that was hiding the __block/shared_ptr capture from
  // ThreadSanitizer; capturing by pointer needs no such edge to be obviously correct.)
  std::vector<SNTFileInfo*> fis(subpaths.count);
  auto* fisPtr = &fis;

  // Counts used as additional progress information in SantaGUI
  std::atomic<int64_t> binaryCount{0};
  std::atomic<int64_t> completedUnits{0};
  // Highest count already reported to the GUI. Only ever written on stateQueue, and only ever
  // forward; atomic so the per-file fast path below can read it without taking that queue.
  std::atomic<int64_t> reportedUnits{0};
  auto* binaryCountPtr = &binaryCount;
  auto* completedUnitsPtr = &completedUnits;
  auto* reportedUnitsPtr = &reportedUnits;

  // Report every 1% of work, as before, but derived once rather than recomputed per file. Also
  // makes the throttle independent of `p`, which fixes a flood when `progress` is nil: the old
  // condition compared against `p.completedUnitCount`, and messaging nil always returns 0, so
  // past the 1% mark it reported on every single file.
  const int64_t reportInterval = std::max<int64_t>(1, (int64_t)subpaths.count / 100);

  // Account for 80% of the work
  NSProgress* p;
  if (progress) {
    [progress becomeCurrentWithPendingUnitCount:80];
    p = [NSProgress progressWithTotalUnitCount:subpaths.count * 100];
  }

  // Dispatch a block for every file in dirEnum.
  dispatch_apply(subpaths.count, self.queue, ^(size_t i) {
    @autoreleasepool {
      if (progress.isCancelled) return;

      // Update the UI for every 1% of work completed.
      //
      // This used to hop to the main queue for every file, purely to serialize the throttle
      // check. For Xcode.app that is ~120k blocking round trips through the main thread, which
      // serialized this otherwise-concurrent dispatch_apply and made the main thread the
      // bottleneck for the whole scan. The per-file cost is now a lock-free atomic read; only a
      // worker that actually crosses a boundary takes a queue, and never the main one.
      int64_t done = completedUnitsPtr->fetch_add(1) + 1;
      if (done - reportedUnitsPtr->load() >= reportInterval) {
        // Claim and publish together. An atomic compare-exchange would pick one reporter per
        // boundary but would not order the publish that follows it: a worker preempted between
        // claiming 5000 and sending it lands after a worker that already sent 10000, and both
        // the progress bar and the GUI's file count jump backwards -- a visible flicker on
        // exactly the large bundles this throttle exists for. Serializing the pair keeps both
        // monotonic. Reached ~100 times, not once per file.
        dispatch_sync(self.stateQueue, ^{
          // Re-check under serialization: a larger claim may have landed while this worker was
          // waiting, in which case this one is stale and must not publish.
          if (done - reportedUnitsPtr->load() < reportInterval) return;
          reportedUnitsPtr->store(done);
          p.completedUnitCount = done;
          // fileCount is how many have been scanned, not `i`: dispatch_apply does not hand out
          // indices in order, so `i` made the displayed count jump around.
          [[clientListener remoteObjectProxy] updateCountsForEvent:event
                                                       binaryCount:binaryCountPtr->load()
                                                         fileCount:done
                                                       hashedCount:0];
        });
      }

      NSString* subpath = subpaths[i];

      NSString* file =
          [event.fileBundlePath stringByAppendingPathComponent:subpath].stringByStandardizingPath;
      SNTFileInfo* fi = [[SNTFileInfo alloc] initWithResolvedPath:file error:NULL];
      if (!fi.isExecutable) return;

      fisPtr->at(i) = fi;
      binaryCountPtr->fetch_add(1);
    }
  });

  [progress resignCurrent];

  NSMutableArray* fileInfos = [NSMutableArray arrayWithCapacity:binaryCount.load()];
  for (NSUInteger i = 0; i < subpaths.count; i++) {
    if (fis.at(i)) [fileInfos addObject:fis.at(i)];
  }

  return [self generateEventsFromBinaries:fileInfos
                            blockingEvent:event
                                 progress:progress
                           clientListener:clientListener];
}

- (NSDictionary*)generateEventsFromBinaries:(NSArray*)fis
                              blockingEvent:(SNTStoredExecutionEvent*)event
                                   progress:(NSProgress*)progress
                             clientListener:(MOLXPCConnection*)clientListener {
  if (progress.isCancelled) return nil;

  NSMutableDictionary* relatedEvents = [NSMutableDictionary dictionaryWithCapacity:fis.count];

  // Account for 15% of the work
  NSProgress* p;
  if (progress) {
    [progress becomeCurrentWithPendingUnitCount:15];
    p = [NSProgress progressWithTotalUnitCount:fis.count * 100];
  }

  // Throttle GUI updates to every 1% of work, matching -findRelatedBinaries: above. Unthrottled,
  // this sent one XPC message per binary -- 1822 of them for Xcode.app -- and each one lands on
  // the GUI's main thread and re-renders the notification window, pinning that main thread for
  // tens of seconds (beachball, unresponsive status item) while a large bundle is hashed.
  // Both counters are only ever touched on stateQueue below, so no atomics needed.
  __block int64_t completedBinaries = 0;
  __block int64_t reportedBinaries = 0;

  dispatch_apply(fis.count, self.queue, ^(size_t i) {
    @autoreleasepool {
      if (progress.isCancelled) return;

      SNTFileInfo* fi = fis[i];

      SNTStoredExecutionEvent* se = [[SNTStoredExecutionEvent alloc] initWithFileInfo:fi];
      se.decision = SNTEventStateBundleBinary;
      se.fileBundlePath = event.fileBundlePath;
      se.fileBundleExecutableRelPath = event.fileBundleExecutableRelPath;
      se.fileBundleID = event.fileBundleID;
      se.fileBundleName = event.fileBundleName;
      se.fileBundleVersion = event.fileBundleVersion;
      se.fileBundleVersionString = event.fileBundleVersionString;

      // stateQueue, not the main queue: this only needs mutual exclusion for the dictionary
      // write and the two counters, which is no reason to involve the UI thread.
      dispatch_sync(self.stateQueue, ^{
        relatedEvents[se.fileSHA256] = se;
        p.completedUnitCount++;
        completedBinaries++;
        // hashedCount reports how many are done, not `i`: dispatch_apply does not hand out
        // indices in order, so `i` made the displayed count jump around.
        if (progress &&
            ((double)(completedBinaries - reportedBinaries) / (double)fis.count) > 0.01) {
          reportedBinaries = completedBinaries;
          [[clientListener remoteObjectProxy] updateCountsForEvent:event
                                                       binaryCount:fis.count
                                                         fileCount:0
                                                       hashedCount:completedBinaries];
        }
      });
    }
  });

  [progress resignCurrent];

  return relatedEvents;
}

- (NSString*)calculateBundleHashFromSHA256Hashes:(NSArray*)hashes progress:(NSProgress*)progress {
  if (!hashes.count) return nil;

  // Account for 5% of the work
  NSProgress* p;
  if (progress) {
    [progress becomeCurrentWithPendingUnitCount:5];
    p = [NSProgress progressWithTotalUnitCount:5 * 100];
  }

  NSMutableArray* sortedHashes = [hashes mutableCopy];
  [sortedHashes sortUsingSelector:@selector(localizedCaseInsensitiveCompare:)];
  NSString* sha256Hashes = [sortedHashes componentsJoinedByString:@""];

  CC_SHA256_CTX c256;
  CC_SHA256_Init(&c256);
  CC_SHA256_Update(&c256, (const void*)sha256Hashes.UTF8String, (CC_LONG)sha256Hashes.length);
  unsigned char digest[CC_SHA256_DIGEST_LENGTH];
  CC_SHA256_Final(digest, &c256);

  NSString* const SHA256FormatString =
      @"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
       "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x";

  NSString* sha256 = [[NSString alloc]
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
