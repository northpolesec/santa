/// Copyright 2021-2022 Google Inc. All rights reserved.
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

#import "Source/santad/EventProviders/SNTEndpointSecurityDeviceManager.h"

#import <DiskArbitration/DiskArbitration.h>
#include <EndpointSecurity/EndpointSecurity.h>
#import <Foundation/Foundation.h>

#include <atomic>
#include <memory>

#include <bsm/libbsm.h>
#include <errno.h>
#include <libproc.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/ucred.h>

#import "Source/common/SNTDeviceEvent.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTMetricSet.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/Metrics.h"

using santa::AuthResultCache;
using santa::EndpointSecurityAPI;
using santa::EventDisposition;
using santa::FlushCacheMode;
using santa::FlushCacheReason;
using santa::Logger;
using santa::Message;

// Defined operations for startup metrics:
// Device shouldn't be operated on (e.g. not a mass storage device)
static NSString *const kMetricStartupDiskOperationSkip = @"Skipped";
// Device already had appropriate flags set
static NSString *const kMetricStartupDiskOperationAllowed = @"Allowed";
// Device failed to be unmounted
static NSString *const kMetricStartupDiskOperationUnmountFailed = @"UnmountFailed";
// Device failed to be remounted
static NSString *const kMetricStartupDiskOperationRemountFailed = @"RemountFailed";
// Remounts were requested, but remount args weren't set
static NSString *const kMetricStartupDiskOperationRemountSkipped = @"RemountSkipped";
// Operations on device matching the configured startup pref wwere successful
static NSString *const kMetricStartupDiskOperationSuccess = @"Success";

@interface SNTEndpointSecurityDeviceManager ()

- (void)logDiskAppeared:(NSDictionary *)props;
- (void)logDiskDisappeared:(NSDictionary *)props;

@property SNTMetricCounter *startupDiskMetrics;
@property DASessionRef diskArbSession;
@property(nonatomic, readonly) dispatch_queue_t diskQueue;
@property dispatch_semaphore_t diskSema;

@end

void DiskMountedCallback(DADiskRef disk, DADissenterRef dissenter, void *context) {
  if (dissenter) {
    DAReturn status = DADissenterGetStatus(dissenter);

    IOReturn systemCode = err_get_system(status);
    IOReturn subSystemCode = err_get_sub(status);
    IOReturn errorCode = err_get_code(status);

    LOGE(@"SNTEndpointSecurityDeviceManager: dissenter status codes: system: %d, subsystem: %d, "
         @"err: %d; status: %@",
         systemCode, subSystemCode, errorCode,
         CFBridgingRelease(DADissenterGetStatusString(dissenter)));
  }

  if (context) {
    dispatch_semaphore_t sema = (__bridge dispatch_semaphore_t)context;
    dispatch_semaphore_signal(sema);
  }
}

void DiskAppearedCallback(DADiskRef disk, void *context) {
  NSDictionary *props = CFBridgingRelease(DADiskCopyDescription(disk));
  if (![props[@"DAVolumeMountable"] boolValue]) return;
  SNTEndpointSecurityDeviceManager *dm = (__bridge SNTEndpointSecurityDeviceManager *)context;

  [dm logDiskAppeared:props];
}

void DiskDescriptionChangedCallback(DADiskRef disk, CFArrayRef keys, void *context) {
  NSDictionary *props = CFBridgingRelease(DADiskCopyDescription(disk));
  if (![props[@"DAVolumeMountable"] boolValue]) return;

  if (props[@"DAVolumePath"]) {
    SNTEndpointSecurityDeviceManager *dm = (__bridge SNTEndpointSecurityDeviceManager *)context;

    [dm logDiskAppeared:props];
  }
}

void DiskDisappearedCallback(DADiskRef disk, void *context) {
  NSDictionary *props = CFBridgingRelease(DADiskCopyDescription(disk));
  if (![props[@"DAVolumeMountable"] boolValue]) return;

  SNTEndpointSecurityDeviceManager *dm = (__bridge SNTEndpointSecurityDeviceManager *)context;

  [dm logDiskDisappeared:props];
}

void DiskUnmountCallback(DADiskRef disk, DADissenterRef dissenter, void *context) {
  if (dissenter) {
    LOGW(@"Unable to unmount device: %@", CFBridgingRelease(DADissenterGetStatusString(dissenter)));
  } else if (disk) {
    NSDictionary *diskInfo = CFBridgingRelease(DADiskCopyDescription(disk));
    LOGI(@"Unmounted device: Model: %@, Vendor: %@, Path: %@",
         diskInfo[(__bridge NSString *)kDADiskDescriptionDeviceModelKey],
         diskInfo[(__bridge NSString *)kDADiskDescriptionDeviceVendorKey],
         diskInfo[(__bridge NSString *)kDADiskDescriptionVolumePathKey]);
  }

  dispatch_semaphore_t sema = (__bridge dispatch_semaphore_t)context;
  dispatch_semaphore_signal(sema);
}

NSArray<NSString *> *maskToMountArgs(uint32_t remountOpts) {
  NSMutableArray<NSString *> *args = [NSMutableArray array];
  if (remountOpts & MNT_RDONLY) [args addObject:@"rdonly"];
  if (remountOpts & MNT_NOEXEC) [args addObject:@"noexec"];
  if (remountOpts & MNT_NOSUID) [args addObject:@"nosuid"];
  if (remountOpts & MNT_DONTBROWSE) [args addObject:@"nobrowse"];
  if (remountOpts & MNT_UNKNOWNPERMISSIONS) [args addObject:@"noowners"];
  if (remountOpts & MNT_NODEV) [args addObject:@"nodev"];
  if (remountOpts & MNT_JOURNALED) [args addObject:@"-j"];
  if (remountOpts & MNT_ASYNC) [args addObject:@"async"];
  return args;
}

uint32_t mountArgsToMask(NSArray<NSString *> *args) {
  uint32_t flags = 0;
  for (NSString *i in args) {
    NSString *arg = [i lowercaseString];
    if ([arg isEqualToString:@"rdonly"]) {
      flags |= MNT_RDONLY;
    } else if ([arg isEqualToString:@"noexec"]) {
      flags |= MNT_NOEXEC;
    } else if ([arg isEqualToString:@"nosuid"]) {
      flags |= MNT_NOSUID;
    } else if ([arg isEqualToString:@"nobrowse"]) {
      flags |= MNT_DONTBROWSE;
    } else if ([arg isEqualToString:@"noowners"]) {
      flags |= MNT_UNKNOWNPERMISSIONS;
    } else if ([arg isEqualToString:@"nodev"]) {
      flags |= MNT_NODEV;
    } else if ([arg isEqualToString:@"-j"]) {
      flags |= MNT_JOURNALED;
    } else if ([arg isEqualToString:@"async"]) {
      flags |= MNT_ASYNC;
    } else {
      LOGE(@"SNTEndpointSecurityDeviceManager: unexpected mount arg: %@", arg);
    }
  }
  return flags;
}

NS_ASSUME_NONNULL_BEGIN

@implementation SNTEndpointSecurityDeviceManager {
  std::shared_ptr<AuthResultCache> _authResultCache;
  std::shared_ptr<Logger> _logger;
}

- (instancetype)initWithESAPI:(std::shared_ptr<EndpointSecurityAPI>)esApi
                      metrics:(std::shared_ptr<santa::Metrics>)metrics
                       logger:(std::shared_ptr<Logger>)logger
              authResultCache:(std::shared_ptr<AuthResultCache>)authResultCache
                blockUSBMount:(BOOL)blockUSBMount
               remountUSBMode:(nullable NSArray<NSString *> *)remountUSBMode
           startupPreferences:(SNTDeviceManagerStartupPreferences)startupPrefs {
  self = [super initWithESAPI:std::move(esApi)
                      metrics:std::move(metrics)
                    processor:santa::Processor::kDeviceManager];
  if (self) {
    _logger = logger;
    _authResultCache = authResultCache;
    _blockUSBMount = blockUSBMount;
    _remountArgs = remountUSBMode;

    _diskQueue =
        dispatch_queue_create("com.northpolesec.santa.daemon.disk_queue", DISPATCH_QUEUE_SERIAL);

    _diskArbSession = DASessionCreate(NULL);
    DASessionSetDispatchQueue(_diskArbSession, _diskQueue);

    SNTMetricInt64Gauge *startupPrefsMetric = [[SNTMetricSet sharedInstance]
        int64GaugeWithName:@"/santa/device_manager/startup_preference"
                fieldNames:@[]
                  helpText:@"The current startup preference value"];

    [[SNTMetricSet sharedInstance] registerCallback:^{
      [startupPrefsMetric set:startupPrefs forFieldValues:@[]];
    }];

    _startupDiskMetrics = [[SNTMetricSet sharedInstance]
        counterWithName:@"/santa/device_manager/startup_disk_operation"
             fieldNames:@[ @"operation" ]
               helpText:@"Count of the number of USB devices encountered per operation"];

    [self performStartupTasks:startupPrefs];

    [self establishClientOrDie];
  }
  return self;
}

- (uint32_t)updatedMountFlags:(struct statfs *)sfs {
  uint32_t mask = sfs->f_flags | mountArgsToMask(self.remountArgs);

  // NB: APFS mounts get MNT_JOURNALED implicitly set. However, mount_apfs
  // does not support the `-j` option so this flag needs to be cleared.
  if (strncmp(sfs->f_fstypename, "apfs", sizeof(sfs->f_fstypename)) == 0) {
    mask &= ~MNT_JOURNALED;
  }

  return mask;
}

- (BOOL)shouldOperateOnDisk:(DADiskRef)disk {
  NSDictionary *diskInfo = CFBridgingRelease(DADiskCopyDescription(disk));

  BOOL isInternal = [diskInfo[(__bridge NSString *)kDADiskDescriptionDeviceInternalKey] boolValue];
  BOOL isRemovable = [diskInfo[(__bridge NSString *)kDADiskDescriptionMediaRemovableKey] boolValue];
  BOOL isEjectable = [diskInfo[(__bridge NSString *)kDADiskDescriptionMediaEjectableKey] boolValue];
  NSString *protocol = diskInfo[(__bridge NSString *)kDADiskDescriptionDeviceProtocolKey];
  BOOL isUSB = [protocol isEqualToString:@"USB"];
  BOOL isSecureDigital = [protocol isEqualToString:@"Secure Digital"];
  BOOL isVirtual = [protocol isEqualToString:@"Virtual Interface"];

  NSString *kind = diskInfo[(__bridge NSString *)kDADiskDescriptionMediaKindKey];

  // TODO: check kind and protocol for banned things (e.g. MTP).
  LOGD(@"SNTEndpointSecurityDeviceManager: DiskInfo Protocol: %@ Kind: %@ isInternal: %d "
       @"isRemovable: %d isEjectable: %d",
       protocol, kind, isInternal, isRemovable, isEjectable);

  // if the device is internal, or virtual *AND* is not an SD Card,
  // then allow the mount. This is to ensure we block SD cards inserted into
  // the internal reader of some Macs, whilst also ensuring we don't block
  // the internal storage device.
  if ((isInternal || isVirtual) && !isSecureDigital) {
    return false;
  }

  // We are okay with operations for devices that are non-removable as long as
  // they are NOT a USB device, or an SD Card.
  if (!isRemovable && !isEjectable && !isUSB && !isSecureDigital) {
    return false;
  }

  return true;
}

- (BOOL)haveRemountArgs {
  return [self.remountArgs count] > 0;
}

- (BOOL)remountUSBModeContainsFlags:(uint32_t)flags {
  if (![self haveRemountArgs]) {
    return false;
  }

  uint32_t requiredFlags = mountArgsToMask(self.remountArgs);

  LOGD(@" Got mount flags: 0x%08x | %@", flags, maskToMountArgs(flags));
  LOGD(@"Want mount flags: 0x%08x | %@", mountArgsToMask(self.remountArgs), self.remountArgs);

  return (flags & requiredFlags) == requiredFlags;
}

- (void)incrementStartupMetricsOperation:(NSString *)op {
  [self.startupDiskMetrics incrementForFieldValues:@[ op ]];
}

// NB: Remount options are implemented as separate "unmount" and "mount"
// operations instead of using the "update"/MNT_UPDATE flag. This is because
// filesystems often don't support many transitions (e.g. RW to RO). Performing
// the two step process has a higher chance of succeeding.
- (void)performStartupTasks:(SNTDeviceManagerStartupPreferences)startupPrefs {
  if (!self.blockUSBMount || (startupPrefs != SNTDeviceManagerStartupPreferencesUnmount &&
                              startupPrefs != SNTDeviceManagerStartupPreferencesForceUnmount &&
                              startupPrefs != SNTDeviceManagerStartupPreferencesRemount &&
                              startupPrefs != SNTDeviceManagerStartupPreferencesForceRemount)) {
    return;
  }

  struct statfs *mnts;
  int numMounts = getmntinfo_r_np(&mnts, MNT_WAIT);

  if (numMounts == 0) {
    LOGE(@"Failed to get mount info: %d: %s", errno, strerror(errno));
    return;
  }

  self.diskSema = dispatch_semaphore_create(0);

  for (int i = 0; i < numMounts; i++) {
    struct statfs *sfs = &mnts[i];

    DADiskRef disk = DADiskCreateFromBSDName(NULL, self.diskArbSession, sfs->f_mntfromname);
    if (!disk) {
      LOGW(@"Unable to create disk reference for device: '%s' -> '%s'", sfs->f_mntfromname,
           sfs->f_mntonname);
      continue;
    }

    CFAutorelease(disk);

    if (![self shouldOperateOnDisk:disk]) {
      [self incrementStartupMetricsOperation:kMetricStartupDiskOperationSkip];
      continue;
    }

    if ([self remountUSBModeContainsFlags:sfs->f_flags]) {
      LOGI(@"Allowing existing mount as flags contain RemountUSBMode. '%s' -> '%s'",
           sfs->f_mntfromname, sfs->f_mntonname);
      [self incrementStartupMetricsOperation:kMetricStartupDiskOperationAllowed];
      continue;
    }

    DADiskUnmountOptions unmountOptions = kDADiskUnmountOptionDefault;
    if (startupPrefs == SNTDeviceManagerStartupPreferencesForceUnmount ||
        startupPrefs == SNTDeviceManagerStartupPreferencesForceRemount) {
      unmountOptions = kDADiskUnmountOptionForce;
    }

    LOGI(@"Attempting to unmount device: '%s' mounted on '%s'", sfs->f_mntfromname,
         sfs->f_mntonname);

    DADiskUnmount(disk, unmountOptions, DiskUnmountCallback, (__bridge void *)self.diskSema);

    if (dispatch_semaphore_wait(self.diskSema,
                                dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC))) {
      LOGW(@"Unmounting '%s' mounted on '%s' took longer than expected. Device may still be "
           @"mounted.",
           sfs->f_mntfromname, sfs->f_mntonname);
      [self incrementStartupMetricsOperation:kMetricStartupDiskOperationUnmountFailed];
      continue;
    }

    if (startupPrefs == SNTDeviceManagerStartupPreferencesRemount ||
        startupPrefs == SNTDeviceManagerStartupPreferencesForceRemount) {
      if (![self haveRemountArgs]) {
        [self incrementStartupMetricsOperation:kMetricStartupDiskOperationRemountSkipped];
        LOGW(@"Remount requested during startup, but no remount args set. Leaving unmounted.");
        continue;
      }

      uint32_t newMode = [self updatedMountFlags:sfs];
      LOGI(@"Attempting to mount device again changing flags: 0x%08x --> 0x%08x", sfs->f_flags,
           newMode);

      [self remount:disk mountMode:newMode semaphore:self.diskSema];

      if (dispatch_semaphore_wait(self.diskSema,
                                  dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC))) {
        LOGW(@"Failed to remount device after unmounting: %s", sfs->f_mntfromname);
        [self incrementStartupMetricsOperation:kMetricStartupDiskOperationRemountFailed];
        continue;
      }
    }

    [self incrementStartupMetricsOperation:kMetricStartupDiskOperationSuccess];
  }
}

- (void)logDiskAppeared:(NSDictionary *)props {
  self->_logger->LogDiskAppeared(props);
}

- (void)logDiskDisappeared:(NSDictionary *)props {
  self->_logger->LogDiskDisappeared(props);
}

- (NSString *)description {
  return @"Device Manager";
}

- (void)handleMessage:(Message &&)esMsg
    recordEventMetrics:(void (^)(EventDisposition))recordEventMetrics {
  // Process the unmount event first so that caches are flushed before any
  // other potential early returns.
  if (esMsg->event_type == ES_EVENT_TYPE_NOTIFY_UNMOUNT) {
    self->_authResultCache->FlushCache(FlushCacheMode::kNonRootOnly,
                                       FlushCacheReason::kFilesystemUnmounted);
    recordEventMetrics(EventDisposition::kProcessed);
    return;
  }

  if (!self.blockUSBMount) {
    // TODO: We should also unsubscribe from events when this isn't set, but
    // this is generally a low-volume event type.
    [self respondToMessage:esMsg withAuthResult:ES_AUTH_RESULT_ALLOW cacheable:false];
    recordEventMetrics(EventDisposition::kDropped);
    return;
  }

  [self processMessage:std::move(esMsg)
               handler:^(Message msg) {
                 es_auth_result_t result = [self handleAuthMount:msg];
                 [self respondToMessage:msg withAuthResult:result cacheable:false];
                 recordEventMetrics(EventDisposition::kProcessed);
               }];
}

- (void)enable {
  DARegisterDiskAppearedCallback(_diskArbSession, NULL, DiskAppearedCallback,
                                 (__bridge void *)self);
  DARegisterDiskDescriptionChangedCallback(_diskArbSession, NULL, NULL,
                                           DiskDescriptionChangedCallback, (__bridge void *)self);
  DARegisterDiskDisappearedCallback(_diskArbSession, NULL, DiskDisappearedCallback,
                                    (__bridge void *)self);

  [super subscribeAndClearCache:{
                                    ES_EVENT_TYPE_AUTH_MOUNT,
                                    ES_EVENT_TYPE_AUTH_REMOUNT,
                                    ES_EVENT_TYPE_NOTIFY_UNMOUNT,
  }];
}

- (es_auth_result_t)handleAuthMount:(const Message &)m {
  struct statfs *eventStatFS;

  switch (m->event_type) {
    case ES_EVENT_TYPE_AUTH_MOUNT: eventStatFS = m->event.mount.statfs; break;
    case ES_EVENT_TYPE_AUTH_REMOUNT: eventStatFS = m->event.remount.statfs; break;
    default:
      // This is a programming error
      LOGE(@"Unexpected Event Type passed to DeviceManager handleAuthMount: %d", m->event_type);
      exit(EXIT_FAILURE);
  }

  pid_t pid = audit_token_to_pid(m->process->audit_token);
  LOGD(@"SNTEndpointSecurityDeviceManager: mount syscall arriving from path: %s, pid: %d, fflags: "
       @"%u",
       m->process->executable->path.data, pid, eventStatFS->f_flags);

  DADiskRef disk = DADiskCreateFromBSDName(NULL, self.diskArbSession, eventStatFS->f_mntfromname);
  CFAutorelease(disk);

  if (![self shouldOperateOnDisk:disk]) {
    return ES_AUTH_RESULT_ALLOW;
  }

  SNTDeviceEvent *event = [[SNTDeviceEvent alloc]
      initWithOnName:[NSString stringWithUTF8String:eventStatFS->f_mntonname]
            fromName:[NSString stringWithUTF8String:eventStatFS->f_mntfromname]];

  if ([self haveRemountArgs]) {
    event.remountArgs = self.remountArgs;

    if ([self remountUSBModeContainsFlags:eventStatFS->f_flags] &&
        m->event_type != ES_EVENT_TYPE_AUTH_REMOUNT) {
      LOGD(@"Allowing mount as flags contain RemountUSBMode. '%s' -> '%s'",
           eventStatFS->f_mntfromname, eventStatFS->f_mntonname);
      return ES_AUTH_RESULT_ALLOW;
    }

    uint32_t newMode = [self updatedMountFlags:eventStatFS];
    LOGI(@"SNTEndpointSecurityDeviceManager: remounting device '%s'->'%s', flags (%u) -> (%u)",
         eventStatFS->f_mntfromname, eventStatFS->f_mntonname, eventStatFS->f_flags, newMode);
    [self remount:disk mountMode:newMode semaphore:nil];
  }

  if (self.deviceBlockCallback) {
    self.deviceBlockCallback(event);
  }

  return ES_AUTH_RESULT_DENY;
}

- (void)remount:(DADiskRef)disk
      mountMode:(uint32_t)remountMask
      semaphore:(nullable dispatch_semaphore_t)sema {
  NSArray<NSString *> *args = maskToMountArgs(remountMask);
  CFStringRef *argv = (CFStringRef *)calloc(args.count + 1, sizeof(CFStringRef));
  CFArrayGetValues((__bridge CFArrayRef)args, CFRangeMake(0, (CFIndex)args.count),
                   (const void **)argv);

  DADiskMountWithArguments(disk, NULL, kDADiskMountOptionDefault, DiskMountedCallback,
                           (__bridge void *)sema, (CFStringRef *)argv);

  free(argv);
}

@end

NS_ASSUME_NONNULL_END
