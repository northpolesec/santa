/// Copyright 2022 Google LLC
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

#include "Source/santad/Logs/EndpointSecurity/Serializers/Utilities.h"

#include <sys/mount.h>
#include <sys/param.h>

#include "Source/common/SantaCache.h"
#import "Source/common/SantaVnode.h"
#include "Source/common/String.h"

// These functions are exported by the Security framework, but are not included in headers
extern "C" Boolean SecTranslocateIsTranslocatedURL(CFURLRef path, bool *isTranslocated,
                                                   CFErrorRef *__nullable error);
extern "C" CFURLRef __nullable SecTranslocateCreateOriginalPathForURL(CFURLRef translocatedPath,
                                                                      CFErrorRef *__nullable error);

using santa::Message;

namespace santa {

NSString *OriginalPathForTranslocation(const es_process_t *es_proc) {
  // Cache vnodes that have been determined to not be translocated
  static SantaCache<SantaVnode, bool> isNotTranslocatedCache(1024);

  if (!es_proc) {
    return nil;
  }

  if (isNotTranslocatedCache.get(SantaVnode::VnodeForFile(es_proc->executable))) {
    return nil;
  }

  // Note: Benchmarks showed better performance using `URLWithString` with a `file://` prefix
  // compared to using `fileURLWithPath`.
  CFURLRef cfExecURL = (__bridge CFURLRef)[NSURL
      URLWithString:[NSString stringWithFormat:@"file://%s", es_proc->executable->path.data]];
  NSURL *origURL = nil;
  bool isTranslocated = false;

  if (SecTranslocateIsTranslocatedURL(cfExecURL, &isTranslocated, NULL) && isTranslocated) {
    origURL = CFBridgingRelease(SecTranslocateCreateOriginalPathForURL(cfExecURL, NULL));
  } else {
    isNotTranslocatedCache.set(SantaVnode::VnodeForFile(es_proc->executable), true);
  }

  return [origURL path];
}

const mach_port_t GetDefaultIOKitCommsPort() {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
  return kIOMasterPortDefault;
#pragma clang diagnostic pop
}

NSString *SerialForDevice(NSString *devPath) {
  if (!devPath.length) {
    return nil;
  }
  NSString *serial;
  io_registry_entry_t device =
      IORegistryEntryFromPath(GetDefaultIOKitCommsPort(), devPath.UTF8String);
  while (!serial && device) {
    CFMutableDictionaryRef device_properties = NULL;
    IORegistryEntryCreateCFProperties(device, &device_properties, kCFAllocatorDefault, kNilOptions);
    NSDictionary *properties = CFBridgingRelease(device_properties);
    if (properties[@"Serial Number"]) {
      serial = properties[@"Serial Number"];
    } else if (properties[@"kUSBSerialNumberString"]) {
      serial = properties[@"kUSBSerialNumberString"];
    }

    if (serial) {
      IOObjectRelease(device);
      break;
    }

    io_registry_entry_t parent;
    IORegistryEntryGetParentEntry(device, kIOServicePlane, &parent);
    IOObjectRelease(device);
    device = parent;
  }

  return [serial stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
}

NSString *MountFromName(NSString *path) {
  if (!path.length) {
    return nil;
  }

  struct statfs sfs;

  if (statfs(path.UTF8String, &sfs) != 0) {
    return nil;
  }

  NSString *mntFromName = santa::StringToNSString(sfs.f_mntfromname);

  return mntFromName.length > 0 ? mntFromName : nil;
}

static NSDictionary *PropertiesForDevice(NSString *devPath) {
  if (!devPath.length) {
    return nil;
  }

  io_registry_entry_t device =
      IORegistryEntryFromPath(GetDefaultIOKitCommsPort(), devPath.UTF8String);
  CFMutableDictionaryRef device_properties = NULL;
  IORegistryEntryCreateCFProperties(device, &device_properties, kCFAllocatorDefault, kNilOptions);
  NSDictionary *properties = CFBridgingRelease(device_properties);
  IOObjectRelease(device);
  return properties;
}

NSString *DiskImageForDevice(NSString *devPath) {
  NSString *result;

  // First, lookup properties of the full given path then look for either the
  // DiskImageURL or Virtual Interface Location Path keys. Since at least
  // macOS 13, these keys work for both DiskImageMounter and `hdiutil attach`.
  NSDictionary *properties = PropertiesForDevice(devPath);

  if ([properties[@"DiskImageURL"] isKindOfClass:[NSString class]]) {
    // Note: This is often a file URL. Check and convert to a path to have
    // consistent output compared to the other properties.
    result = properties[@"DiskImageURL"];
    if ([result hasPrefix:@"file://"]) {
      result = [[NSURL URLWithString:result] path];
    }
  } else if ([properties[@"Protocol Characteristics"] isKindOfClass:[NSDictionary class]] &&
             [properties[@"Protocol Characteristics"][@"Virtual Interface Location Path"]
                 isKindOfClass:[NSData class]]) {
    result = [[NSString alloc]
        initWithData:properties[@"Protocol Characteristics"][@"Virtual Interface Location Path"]
            encoding:NSUTF8StringEncoding];
  } else {
    // Fallback to the old Santa method which used to more broadly work on older
    // macOS versions (<v13), but still works on macOS 13+ when mounting via
    // `hdiutil attach` only. This method tries to get the image-path property
    // of the parent device of the given device path.
    properties = PropertiesForDevice([devPath stringByDeletingLastPathComponent]);
    if (properties[@"image-path"]) {
      result = [[NSString alloc] initWithData:properties[@"image-path"]
                                     encoding:NSUTF8StringEncoding];
    }
  }

  return [result stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
}

es_file_t *GetAllowListTargetFile(const Message &msg) {
  switch (msg->event_type) {
    case ES_EVENT_TYPE_NOTIFY_CLOSE: return msg->event.close.target;
    case ES_EVENT_TYPE_NOTIFY_RENAME: return msg->event.rename.source;
    default:
      // This is a programming error
      [NSException raise:@"Unexpected type"
                  format:@"Unexpected event type for AllowList: %d", msg->event_type];
      return nil;
  }
}

}  // namespace santa
