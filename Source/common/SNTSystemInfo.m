/// Copyright 2015-2022 Google Inc. All rights reserved.
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

#import "Source/common/SNTSystemInfo.h"
#include <sys/sysctl.h>

@implementation SNTSystemInfo

+ (NSString *)serialNumber {
  static NSString *serial;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    io_service_t platformExpert = IOServiceGetMatchingService(
        kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"));
    if (!platformExpert) return;

    serial = CFBridgingRelease(IORegistryEntryCreateCFProperty(
        platformExpert, CFSTR(kIOPlatformSerialNumberKey), kCFAllocatorDefault, 0));

    IOObjectRelease(platformExpert);
  });
  return serial;
}

+ (NSString *)hardwareUUID {
  static NSString *uuid;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    io_service_t platformExpert = IOServiceGetMatchingService(
        kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"));
    if (!platformExpert) return;

    uuid = CFBridgingRelease(IORegistryEntryCreateCFProperty(
        platformExpert, CFSTR(kIOPlatformUUIDKey), kCFAllocatorDefault, 0));

    IOObjectRelease(platformExpert);
  });

  return uuid;
}

+ (NSString *)bootSessionUUID {
  static NSString *uuid;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    uuid_string_t bootSessionUUID = {};
    size_t uuidLength = sizeof(bootSessionUUID);
    // If this fails, bootSessionUUID is left as a fixed stack array of 0's,
    // so the line following will create a zero-length NSString. There's not
    // much we can really do if this fails, there are no other ways to get this
    // information.
    sysctlbyname("kern.bootsessionuuid", bootSessionUUID, &uuidLength, NULL, 0);
    uuid = @(bootSessionUUID);
  });
  return uuid;
}

+ (NSString *)osVersion {
  return [SNTSystemInfo _systemVersionDictionary][@"ProductVersion"];
}

+ (NSString *)osBuild {
  return [SNTSystemInfo _systemVersionDictionary][@"ProductBuildVersion"];
}

+ (NSString *)shortHostname {
  return [[[SNTSystemInfo longHostname] componentsSeparatedByString:@"."] firstObject];
}

+ (NSString *)longHostname {
  char hostname[MAXHOSTNAMELEN];
  gethostname(hostname, (int)sizeof(hostname));
  return @(hostname);
}

+ (NSString *)modelIdentifier {
  char model[32];
  size_t len = 32;
  sysctlbyname("hw.model", model, &len, NULL, 0);
  return @(model);
}

+ (NSString *)santaProductVersion {
  NSDictionary *info_dict = [[NSBundle mainBundle] infoDictionary];
  return info_dict[@"CFBundleShortVersionString"];
}

+ (NSString *)santaBuildVersion {
  NSDictionary *info_dict = [[NSBundle mainBundle] infoDictionary];
  return [[info_dict[@"CFBundleVersion"] componentsSeparatedByString:@"."] lastObject];
}

+ (NSString *)santaFullVersion {
  NSDictionary *info_dict = [[NSBundle mainBundle] infoDictionary];
  return info_dict[@"CFBundleVersion"];
}

#pragma mark - Internal

+ (NSDictionary *)_systemVersionDictionary {
  return [NSDictionary
      dictionaryWithContentsOfFile:@"/System/Library/CoreServices/SystemVersion.plist"];
}

@end
