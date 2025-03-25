#import "Source/common/SNTMdmConfigSource.h"

@interface SNTMdmConfigSource ()
@end

/// The domain used by mobileconfig.
static const CFStringRef kMobileConfigDomain = CFSTR("com.northpolesec.santa");

@implementation SNTMdmConfigSource

- (int)appValueIsForced:(NSString *)key {
  CFStringRef keyRef = (__bridge CFStringRef)key;
  return CFPreferencesAppValueIsForced(keyRef, kMobileConfigDomain);
}

- (id)copyAppValue:(NSString *)key {
  CFStringRef keyRef = (__bridge CFStringRef)key;
  return CFBridgingRelease(CFPreferencesCopyAppValue(keyRef, kMobileConfigDomain));
}

@end