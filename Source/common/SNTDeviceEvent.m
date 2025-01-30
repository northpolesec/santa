#import "Source/common/SNTDeviceEvent.h"

#import "Source/common/CoderMacros.h"

@implementation SNTDeviceEvent

- (instancetype)initWithOnName:(NSString *)mntonname fromName:(NSString *)mntfromname {
  self = [super init];
  if (self) {
    _mntonname = mntonname;
    _mntfromname = mntfromname;
  }
  return self;
}

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder {
  ENCODE(coder, mntonname);
  ENCODE(coder, mntfromname);
  ENCODE(coder, remountArgs);
}

- (instancetype)initWithCoder:(NSCoder *)decoder {
  self = [super init];
  if (self) {
    DECODE(decoder, mntonname, NSString);
    DECODE(decoder, mntfromname, NSString);
    DECODE_ARRAY(decoder, remountArgs, NSString);
  }
  return self;
}
- (NSString *)description {
  return [NSString stringWithFormat:@"SNTDeviceEvent '%@' -> '%@' (with permissions: [%@]",
                                    self.mntfromname, self.mntonname,
                                    [self.remountArgs componentsJoinedByString:@", "]];
}

- (NSString *)readableRemountArgs {
  NSMutableArray<NSString *> *readable = [NSMutableArray array];
  for (NSString *arg in self.remountArgs) {
    if ([arg isEqualToString:@"rdonly"]) {
      [readable addObject:@"read-only"];
    } else if ([arg isEqualToString:@"noexec"]) {
      [readable addObject:@"block executables"];
    } else {
      [readable addObject:arg];
    }
  }
  return [readable componentsJoinedByString:@", "];
}

@end
