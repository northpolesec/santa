#import <Foundation/Foundation.h>

@interface SNTMdmConfigSource : NSObject

- (int)appValueIsForced:(NSString *)key;

- (id)copyAppValue:(NSString *)key;

@end