#import <XCTest/XCTest.h>
#import "ParquetLogger.h"

@interface PrefixTreeTest : XCTestCase
@end

@implementation PrefixTreeTest

// Currently, this just demonstrates that Rust code can be called into.
- (void)testBasic {
  XCTAssertFalse(BloomFilterContains(1338));
  XCTAssertTrue(BloomFilterContains(1337));
}

@end
