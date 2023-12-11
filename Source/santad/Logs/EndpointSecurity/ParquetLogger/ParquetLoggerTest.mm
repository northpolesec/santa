#import <XCTest/XCTest.h>
#import "ParquetLogger.h"

@interface ParquetLoggerTest : XCTestCase
@end

@implementation ParquetLoggerTest

// Currently, this just demonstrates that Rust code can be called into.
- (void)testBasic {
  XCTAssertFalse(BloomFilterContains(1338));
  XCTAssertTrue(BloomFilterContains(1337));
}

@end
