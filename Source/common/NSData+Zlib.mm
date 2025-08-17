/// Copyright 2015 Google Inc. All rights reserved.
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

#import "Source/common/NSData+Zlib.h"

#include <zlib.h>

static constexpr NSUInteger kChunkSize = 16384;
static constexpr int kWindowSizeZlib = 15;
static constexpr int kWindowSizeGzip = kWindowSizeZlib + 16;

@implementation NSData (Zlib)

- (NSData *)compressIncludingGzipHeader:(BOOL)includeHeader {
  if ([self length]) {
    z_stream stream;
    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;
    stream.avail_in = (uint)[self length];
    stream.next_in = (Bytef *)[self bytes];
    stream.total_out = 0;
    stream.avail_out = 0;

    int windowSize = includeHeader ? kWindowSizeGzip : kWindowSizeZlib;

    if (deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, windowSize, 8,
                     Z_DEFAULT_STRATEGY) == Z_OK) {
      NSMutableData *data = [NSMutableData dataWithLength:kChunkSize];
      while (stream.avail_out == 0) {
        if (stream.total_out >= [data length]) {
          data.length += kChunkSize;
        }
        stream.next_out = (uint8_t *)[data mutableBytes] + stream.total_out;
        stream.avail_out = (uInt)([data length] - stream.total_out);
        deflate(&stream, Z_FINISH);
      }
      deflateEnd(&stream);
      data.length = stream.total_out;
      return data;
    }
  }
  return nil;
}

- (NSData *)decompressIncludingGzipHeader:(BOOL)includeHeader {
  if ([self length]) {
    z_stream stream;
    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;
    stream.avail_in = (uint)[self length];
    stream.next_in = (Bytef *)[self bytes];
    stream.total_out = 0;
    stream.avail_out = 0;

    int windowSize = includeHeader ? kWindowSizeGzip : kWindowSizeZlib;

    if (inflateInit2(&stream, windowSize) == Z_OK) {
      NSMutableData *data = [NSMutableData dataWithLength:kChunkSize];
      int status = Z_OK;

      while (status == Z_OK) {
        if (stream.total_out >= [data length]) {
          data.length += kChunkSize;
        }
        stream.next_out = (uint8_t *)[data mutableBytes] + stream.total_out;
        stream.avail_out = (uInt)([data length] - stream.total_out);
        status = inflate(&stream, Z_SYNC_FLUSH);
      }

      if (inflateEnd(&stream) == Z_OK) {
        if (status == Z_STREAM_END) {
          data.length = stream.total_out;
          return data;
        }
      }
    }
  }
  return nil;
}

- (NSData *)zlibCompressed {
  return [self compressIncludingGzipHeader:NO];
}

- (NSData *)gzipCompressed {
  return [self compressIncludingGzipHeader:YES];
}

- (NSData *)zlibDecompressed {
  return [self decompressIncludingGzipHeader:NO];
}

- (NSData *)gzipDecompressed {
  return [self decompressIncludingGzipHeader:YES];
}

@end
