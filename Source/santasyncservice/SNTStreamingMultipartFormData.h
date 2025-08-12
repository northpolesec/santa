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

#import <Foundation/Foundation.h>

@interface SNTStreamingMultipartFormData : NSObject

// Stream to provide to an HTTP request. The stream will be closed once all the
// data has been sent or if there is an error. The reply block is called on
// success or error. The caller is responsible for setting the stream queue,
// opening and closing.
@property(readonly) NSInputStream *stream;

// HTTP Content-Type
@property(readonly, nonatomic) NSString *contentType;

// The total content length, including the file to be streamed.
@property(readonly, nonatomic) NSUInteger contentLength;

// Creates a streaming HTTP multipart/form-data body
// (https://datatracker.ietf.org/doc/html/rfc7578). The form is built from the
// passed in formParts. The file is then streamed after the form.
- (instancetype)initWithFormParts:(NSDictionary<NSString *, NSString *> *)formParts
                             file:(NSFileHandle *)fd
                         fileName:(NSString *)fileName NS_DESIGNATED_INITIALIZER;
- (instancetype)init NS_UNAVAILABLE;

@end
