/// Copyright 2026 North Pole Security, Inc.
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

#import "Source/common/SNTLiteDetector.h"
#import "Source/common/SNTCommonEnums.h"

namespace santa {

BOOL SNTIsLiteAppBundle(NSString *appPath) {
  NSString *plistPath = [appPath stringByAppendingPathComponent:@"Contents/Info.plist"];
  NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:plistPath];
  return [plist[@"SNTIsLite"] boolValue];
}

BOOL SNTIsLiteInstall(void) {
  static BOOL isLite;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    isLite = SNTIsLiteAppBundle(@(kSantaAppPath));
  });
  return isLite;
}

}  // namespace santa
