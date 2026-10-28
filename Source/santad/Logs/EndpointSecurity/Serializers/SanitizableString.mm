/// Copyright 2022 Google Inc. All rights reserved.
/// Copyright 2026 North Pole Security, Inc.
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

#include "Source/santad/Logs/EndpointSecurity/Serializers/SanitizableString.h"

#include <array>

#include "Source/common/String.h"

using santa::NSStringToUTF8StringView;

namespace santa {

namespace {

constexpr std::array<bool, 256> kNeedsEscape = [] {
  std::array<bool, 256> t{};
  t['|'] = t['\n'] = t['\r'] = true;
  return t;
}();

}  // namespace

void AppendSanitized(std::string& dst, std::string_view src) {
  size_t start = 0;
  for (size_t i = 0; i < src.size(); ++i) {
    unsigned char c = src[i];
    if (!kNeedsEscape[c]) {
      continue;
    }

    dst.append(src.substr(start, i - start));
    switch (c) {
      case '|': dst.append("<pipe>"); break;
      case '\n': dst.append("\\n"); break;
      case '\r': dst.append("\\r"); break;
    }
    start = i + 1;
  }

  dst.append(src.substr(start));
}

void AppendSanitized(std::string& dst, const es_file_t* file) {
  AppendSanitized(dst, std::string_view(file->path.data, file->path.length));
}

void AppendSanitized(std::string& dst, const es_string_token_t& tok) {
  AppendSanitized(dst, std::string_view(tok.data, tok.length));
}

void AppendSanitized(std::string& dst, NSString* str) {
  AppendSanitized(dst, NSStringToUTF8StringView(str));
}

}  // namespace santa
