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

#include "Source/common/Glob.h"

#include <glob.h>

#import "Source/common/SNTLogging.h"
#include "absl/cleanup/cleanup.h"

namespace santa {

void FindMatches(NSString *base, NSMutableArray<NSString *> *path_components, NSUInteger idx,
                 std::vector<std::string> &matches) {
  if (path_components.count == idx) {
    // Nothing left to match, add the current full base path
    matches.push_back(base.UTF8String);
    return;
  }

  NSString *path = [NSString stringWithFormat:@"%@%@", base, path_components[idx]];

  glob_t *g = (glob_t *)alloca(sizeof(glob_t));
  // Ensure gl_pathv is NULL so globfree can always safely be called
  g->gl_pathv = NULL;

  // Ensure globfree is always called
  absl::Cleanup glob_cleanup = ^{
    globfree(g);
  };

  int err = glob(path.UTF8String, GLOB_NOSORT, nullptr, g);
  if (err != 0 && err != GLOB_NOMATCH) {
    LOGE(@"Failed to generate path names from glob: %@", path);
    return;
  }

  if (g->gl_pathc == 0) {
    // If there were no hits...
    if ((g->gl_flags & GLOB_MAGCHAR) == 0) {
      // As long as there are no remaining magic chars in any of the path
      // components, we can add a watch item
      NSArray<NSString *> *remaining_components =
          (idx == path_components.count - 1)
              ? @[]
              : [path_components
                    subarrayWithRange:NSMakeRange(idx + 1, path_components.count - idx - 1)];
      NSString *remaining_path = [remaining_components componentsJoinedByString:@""];

      // Need to manually globfree here since we're about to re-glob
      globfree(g);
      glob(remaining_path.UTF8String, 0, NULL, g);
      if ((g->gl_flags & GLOB_MAGCHAR) == 0) {
        matches.push_back([NSString stringWithFormat:@"%@%@", path, remaining_path].UTF8String);
      }
    } else {
      // There was a magic char but no FS match. No paths will be watched.
    }
  } else {
    // For every subpath match, recurse into
    for (size_t i = g->gl_offs; i < g->gl_pathc; i++) {
      FindMatches(@(g->gl_pathv[i]), path_components, idx + 1, matches);
    }
  }
}

std::vector<std::string> FindMatches(NSString *path) {
  if (!path) {
    return {};
  }

  if (![path hasPrefix:@"/"]) {
    path = [NSString stringWithFormat:@"/%@", path];
  }

  glob_t *g = (glob_t *)alloca(sizeof(glob_t));
  // Ensure gl_pathv is NULL so globfree can always safely be called
  g->gl_pathv = NULL;

  // Ensure globfree is always called
  absl::Cleanup glob_cleanup = ^{
    globfree(g);
  };

  int err = glob(path.UTF8String, 0, nullptr, g);
  if (err != 0 && err != GLOB_NOMATCH) {
    LOGE(@"Failed to generate path names from glob: %@", path);
    return {};
  }

  // If the path had no glob char, begin watching it whether or not it exists
  if ((g->gl_flags & GLOB_MAGCHAR) == 0) {
    return {path.UTF8String};
  }

  NSArray<NSString *> *path_components = [path pathComponents];
  // Code above enforces the given path starts with a /, so must be at least two entries
  assert(path_components.count > 1);

  // Semi-arbitrary to prevent run away recursion. We could consider increasing this if
  // anyone ever has a good use case.
  if (path_components.count > 40) {
    LOGW(@"Glob path contained too many components, skipping: %@", path);
    return {};
  }

  // Modify each path component to have a trailing slash. This is to ensure that when path
  // components are appended for recursive glob searches, only directory results will be returned.
  NSMutableArray<NSString *> *modified_path_components = [NSMutableArray array];
  NSUInteger limit = [path hasSuffix:@"/"] ? path_components.count - 1 : path_components.count;
  for (NSUInteger i = 1; i < limit; i++) {
    // If adding the last component and the input doesn't end with a slash, don't append the slash
    if (i == limit - 1 && ![path hasSuffix:@"/"]) {
      [modified_path_components addObject:path_components[i]];
    } else {
      [modified_path_components addObject:[NSString stringWithFormat:@"%@/", path_components[i]]];
    }
  }

  std::vector<std::string> matches;
  FindMatches(@"/", modified_path_components, 0, matches);

  return matches;
}

}  // namespace santa
