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

#ifndef SANTA__SANTAD__EVENTPROVIDERS_FAAPOLICYPROCESSOR_H
#define SANTA__SANTAD__EVENTPROVIDERS_FAAPOLICYPROCESSOR_H

#include <EndpointSecurity/EndpointSecurity.h>
#include <sys/stat.h>

#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTCommonEnums.h"
#include "Source/common/SantaCache.h"
#include "Source/common/SantaVnode.h"
#include "Source/santad/DataLayer/WatchItemPolicy.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#import "Source/santad/SNTDecisionCache.h"

extern NSString *const kBadCertHash;

// NB: Unfortunately, googletest macros don't play nice with Objective-C types
// and when using macros like MOCK_METHOD, the compiler generates errors about
// "NSString *" and "NSString *__strong" being different types. In order to
// facilitate testing, these unnecessary qualifiers are added in this class
// and we ignore clang complaining about them.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wignored-qualifiers"

namespace santa {

class FAAPolicyProcessor {
 public:
  // Small structure to hold a complete event path target being operated upon and
  // a bool indicating whether the path is a readable target (e.g. a file being
  // opened or cloned)
  struct PathTarget {
    std::string path;
    bool is_readable;
    std::optional<std::pair<dev_t, ino_t>> devno_ino;
  };

  friend class MockFAAPolicyProcessor;

  FAAPolicyProcessor(SNTDecisionCache *decision_cache);

  virtual ~FAAPolicyProcessor() = default;

  virtual bool PolicyMatchesProcess(const WatchItemProcess &policy_proc,
                                    const es_process_t *es_proc);

  virtual SNTCachedDecision *__strong GetCachedDecision(const struct stat &stat_buf);

  static void PopulatePathTargets(const Message &msg, std::vector<PathTarget> &targets);

 private:
  SNTDecisionCache *decision_cache_;
  SantaCache<SantaVnode, NSString *> cert_hash_cache_;

  virtual NSString *__strong GetCertificateHash(const es_file_t *es_file);
};

}  // namespace santa

#pragma clang diagnostic pop

#endif
