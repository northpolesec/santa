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

#ifndef SANTA__SANTAD__EVENTPROVIDERS_MOCKFAAPOLICYPROCESSOR_H
#define SANTA__SANTAD__EVENTPROVIDERS_MOCKFAAPOLICYPROCESSOR_H

#include "Source/santad/EventProviders/FAAPolicyProcessor.h"

#import <Foundation/Foundation.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <sys/stat.h>

#import "Source/common/SNTCachedDecision.h"
#include "Source/santad/DataLayer/WatchItemPolicy.h"
#include "Source/santad/SNTDecisionCache.h"

namespace santa {

class MockFAAPolicyProcessor : public FAAPolicyProcessor {
 public:
  MockFAAPolicyProcessor(SNTDecisionCache *dc) : FAAPolicyProcessor(dc) {}
  virtual ~MockFAAPolicyProcessor() {}

  // Wraps the call into the private GetCertificateHash method
  NSString *GetCertificateHashWrapper(const es_file_t *es_file) {
    return FAAPolicyProcessor::GetCertificateHash(es_file);
  }

  MOCK_METHOD(bool, PolicyMatchesProcess,
              (const WatchItemProcess &policy_proc, const es_process_t *es_proc), (override));
  MOCK_METHOD(SNTCachedDecision *, GetCachedDecision, (const struct stat &stat_buf), (override));
  MOCK_METHOD(NSString *, GetCertificateHash, (const es_file_t *es_file), (override));
};

}  // namespace santa

#endif
