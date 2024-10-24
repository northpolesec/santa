/// Copyright 2023 Google LLC
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
#ifndef SANTA__SANTAD_PROCESSTREE_ANNOTATIONS_ORIGINATOR_H
#define SANTA__SANTAD_PROCESSTREE_ANNOTATIONS_ORIGINATOR_H

#include <optional>

#include "Source/santad/ProcessTree/annotations/annotator.h"
#include "Source/santad/ProcessTree/process.h"
#include "telemetry/proto_include_wrapper.h"

namespace santa::santad::process_tree {

class OriginatorAnnotator : public Annotator {
 public:
  // Disabling clang format due to local/remote version differences.
  // clang-format off
  OriginatorAnnotator()
      : originator_(::santa::telemetry::v1::ProcessTreeAnnotations::Originator::
                        ProcessTreeAnnotations_Originator_UNSPECIFIED) {};
  explicit OriginatorAnnotator(
      ::santa::telemetry::v1::ProcessTreeAnnotations::Originator originator)
      : originator_(originator) {};
  // clang-format on

  void AnnotateFork(ProcessTree &tree, const Process &parent,
                    const Process &child) override;
  void AnnotateExec(ProcessTree &tree, const Process &orig_process,
                    const Process &new_process) override;

  std::optional<::santa::telemetry::v1::ProcessTreeAnnotations> Proto()
      const override;

 private:
  ::santa::telemetry::v1::ProcessTreeAnnotations::Originator originator_;
};

}  // namespace santa::santad::process_tree

#endif
