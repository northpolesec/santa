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

#ifndef SANTA_SANTAD_SNTBINARYUPLOADCONTROLLER_H
#define SANTA_SANTAD_SNTBINARYUPLOADCONTROLLER_H

#include <dispatch/dispatch.h>

#include <cstdint>
#include <memory>

#include "Source/santad/SleighLauncher.h"
#include "commands/v1.pb.h"

namespace santa {

// Drives a single binary upload: opens the requested file (as root) regular-file
// only, computes BinaryMetadata from that same fd, reads the upload filter
// expressions, and launches sleigh to perform the upload. The CEL filter itself
// runs in sleigh — this controller only computes and forwards inputs.
class SNTBinaryUploadController {
 public:
  // launcher performs the sleigh launch; timeout_seconds bounds it (must exceed
  // sleigh's internal upload deadline — see the timeout nesting in the plan).
  SNTBinaryUploadController(std::unique_ptr<SleighLauncher> launcher, uint32_t timeout_seconds);
  virtual ~SNTBinaryUploadController() = default;

  SNTBinaryUploadController(const SNTBinaryUploadController&) = delete;
  SNTBinaryUploadController& operator=(const SNTBinaryUploadController&) = delete;

  // Handles one request and always returns a populated response (failures map to a
  // disposition; never throws). Launches are serialized (K=1).
  virtual ::santa::commands::v1::BinaryUploadResponse Handle(
      const ::santa::commands::v1::BinaryUploadRequest& request);

 private:
  // Runs on serial_queue_ (one upload at a time).
  ::santa::commands::v1::BinaryUploadResponse HandleSerial(
      const ::santa::commands::v1::BinaryUploadRequest& request);

  std::unique_ptr<SleighLauncher> launcher_;
  uint32_t timeout_seconds_;
  dispatch_queue_t serial_queue_;
};

}  // namespace santa

#endif  // SANTA_SANTAD_SNTBINARYUPLOADCONTROLLER_H
