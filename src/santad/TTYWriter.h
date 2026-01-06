/// Copyright 2023 Google LLC
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

#ifndef SANTA__SANTAD__TTYWRITER_H
#define SANTA__SANTAD__TTYWRITER_H

#include <EndpointSecurity/EndpointSecurity.h>
#import <Foundation/Foundation.h>
#include <dispatch/dispatch.h>

#include <atomic>
#include <memory>

namespace santa {

// Small helper class to synchronize writing to TTYs
class TTYWriter {
 public:
  static std::unique_ptr<TTYWriter> Create(bool silent_tty_mode);

  TTYWriter(dispatch_queue_t q, bool silent_tty_mode);

  // Moves can be safe, but not currently needed/implemented
  TTYWriter(TTYWriter &&other) = delete;
  TTYWriter &operator=(TTYWriter &&rhs) = delete;

  // No copies
  TTYWriter(const TTYWriter &other) = delete;
  TTYWriter &operator=(const TTYWriter &other) = delete;

  static bool CanWrite(const es_process_t *proc);

  void Write(const es_process_t *proc, NSString * (^messageCreator)(void));
  void Write(const es_process_t *proc, NSString *msg);

  void EnableSilentTTYMode(bool silent_tty_mode);

 private:
  dispatch_queue_t q_;
  std::atomic<bool> silent_tty_mode_;
};

}  // namespace santa

#endif
