/// Copyright 2023 Google LLC
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

#ifndef SANTA_SANTAD_TTYWRITER_H
#define SANTA_SANTAD_TTYWRITER_H

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
  TTYWriter(TTYWriter&& other) = delete;
  TTYWriter& operator=(TTYWriter&& rhs) = delete;

  // No copies
  TTYWriter(const TTYWriter& other) = delete;
  TTYWriter& operator=(const TTYWriter& other) = delete;

  static bool CanWrite(const es_process_t* proc);
  static bool CanWrite(NSString* ttyPath);

  void Write(const es_process_t* proc, NSString* (^messageCreator)(void));
  void Write(const es_process_t* proc, NSString* msg);
  void WriteWithoutSignal(const es_process_t* proc, NSString* msg);

  // Path-based entry point (network-flow blocks have a tty path, not an es_process_t).
  virtual void WriteWithoutSignal(NSString* ttyPath, NSString* msg);

  void EnableSilentTTYMode(bool silent_tty_mode);

  // Virtual so deleting a derived instance (e.g. a test double) through a TTYWriter* is
  // well-defined once the class has virtual methods; public so unique_ptr/shared_ptr
  // deleters can reach it.
  virtual ~TTYWriter() = default;

 private:
  void Write(const es_process_t* proc, bool send_signal, NSString* (^messageCreator)(void));
  void Write(NSString* ttyPath, bool send_signal, NSString* (^messageCreator)(void));

  dispatch_queue_t q_;
  std::atomic<bool> silent_tty_mode_;
};

}  // namespace santa

#endif  // SANTA_SANTAD_TTYWRITER_H
