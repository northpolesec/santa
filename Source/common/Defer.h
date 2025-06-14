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

#ifndef SANTA__COMMON__DEFER_H
#define SANTA__COMMON__DEFER_H

#include <utility>

namespace santa {

/// Defer executes a block on destruction
template <typename F>
class Defer {
 public:
  explicit Defer(F&& block)
      : cleanup_block_(std::forward<F>(block)), should_execute_(true) {}

  ~Defer() {
    if (should_execute_) {
      cleanup_block_();
    }
  }

  Defer(Defer&& other) noexcept
      : cleanup_block_(std::move(other.cleanup_block_)),
        should_execute_(other.should_execute_) {
    other.should_execute_ = false;
  }

  Defer& operator=(Defer&& other) noexcept {
    if (this != &other) {
      // Call our block before moving from other
      if (should_execute_) {
        cleanup_block_();
      }
      cleanup_block_ = std::move(other.cleanup_block_);
      should_execute_ = other.should_execute_;
      other.should_execute_ = false;
    }
    return *this;
  }

  // Not copyable
  Defer(const Defer&) = delete;
  Defer& operator=(const Defer&) = delete;

  void Cancel() { should_execute_ = false; }

  // Execute early, will not be called again upon destruction
  void Execute() {
    if (should_execute_) {
      cleanup_block_();
      should_execute_ = false;
    }
  }

 private:
  F cleanup_block_;
  bool should_execute_;
};

}  // namespace santa

#endif  // SANTA__COMMON__DEFER_H
