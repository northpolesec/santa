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

#ifndef SANTA_COMMON_MEMOIZER_H
#define SANTA_COMMON_MEMOIZER_H

#include <functional>
#include <optional>

namespace santa {

// Memoizer is a template class that memoizes the result of a function call that
// requires no arguments, to avoid expensive recalculations.
//
// Not thread-safe: a given instance must only be accessed from one thread.
template <typename T>
class Memoizer {
 public:
  // Constructor takes the function to be memoized
  Memoizer(std::function<T()> func) : func_(func) {}

  // References returned by operator() are tied to this instance; copying or
  // moving would let them silently outlive the storage they point into.
  Memoizer(const Memoizer&) = delete;
  Memoizer& operator=(const Memoizer&) = delete;
  Memoizer(Memoizer&&) = delete;
  Memoizer& operator=(Memoizer&&) = delete;

  // Overload the operator() to enable calling the Memoizer like a function
  // Mark this as const to allow it to be called from const methods. It
  // technically isn't const given that cache_ is updated but we mark that field
  // as mutable.
  //
  // The returned reference is valid for the lifetime of the Memoizer and is
  // never invalidated; callers may hold pointers into the returned value for
  // as long as the Memoizer is alive.
  const T& operator()() const {
    if (!cache_.has_value()) {
      cache_ = func_();
    }
    return *cache_;
  }

  bool HasValue() const { return cache_.has_value(); }

 private:
  std::function<T()> func_;
  mutable std::optional<T> cache_;
};

}  // namespace santa

#endif  // SANTA_COMMON_MEMOIZER_H
