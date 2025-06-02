/// Copyright 2025 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///    http://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#ifndef SANTA__COMMON__CEL__MEMOIZER_H
#define SANTA__COMMON__CEL__MEMOIZER_H

#include <functional>
#include <optional>

namespace santa {
namespace cel {

// Memoizer is a template class that memoizes the result of a function call that
// requires no arguments to avoid expensive recalculations.
template <typename T>
class Memoizer {
 public:
  // Constructor takes the function to be memoized
  Memoizer(std::function<T()> func) : func_(func) {}

  // Overload the operator() to enable calling the Memoizer like a function
  // Mark this as const to allow it to be called from const methods. It
  // technically isn't const given that cache_ is updated but we mark that field
  // as mutable.
  T operator()() const {
    if (cache_.has_value()) {
      return cache_.value();
    }

    T result = func_();
    cache_ = result;
    return result;
  }

 private:
  std::function<T()> func_;
  mutable std::optional<T> cache_;
};

}  // namespace cel
}  // namespace santa

#endif  // SANTA__COMMON__CEL__MEMOIZER_H
