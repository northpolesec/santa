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

#ifndef SANTA__COMMON__PASSKEY_H
#define SANTA__COMMON__PASSKEY_H

// This CRTP mixin class enables derived classes to instantiate private
// instances of PassKey templates specific to them.
//
// The primary purpose is to enable std::make_unique/std::make_shared flows
// from a factory method and disallowing the derived class to be directly
// instantiated.
//
// Example:
// struct Foo : public PassKey<Foo> {
//   static std::shared_ptr<Foo> Create() {
//     return std::make_shared<Foo>(PassKey());
//   }
//
//   explicit Foo(PassKey) {}
// };
template <typename T>
class PassKey {
  friend T;
  explicit PassKey() = default;

 protected:
  static PassKey<T> MakeKey() { return PassKey<T>{}; }
};

#endif  // SANTA__COMMON__PASSKEY_H
