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

/// ScopedTypeRef.h is deliberately free of Objective-C and Foundation
/// dependencies so that it can be included from pure C++ translation units.
/// This file is compiled as C++ rather than Objective-C++ to keep it that way:
/// if either dependency comes back unguarded, this stops compiling.
///
/// Nothing consumes the symbols defined here. This is built as a dependency of
/// ScopedCFTypeRefTest, which is where the behavior of ScopedTypeRef is
/// actually covered.

#include <type_traits>
#include <utility>

#include "Source/common/ScopedTypeRef.h"

namespace {

struct FakeObject {
  int refcount = 1;
};

void FakeRetain(FakeObject* obj) { obj->refcount++; }

void FakeRelease(FakeObject* obj) { obj->refcount--; }

using ScopedFake =
    santa::ScopedTypeRef<FakeObject*, nullptr, FakeRetain, FakeRelease>;

static_assert(std::is_copy_constructible_v<ScopedFake>);
static_assert(std::is_copy_assignable_v<ScopedFake>);
static_assert(std::is_move_constructible_v<ScopedFake>);
static_assert(std::is_move_assignable_v<ScopedFake>);

}  // namespace

// Template members are only instantiated where they're used, so touch each one
// to get it parsed. Never called; declared with external linkage so that it
// isn't flagged as unused.
bool SantaScopedTypeRefPureCXXCompileCheck() {
  FakeObject obj;

  ScopedFake def;
  ScopedFake assumed = ScopedFake::Assume(&obj);
  ScopedFake retained = ScopedFake::Retain(&obj);
  ScopedFake copied = assumed;
  ScopedFake moved = std::move(copied);

  copied = assumed;
  moved = std::move(retained);

  auto [ret, from_out] = ScopedFake::AssumeFrom([&obj](FakeObject** out) {
    *out = &obj;
    return 0;
  });

  ScopedFake into;
  *into.InitializeInto() = &obj;

  return static_cast<bool>(def) || static_cast<bool>(assumed) ||
         static_cast<bool>(copied) || static_cast<bool>(moved) ||
         static_cast<bool>(from_out) || into.Unsafe() != nullptr || ret != 0;
}
