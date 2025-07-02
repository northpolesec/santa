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

#ifndef SANTA__COMMON__SCOPEDTYPEREF_H
#define SANTA__COMMON__SCOPEDTYPEREF_H

#include <CoreFoundation/CoreFoundation.h>
#include <assert.h>

#include <utility>

namespace santa {

template <typename ElementT, ElementT InvalidV, auto RetainFunc, auto ReleaseFunc>
class ScopedTypeRef {
 public:
  ScopedTypeRef() : ScopedTypeRef(InvalidV) {}

  ScopedTypeRef(ScopedTypeRef &&other) : object_(other.object_) { other.object_ = InvalidV; }

  ScopedTypeRef &operator=(ScopedTypeRef &&rhs) {
    if (this == &rhs) {
      return *this;
    }

    if (object_ != InvalidV) {
      ReleaseFunc(object_);
    }

    object_ = rhs.object_;
    rhs.object_ = InvalidV;

    return *this;
  }

  ScopedTypeRef(const ScopedTypeRef &other) : object_(other.object_) {
    if (object_ != InvalidV) {
      RetainFunc(object_);
    }
  }

  ScopedTypeRef &operator=(const ScopedTypeRef &rhs) {
    if (this == &rhs) {
      return *this;
    }

    if (object_ != InvalidV) {
      ReleaseFunc(object_);
    }

    object_ = rhs.object_;
    if (object_ != InvalidV) {
      RetainFunc(object_);
    }

    return *this;
  }

  // Take ownership of a given object
  static ScopedTypeRef<ElementT, InvalidV, RetainFunc, ReleaseFunc> Assume(ElementT object) {
    return ScopedTypeRef<ElementT, InvalidV, RetainFunc, ReleaseFunc>(object);
  }

  // Take ownership of an out parameter
  template <typename RetT>
  static std::pair<RetT, ScopedTypeRef<ElementT, InvalidV, RetainFunc, ReleaseFunc>> AssumeFrom(
      RetT (^block)(ElementT *object)) {
    ElementT out = InvalidV;
    RetT ret = block(&out);

    return {ret, ScopedTypeRef<ElementT, InvalidV, RetainFunc, ReleaseFunc>::Assume(out)};
  }

  // Retain and take ownership of a given object
  static ScopedTypeRef<ElementT, InvalidV, RetainFunc, ReleaseFunc> Retain(ElementT object) {
    if (object != InvalidV) {
      RetainFunc(object);
    }
    return ScopedTypeRef<ElementT, InvalidV, RetainFunc, ReleaseFunc>(object);
  }

  ~ScopedTypeRef() {
    if (object_ != InvalidV) {
      ReleaseFunc(object_);
    }
  }

  explicit operator bool() const { return object_ != InvalidV; }

  ElementT Unsafe() const { return object_; }

  template <typename T>
  T Bridge() const {
    return (__bridge T)object_;
  }

  // This is to be used only to take ownership of objects that are created by
  // pass-by-pointer create functions. The object must not already be valid.
  // In non-opt builds, this is enforced by an assert that will terminate the
  // process.
  ElementT *InitializeInto() {
    assert(object_ == InvalidV);
    return &object_;
  }

 private:
  // Not API.
  // Use Assume or Retain static methods.
  ScopedTypeRef(ElementT object) : object_(object) {}

  ElementT object_;
};

}  // namespace santa

#endif
