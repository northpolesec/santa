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

#ifndef SANTA__COMMON__CODERMACROS_H
#define SANTA__COMMON__CODERMACROS_H

// Encode the property keyed by the property name.
#define ENCODE(c, o)                        \
  do {                                      \
    if (self.o) {                           \
      [c encodeObject:self.o forKey:@(#o)]; \
    }                                       \
  } while (0)

// Encode the property (by first boxing the value) keyed
// by the property name.
#define ENCODE_BOXABLE(c, o)                   \
  do {                                         \
    id local_obj__ = @(self.o);                \
    [c encodeObject:local_obj__ forKey:@(#o)]; \
  } while (0)

// Decode a property of a given type and assign the value to
// the named property.
#define DECODE(d, o, c)                                    \
  do {                                                     \
    _##o = [d decodeObjectOfClass:[c class] forKey:@(#o)]; \
  } while (0)

// Decode a property of a given type and calls a method on that
// type before assigning the value to the named property
#define DECODE_SELECTOR(d, o, c, s)                            \
  do {                                                         \
    _##o = [[d decodeObjectOfClass:[c class] forKey:@(#o)] s]; \
  } while (0)

// Decode a property of an array  of objects of the given type
// and assign the value to the named property.
#define DECODEARRAY(d, o, c)                                                               \
  do {                                                                                     \
    _##o = [d decodeObjectOfClasses:[NSSet setWithObjects:[NSArray class], [c class], nil] \
                             forKey:@(#o)];                                                \
  } while (0)

#endif
