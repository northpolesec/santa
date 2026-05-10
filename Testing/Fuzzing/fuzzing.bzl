# Copyright 2026 North Pole Security, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Utilities for fuzzing VerifyingHasher in Santa."""

load("@rules_cc//cc:objc_library.bzl", "objc_library")
load("@rules_fuzzing//fuzzing:cc_defs.bzl", "cc_fuzz_test")

def objc_fuzz_test(name, srcs, deps, corpus, linkopts = [], **kwargs):
    objc_library(
        name = "%s_lib" % name,
        srcs = srcs,
        deps = deps,
        **kwargs
    )

    cc_fuzz_test(
        name = name,
        deps = [
            "%s_lib" % name,
        ],
        linkopts = linkopts,
        corpus = corpus,
    )
