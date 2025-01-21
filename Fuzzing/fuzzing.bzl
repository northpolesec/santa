"""Utilities for fuzzing Santa"""

load("@rules_cc//cc:defs.bzl", "objc_library")
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
