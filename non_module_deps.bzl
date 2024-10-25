"""Modules for dependencies not included in the Bazel Central Registry"""

load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")

def _non_module_deps_impl(_):
    # FMDB is used to access SQLite from Objective-C(++) code.
    git_repository(
        name = "FMDB",
        remote = "https://github.com/ccgus/fmdb.git",
        commit = "61e51fde7f7aab6554f30ab061cc588b28a97d04",
        shallow_since = "1589301502 -0700",
        build_file_content = """
objc_library(
    name = "FMDB",
    srcs = glob(["src/fmdb/*.m"], exclude=["src/fmdb.m"]),
    hdrs = glob(["src/fmdb/*.h"]),
    includes = ["src"],
    sdk_dylibs = ["sqlite3"],
    visibility = ["//visibility:public"],
)
""",
    )

    # OCMock is used in several tests.
    git_repository(
        name = "OCMock",
        build_file_content = """
objc_library(
    name = "OCMock",
    testonly = 1,
    hdrs = glob(["Source/OCMock/*.h"]),
    copts = [
        "-Wno-vla",
    ],
    includes = [
        "Source",
        "Source/OCMock",
    ],
    non_arc_srcs = glob(["Source/OCMock/*.m"]),
    pch = "Source/OCMock/OCMock-Prefix.pch",
    visibility = ["//visibility:public"],
)
""",
        commit = "2c0bfd373289f4a7716db5d6db471640f91a6507",  # tag = v3.9.4
        remote = "https://github.com/erikdoe/ocmock",
    )

non_module_deps = module_extension(implementation = _non_module_deps_impl)
