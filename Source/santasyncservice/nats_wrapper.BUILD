load("@rules_cc//cc:defs.bzl", "cc_library")

cc_library(
    name = "nats",
    srcs = glob([
        "src/*.c",
        "src/glib/*.c",
        "src/unix/*.c",
    ], exclude = [
        "src/stan/**",
        "src/win/**",
    ]),
    hdrs = glob([
        "src/*.h", 
        "src/glib/*.h",
        "src/include/*.h",
    ]),
    copts = [
        "-std=c99",
        "-fstrict-aliasing",
        "-Wall",
        "-W",
        "-Wno-unused-parameter",
        "-Wno-unused-function",
        "-Wstrict-prototypes",
        "-Wwrite-strings",
        "-pthread",
    ],
    defines = [
        "_REENTRANT",
        "NATS_HAS_TLS",
        "DARWIN",
    ],
    includes = [
        "src",
        "src/glib",
        "src/include", 
        "src/unix",
    ],
    linkopts = [
        "-pthread",
        "-framework", "Security",
        "-framework", "CoreFoundation",
    ],
    visibility = ["//visibility:public"],
)