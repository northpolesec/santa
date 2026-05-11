load("@rules_cc//cc:defs.bzl", "objc_library")
load("//:helper.bzl", "santa_unit_test")

# Default visibility scoped to:
#   - this subpackage's own tests
#   - the CLI in Testing/OneOffs
#   - the fuzz harnesses in Testing/Fuzzing
# The public facade target (:VerifyingHasher, added in Task 13) gets
# an explicit per-target visibility list that includes
# //Source/santad:__subpackages__. Internal targets remain
# package-private to santad to enforce that only the facade is consumed
# outside this subpackage.
package(
    default_visibility = [
        "//Source/common/verifyinghasher:__pkg__",
        "//Testing/Fuzzing:__pkg__",
        "//Testing/OneOffs:__pkg__",
    ],
)

licenses(["notice"])

objc_library(
    name = "FileReader",
    srcs = ["FileReader.mm"],
    hdrs = ["FileReader.h"],
)

objc_library(
    name = "MemoryFileReader",
    hdrs = ["MemoryFileReader.h"],
    deps = [":FileReader"],
)

objc_library(
    name = "CountingMemoryFileReader",
    hdrs = ["CountingMemoryFileReader.h"],
    deps = [":FileReader"],
)

santa_unit_test(
    name = "FileReaderTest",
    srcs = ["FileReaderTest.mm"],
    deps = [
        ":FileReader",
        ":MemoryFileReader",
        "//Source/common:ScopedFile",
    ],
)

objc_library(
    name = "HashTraits",
    hdrs = ["HashTraits.h"],
)

santa_unit_test(
    name = "HashTraitsTest",
    srcs = ["HashTraitsTest.mm"],
    deps = [":HashTraits"],
)

objc_library(
    name = "UninitBuffer",
    hdrs = ["UninitBuffer.h"],
)

santa_unit_test(
    name = "UninitBufferTest",
    srcs = ["UninitBufferTest.mm"],
    deps = [":UninitBuffer"],
)

objc_library(
    name = "HeaderParser",
    srcs = ["HeaderParser.mm"],
    hdrs = ["HeaderParser.h"],
)

santa_unit_test(
    name = "HeaderParserTest",
    srcs = ["HeaderParserTest.mm"],
    deps = [
        ":FileReader",
        ":HeaderParser",
        ":MemoryFileReader",
        "//Source/common:ScopedFile",
    ],
)

objc_library(
    name = "CodeSignatureParser",
    srcs = ["CodeSignatureParser.mm"],
    hdrs = ["CodeSignatureParser.h"],
    deps = [":HashTraits"],
)

santa_unit_test(
    name = "CodeSignatureParserTest",
    srcs = ["CodeSignatureParserTest.mm"],
    deps = [
        ":CodeSignatureParser",
        "//Source/common:ScopedFile",
    ],
)

objc_library(
    name = "PageVerifier",
    hdrs = ["PageVerifier.h"],
    deps = [":HashTraits"],
)

santa_unit_test(
    name = "PageVerifierTest",
    srcs = ["PageVerifierTest.mm"],
    deps = [":PageVerifier"],
)

objc_library(
    name = "VerifyingHasherCore",
    srcs = ["VerifyingHasherCore.mm"],
    hdrs = ["VerifyingHasherCore.h"],
    deps = [
        ":CodeSignatureParser",
        ":FileReader",
        ":HashTraits",
        ":HeaderParser",
        ":PageVerifier",
        ":UninitBuffer",
    ],
)

# Single source of truth for the multi-CD ad-hoc-signed test fixture.
# Testing/Fuzzing references this via cross-package filegroup rather than
# holding its own copy.
filegroup(
    name = "hw_universal_fixture",
    srcs = ["testdata/hw_universal"],
    visibility = [
        "//Source/common/verifyinghasher:__pkg__",
        "//Testing/Fuzzing:__pkg__",
    ],
)

# Team-signed counterpart used to exercise positive drift detection
# (kMatchSidTidDrift requires a non-empty team_id). Generated via:
#   cp testdata/hw_universal testdata/hw_team_signed
#   codesign --force --sign <ApplicationDevelopmentIdentity> testdata/hw_team_signed
# Update kHwTeamSignedSigningID + kHwTeamSignedTeamID in VerifyingHasherTest.mm
# if regenerated with a different identity.
filegroup(
    name = "hw_team_signed_fixture",
    srcs = ["testdata/hw_team_signed"],
    visibility = ["//Source/common/verifyinghasher:__pkg__"],
)

santa_unit_test(
    name = "VerifyingHasherCoreTest",
    srcs = ["VerifyingHasherCoreTest.mm"],
    structured_resources = [":hw_universal_fixture"],
    deps = [
        ":CountingMemoryFileReader",
        ":MemoryFileReader",
        ":VerifyingHasherCore",
        "//Source/common:ScopedFile",
    ],
)

objc_library(
    name = "VerifyingHasher",
    srcs = ["VerifyingHasher.mm"],
    hdrs = ["VerifyingHasher.h"],
    visibility = [
        "//Source/common/verifyinghasher:__pkg__",
        "//Source/santad:__subpackages__",
        "//Testing/Fuzzing:__pkg__",
        "//Testing/OneOffs:__pkg__",
    ],
    deps = [
        ":CodeSignatureParser",
        ":FileReader",
        ":VerifyingHasherCore",
    ],
)

santa_unit_test(
    name = "VerifyingHasherTest",
    srcs = ["VerifyingHasherTest.mm"],
    structured_resources = [
        ":hw_team_signed_fixture",
        ":hw_universal_fixture",
    ],
    deps = [
        ":VerifyingHasher",
        "//Source/common:ScopedFile",
    ],
)

test_suite(
    name = "unit_tests",
    tests = [
        ":CodeSignatureParserTest",
        ":FileReaderTest",
        ":HashTraitsTest",
        ":HeaderParserTest",
        ":PageVerifierTest",
        ":UninitBufferTest",
        ":VerifyingHasherCoreTest",
        ":VerifyingHasherTest",
    ],
)
