load("//Testing/Fuzzing:fuzzing.bzl", "objc_fuzz_test")

package(default_visibility = ["//visibility:private"])

licenses(["notice"])

# Pull in the multi-CD signed fixture from the production tree as a fuzz seed.
# Single source of truth lives at
# Source/common/verifyinghasher/testdata/hw_universal.
filegroup(
    name = "hw_universal_seed",
    srcs = ["//Source/common/verifyinghasher:hw_universal_fixture"],
)

objc_fuzz_test(
    name = "VerifyingHasherFuzzer",
    srcs = ["VerifyingHasherFuzzer.mm"],
    corpus = glob(
        ["VerifyingHasherFuzzer_corpus/*"],
        allow_empty = True,
    ) + [":hw_universal_seed"],
    deps = [
        "//Source/common/verifyinghasher:CountingMemoryFileReader",
        "//Source/common/verifyinghasher:VerifyingHasherCore",
    ],
)

objc_fuzz_test(
    name = "HeaderParserFuzzer",
    srcs = ["HeaderParserFuzzer.mm"],
    corpus = glob(
        ["HeaderParserFuzzer_corpus/*"],
        allow_empty = True,
    ),
    deps = ["//Source/common/verifyinghasher:HeaderParser"],
)
