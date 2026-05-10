# Fuzzing

libFuzzer harnesses for `//Source/common/verifyinghasher`.

## Targets

- **`:VerifyingHasherFuzzer`** — end-to-end against
  `santa::VerifyingHasherCore::Run()`. Two oracles run on every input:
  AddressSanitizer plus the single-observation invariant (every input byte
  is read at most once per `Run()`, enforced via
  `CountingMemoryFileReader`).
- **`:HeaderParserFuzzer`** — focused on `santa::HeaderParser::Update()`
  with a fixed 256-byte chunk size, exercising multi-chunk replay paths.

Each target's seed corpus lives next to its source file:

- `VerifyingHasherFuzzer_corpus/` — synthetic Mach-O seeds (`fat32`,
  `fat64_synthetic`, `thin_arm64e`). The multi-CD `hw_universal` fixture
  is pulled in via cross-package filegroup from
  `//Source/common/verifyinghasher:hw_universal_fixture` rather than
  duplicated here.
- `HeaderParserFuzzer_corpus/` — header-only synthetic seeds (`fat32_hdr`,
  `fat64_synthetic_hdr`, `hw_universal_hdr`, `thin_arm64e_hdr`).

## One-time toolchain bootstrap

Apple Clang doesn't ship the libFuzzer runtime (`libclang_rt.fuzzer_osx.a`).
Before the first `--config=fuzz` build on a workstation, run the install
helper:

```
./Testing/Fuzzing/install_libclang_fuzzer.sh
```

The script downloads a pinned upstream LLVM macOS arm64 release, copies
the fuzzer runtime into the active Xcode toolchain, and exits. It's
idempotent — safe to re-run if the toolchain ever changes. Writes to
system Xcode require sudo (the script prompts).

Hardcoded for arm64 macOS; on x86_64 hosts, swap the tarball name (see
the comment in the script).

## Running the fuzzers

### Replay corpus (regression mode — fast, suitable for CI)

```
bazel test --config=fuzz \
    //Testing/Fuzzing:VerifyingHasherFuzzer \
    //Testing/Fuzzing:HeaderParserFuzzer
```

Replays each seed through the fuzzer; exits non-zero on any crash, ASan
finding, or single-observation oracle trip.

### Active fuzz with mutation (time-bounded)

```
bazel run --config=fuzz //Testing/Fuzzing:VerifyingHasherFuzzer_run \
    -- --timeout_secs=120
bazel run --config=fuzz //Testing/Fuzzing:HeaderParserFuzzer_run \
    -- --timeout_secs=120
```

Drop `--timeout_secs` to fuzz indefinitely (Ctrl-C to stop). The `_run`
target is the libFuzzer launcher in mutation mode; the plain target
(without `_run`) is replay-only.

Crash reproducers, if any are surfaced, are dumped by libFuzzer under
`/tmp/fuzzing/<target>/...` (the launcher's `--fuzzing_output_root`
default). To turn a reproducer into a permanent regression seed after
the underlying bug is fixed, copy it into
`Testing/Fuzzing/<target>_corpus/regression-<short-name>` and commit
alongside the fix.

## Regenerating seed corpora

Required only after Mach-O / CS-blob format changes that materially
affect the corpus shape (rare).

```
./Testing/Fuzzing/regenerate_corpus.sh
```

The script self-relocates, so it's safe to invoke from anywhere. It
overwrites the existing seed files in both `*_corpus/` directories. The
`hw_universal` production fixture is **not** touched — it lives at
`Source/common/verifyinghasher/testdata/hw_universal` and is regenerated
separately.

Requirements: macOS + Apple Clang (`arm64e` target is Apple-only) plus
`lipo`, `codesign`, `dd`, `python3`. Not portable to Linux.

## Supported inputs (what the fuzzers cover)

- Mach-O thin: `MH_MAGIC` / `MH_MAGIC_64` and byte-swapped forms.
- Fat32: `FAT_MAGIC` / `FAT_CIGAM`.
- Fat64: `FAT_MAGIC_64` / `FAT_CIGAM_64`. Accepted for dyld dylib
  verification even though xnu's exec path doesn't load fat64.
- Architectures: `arm64`, `arm64e`, `x86_64`.
- CD hash types: `SHA-1`, `SHA-256`, `SHA-256-TRUNCATED`, `SHA-384`.

## Adding a new fuzz target

The `objc_fuzz_test` macro in `fuzzing.bzl` wraps `cc_fuzz_test` from
`rules_fuzzing`. Pattern:

```
objc_fuzz_test(
    name = "MyNewFuzzer",
    srcs = ["MyNewFuzzer.mm"],
    corpus = glob(["MyNewFuzzer_corpus/*"], allow_empty = True),
    deps = ["//Source/common/verifyinghasher:SomeTarget"],
)
```

Each fuzz `.mm` defines
`extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)`.
Drop seed inputs into `MyNewFuzzer_corpus/`.

## Configuration

`--config=fuzz` is defined in the top-level `.bazelrc` and layers on
top of `--config=san-common` (shared sanitizer flags also used by
`--config=asan`). It enables libFuzzer instrumentation, ASan, and the
`rules_fuzzing` engine wiring.
