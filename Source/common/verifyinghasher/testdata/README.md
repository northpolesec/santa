# Verifying-hasher test fixtures

Mach-O binaries used by tests in `Source/common/verifyinghasher`. Each
fixture is checked in; this file documents how to regenerate them.

## `hw_universal`

Multi-CD ad-hoc-signed universal Mach-O (x86_64 + arm64) used by
`VerifyingHasherTest`, `VerifyingHasherCoreTest`, and `HeaderParserTest`.
The arm64 slice is plain `CPU_TYPE_ARM64 + CPU_SUBTYPE_ARM64_ALL` (NOT
arm64e).

**DO NOT regenerate without also updating `kHwUniversalSigningID` in
`VerifyingHasherTest.mm`** — the signing_id is derived from the binary
hash and changes when the fixture is rebuilt.

## `hw_team_signed`

Team-signed counterpart to `hw_universal`. Used to exercise positive drift
detection (`kMatchSidTidDrift` requires a non-empty team_id).

```bash
cp testdata/hw_universal testdata/hw_team_signed
codesign --force --sign <ApplicationDevelopmentIdentity> testdata/hw_team_signed
```

Update `kHwTeamSignedSigningID` and `kHwTeamSignedTeamID` in
`VerifyingHasherTest.mm` if regenerated with a different identity.

## `hw_unsigned`

Thin Mach-O arm64 with NO `LC_CODE_SIGNATURE` / no CS blob. Used to
exercise `Expected::Unsigned` semantics.

```bash
mkdir -p /tmp/hw_unsigned_build
cat > /tmp/hw_unsigned_build/main.c <<'EOF'
int main(void) { return 0; }
EOF
clang -arch arm64 -Wl,-no_adhoc_codesign \
  -o /tmp/hw_unsigned_build/hw_unsigned /tmp/hw_unsigned_build/main.c
cp /tmp/hw_unsigned_build/hw_unsigned testdata/hw_unsigned
```

`-Wl,-no_adhoc_codesign` suppresses the linker's default ad-hoc signing
so the produced Mach-O has no LC_CODE_SIGNATURE.

**DO NOT regenerate without also updating `kHwUnsignedSha256` in
`VerifyingHasherTest.mm`** — the hash changes whenever the toolchain or
the source byte sequence changes.

## `hw_entitled`

Mach-O with both XML (`CSSLOT_ENTITLEMENTS=5`) and DER
(`CSSLOT_DER_ENTITLEMENTS=7`) entitlement slots present alongside a real
CMS signature slot. Drives `KernelCsBlob`'s entitlement-extraction and
`CMSDecoder` paths, and the `BinaryAttestation` end-to-end test.

```bash
mkdir -p /tmp/hw_entitled_build
cat > /tmp/hw_entitled_build/main.c <<'EOF'
int main(void) { return 0; }
EOF

cat > /tmp/hw_entitled_build/ents.plist <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>com.apple.security.cs.allow-jit</key>
  <true/>
  <key>com.apple.security.cs.allow-unsigned-executable-memory</key>
  <true/>
</dict>
</plist>
EOF

clang -arch arm64 -o /tmp/hw_entitled_build/hw_entitled \
  /tmp/hw_entitled_build/main.c
codesign --force \
  --sign <ApplicationDevelopmentIdentity> \
  --entitlements /tmp/hw_entitled_build/ents.plist \
  --options runtime \
  /tmp/hw_entitled_build/hw_entitled
cp /tmp/hw_entitled_build/hw_entitled testdata/hw_entitled
```

Modern macOS codesign produces both XML and DER slots by default when
given `--entitlements`. The specific signing identity does not matter
— tests only assert that both entitlement slots are present and that
the CMS signature parses.
