# Transitive Allowlisting

This page lists well-known and/or community-contributed Transitive Allowlisting
rules for various compiler toolchains.

For each toolchain it's important to note that the last binary that writes to
the new binary is the one that should have a rule.

## Xcode

To cover Xcode you will either need `ld`, `lipo`, or `codesign`, depending on
how the project is configured:

* `platform:com.apple.ld`
* `platform:com.apple.lipo`
* `platform:com.apple.security.codesign`

One important caveat: adding an `ALLOWLIST_COMPILER` rule for the codesign
utility could potentially allow any binary to be re-signed and executed.

