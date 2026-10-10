# Transitive Allowlisting

This page lists well-known and/or community-contributed Transitive Allowlisting
rules for various compiler toolchains.

For each toolchain it's important to note that the last binary that writes to
the new binary is the one that should have a rule.

To find that binary, run `eslogger` while you build, and filter for the name
of the output file:

```sh
sudo eslogger close rename clone | grep -F 'OUTPUT_FILE_NAME'
```

A `rename` or `clone` event names the process that renamed or cloned the file.
A `close` event names the process that closed the file. That process changed the
file only if the event has `"modified": true`.

## Xcode

To cover Xcode you will either need `ld`, `lipo`, or `codesign`, depending on
how the project is configured:

* `platform:com.apple.ld`
* `platform:com.apple.lipo`
* `platform:com.apple.security.codesign`

One important caveat: adding an `ALLOWLIST_COMPILER` rule for the codesign
utility could potentially allow any binary to be re-signed and executed.

