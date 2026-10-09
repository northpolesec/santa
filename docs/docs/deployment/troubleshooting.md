---
sidebar_position: 12
---

# Troubleshooting

This page outlines common troubleshooting steps for confirming proper Santa
daemon operation and steps to diagnose and correct common issues.

## Confirming Proper Santa Daemon Operation

The best way to start diagnosing the Santa daemon is by running:

```sh
/usr/local/bin/santactl status
```

If the daemon is up and running, you should see [normal status output](./install-package.md#verification).

However, if you see a message like "`An error occurred communicating with the
Santa daemon...`", then use the following tips to diagnose the issue.

## Run the doctor command

The doctor command checks Santa and its configuration for potential problems.

```sh
sudo santactl doctor
```

## Enabling Full Disk Access

The Santa daemon is required by the system to have "Full Disk Access" enabled
in order to function. On recent macOS versions, you can ensure this is enabled
using System Settings:

1. Open System Settings from the Apple menu
1. In the left pane, click on "Privacy & Security"
1. In the right pane, click on "Full Disk Access"
1. Ensure that `com.northpolesec.santa.daemon` is selected

If "Full Disk Access" wasn't enabled, re-check `santactl status` to see if the
issue is now resolved. Note that it may take up to 15 seconds for the daemon
to become active if no other issues are present.

## Enabling the System Extension

To confirm the Santa system extension is properly loaded, check the
output of the following command:

```sh
/usr/bin/systemextensionsctl list com.apple.system_extension.endpoint_security
```

Confirm that a line item exists for `com.northpolesec.santa.daemon` with the
expected version and the state is `activated enabled`.

If the extension is in the `activated waiting for the user` state, it must
first be approved to run using System Settings:

1. Open System Settings from the Apple menu.
1. In the left pane, click on "General"
1. In the right pane, click on "Login Items & Extensions"
1. Scroll to "Endpoint Security Extensions" and click the info button
1. Ensure that "Santa" is toggled on.

If Santa wasn't enabled, re-check `systemextensionsctl list`. If it's still
not in the `activated enabled` state, try forcing the extension to load:

```sh
/Applications/Santa.app/Contents/MacOS/Santa --load-system-extension
```

After loading, re-check the output of `systemextensionsctl list`. If issues
persist, reinstall Santa.

## Checking Santa Daemon Logs

The Santa daemon emits warning and error messages for encountered issues. If
it fails to start, check the logs for the cause. Daemon logs can be viewed
with the following command:

```sh
/usr/bin/log stream --level debug --predicate 'sender == "com.northpolesec.santa.daemon"'
```

## Enterprise Deployments

Enterprise deployments are typically managed via MDM, so administrators should
follow the guide on the [Getting Started](./getting-started.md) page for
information on creating the necessary configuration profiles.

To diagnose a user device, administrators should first confirm that the MDM is
supervising the computer (via DEP or UAMDM) using the following command:

```sh
/usr/bin/profiles status -type enrollment
```

Profile payloads that require a supervision relationship cannot be applied
manually for testing. Therefore, it's crucial to ensure the MDM connection is
working as expected during mass deployments.

Additionally, confirm the system extension and TCC/PPPC profiles are present, as
described in the [Getting Started](./getting-started.md) flow.

## Verifying Expected Functionality

After confirming that Santa is running, you can verify that settings are being
applied as expected by running `santactl status`.

Additionally, reviewing Santa's [logs](#checking-santa-daemon-logs) and
[telemetry](../features/telemetry.mdx) is helpful for understanding Santa's
operation. The documentation on [binary authorization](../features/binary-authorization.md)
explains precedence and decision-making.

## Invalid Code Signatures

If macOS reports that a binary's code signature is invalid, Santa can only
match the binary with a `BINARY` rule. Santa ignores `CDHASH`, `SIGNINGID`,
`CERTIFICATE`, and `TEAMID` rules for that execution. The same is true for
unsigned binaries.

This often happens while a large app updates itself. A helper process starts
while the app bundle on disk is only partly written. On Apple silicon, the
kernel kills an arm64 process with an invalid signature, and a Santa rule cannot
prevent it. The app usually starts the process again a few seconds later, and it
runs.

Santa 2026.8 and later does not show a block dialog or terminal message when it
blocks a process that the kernel will kill for an invalid signature. Santa still
logs the event, and its `explain` field contains
`Kernel will kill the process for code signature invalidity; suppressing block UI`.

## Sync Client Certificates

Santa uses only the first of these keys that is set to choose a client
certificate for sync. If that key finds no certificate, Santa does not try the
next one.

1. The PKCS#12 file in
   [`ClientAuthCertificateFile`](/configuration/keys#ClientAuthCertificateFile).
2. A keychain certificate with the Common Name in
   [`ClientAuthCertificateCN`](/configuration/keys#ClientAuthCertificateCN).
3. A keychain certificate with the Issuer Common Name in
   [`ClientAuthCertificateIssuerCN`](/configuration/keys#ClientAuthCertificateIssuerCN).
4. If none of these keys are set, a keychain certificate issued by a CA that
   the sync server names during the TLS handshake.

Matching is case sensitive. If several keychain certificates match, Santa uses
the one with the latest valid-from date. In Santa 2026.9 and later, if Santa
cannot use a certificate's private key, it tries the next certificate that
matches the same setting. Earlier versions use the newest certificate even if
its private key is not usable, and the TLS handshake can fail.
