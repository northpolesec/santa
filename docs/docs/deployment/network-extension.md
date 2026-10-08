---
sidebar_position: 9
---

# Network Extension

Santa includes an optional network [system
extension](https://developer.apple.com/documentation/systemextensions) that can
monitor and control network traffic. It provides two capabilities: a content
filter for monitoring network flows and a DNS proxy for intercepting DNS queries.

:::info

The network extension requires a [Workshop](https://northpole.security/) subscription
and will not activate without one.

:::

## Installation

### Enabling the feature

Workshop customers must enable the network extension on a
[tag](https://docs.workshop.cloud/tags). Navigate to the tag's sync
settings and enable the **Network Extension** setting. The network extension
will only be installed on hosts that are members of a tag with this setting
enabled.

### Automatic installation

The network extension is lazily installed by default. Activating a network
extension tears down all existing network connections, which can disrupt users.
To minimize impact, Santa will automatically install or upgrade the network
extension when:

- The system reboots
- The system wakes from sleep (e.g. when the laptop lid opens)

The network extension [profiles](profile-network-extension.md) must be installed
for automatic installation to succeed silently. If the profiles are not installed
and a user is logged in, macOS will display its standard prompt asking the user
to approve the extension.

### Manual installation

If you need to install the network extension immediately, you can trigger it
manually:

```text
sudo santactl install --network-extension
```

:::caution

This will tear down existing network connections and can interrupt active
network operations. Use with care.

:::

## Verification

You can check the status of the network extension using `santactl status`. The
output includes a Network Extension section:

```text title="santactl status"
>>> Network Extension
  Enabled                   | Yes
  Loaded                    | Yes
```

- **Enabled** means the appropriate Workshop settings have been configured to
  allow the network extension to run on the system.
- **Loaded** means the network extension has been installed and activated via the
  network extension provider configuration.

You can also run `santactl version` to view version information:

```text title="santactl version"
santad               | 2026.3 (build 187, commit 47a21b0d)
santactl             | 2026.3 (build 187, commit 47a21b0d)
SantaGUI             | 2026.3 (build 187, commit 47a21b0d)
santanetd (BETA)     | 2026.3 (build 187, commit 2149a1ce)
```

If a newer version of the network extension is available, it will be noted in the
output and installed on the next reboot or sleep/wake cycle.

## Removal

1. In Workshop, turn off the **Network Extension** setting on every tag that
   has it. Santa then removes the content filter and DNS proxy configurations,
   but the extension stays activated. While the setting is on, Santa tries to
   install the extension again, and users can see approval prompts.
2. To deactivate the extension on a host, run:

   ```sh
   sudo /Applications/Santa.app/Contents/MacOS/Santa --unload-network-extension
   ```

3. In your [system extension profile](profile-system-extension.md), remove
   `com.northpolesec.santa.netd` from the allowed system extensions. If you
   also listed it as non-removable, remove it from that list too. Keep
   `com.northpolesec.santa.daemon`, which Santa needs to run.

The Web Content Filter and DNS Proxy payloads only pre-approve the extension.
You can remove them at any time.
