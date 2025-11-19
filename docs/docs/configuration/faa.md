---
sidebar_position: 2
---

# File-Access Authorization

File Access Authorization (FAA) policies are defined using a plist configuration
file. The policy can be specified either in a
[separate file](/configuration/keys#FileAccessPolicyPlist) or
[in-line](/configuration/keys#FileAccessPolicy) with the rest of the Santa
configuration.

If the policy is specified in a separate file, Santa will periodically re-read
this file. By default this will occur every 10 minutes but the interval can be
[overridden](/configuration/keys#FileAccessPolicyUpdateIntervalSec).

## Policy Structure

The policy file has a hierarchical structure with root-level configuration and
individual watch rules.

### Root Level Keys

- `Version` (required): Policy version identifier that will be reported in events
- `EventDetailURL` (optional): URL displayed when users receive block notifications. Supports [variable substitution](#eventdetailurl-placeholders) (e.g., `%hostname%`, `%rule_name%`, `%file_identifier%`)
- `EventDetailText` (optional): Button label text for the notification dialog, maximum 48 characters. Defaults to 'Open'.
- `WatchItems` (optional): Dictionary containing the individual monitoring rules

### Watch Item Structure

Each entry in the `WatchItems` dictionary represents a single rule. The key for
each entry is the rule name, which will be used in logs and in the block
notification UI. Each rule contains three main components:

- `Paths`: Array of path patterns to monitor
- `Processes`: List of allowed/denied processes with specific identifiers
- `Options`: Settings for rule behavior

## Basic Example

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Version</key>
	<string>v0.1</string>
	<key>EventDetailURL</key>
	<string>https://my-server/faa/%hostname%/%rule_name%/%file_identifier%</string>
	<key>WatchItems</key>
	<dict>
		<key>UserFoo</key>
		<dict>
			<key>Paths</key>
			<array>
				<dict>
					<key>Path</key>
					<string>/Users/*/tmp/foo</string>
					<key>IsPrefix</key>
					<true/>
				</dict>
			</array>
			<key>Options</key>
			<dict>
				<key>AllowReadAccess</key>
				<false/>
				<key>AuditOnly</key>
				<true/>
				<key>RuleType</key>
				<string>PathsWithAllowedProcesses</string>
			</dict>
			<key>Processes</key>
			<array>
				<dict>
					<key>TeamID</key>
					<string>EQHXZ8M8AV</string>
					<key>SigningID</key>
					<string>com.google.Chrome.helper</string>
				</dict>
			</array>
		</dict>
	</dict>
</dict>
</plist>
```

## Path Configuration

Paths can be specified using exact matches or wildcard patterns:

- Exact paths: `/etc/sudoers`
- Wildcards: `/Users/*/Documents/*`

Each path entry can include:

- `Path` (required): The path pattern to monitor
- `IsPrefix` (optional): Boolean indicating whether the path represents prefix matching. When `true`, the rule will match files nested inside directories. When `false` or omitted, wildcards only match files/directories at that level without recursing.

:::important

If a configuration contains multiple rules with overlapping configured paths,
only one rule will be applied. Which rule will be applied is undefined, so take
care not to define rules with duplicate paths.

:::

### Path Globs

Path globs represent a point-in-time snapshot. Globs are expanded when a
configuration is applied and periodically re-evaluated based on the
[FileAccessPolicyUpdateIntervalSec](/configuration/keys#FileAccessPolicyUpdateIntervalSec)
setting (minimum 15 seconds).

When multiple path globs or prefixes match an operation, the rule with the "most
specific" or longest match is applied.

Glob pattern support is provided by the libc
[`glob(3)`](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/glob.3.html)
function. Extended glob patterns, such as globstar (`**`), are not supported.

### Path Resolution

All configured paths are case-sensitive and must match the case as stored on the
filesystem.

Due to system limitations, Santa cannot reliably monitor hard-linked resources.
To help mitigate bypasses, Santa will not allow the creation of hard links for
monitored paths. If hard links previously existed for monitored paths, Santa
cannot guarantee that access via these other links will be monitored.

Configured path globs must refer to resolved paths only. Monitoring access on
symbolic links is not supported. This is important as some common macOS paths
are symbolic links (e.g., `/tmp` and `/var` are both symlinks into `/private`).

## Process Matching

Processes can be matched using several identifiers:

- **Signing ID**: Specified with the `SigningID` key (e.g., `com.google.Chrome.helper`)
- **Team ID**: Specified with the `TeamID` key (e.g., `ZMCG7MLDV9`)
- **Platform Binary**: Specified with the `PlatformBinary` boolean key
- **CDHash**: Specified with the `CDHash` key (e.g., `397d55ebec87943ea3c3fe6b4d4f47edc490d25e`)
- **Leaf Certificate Hash**: Specified with the `CertificateSha256` key
- **Binary Path**: Specified with the `BinaryPath` key (e.g., `/Applications/Safari.app/Contents/MacOS/Safari`)

:::tip

Signing IDs are specified differently in FAA policies than in binary
authorization rules. Instead of prefixing the Signing ID with a TeamID or
`platform`, you specify these in separate `TeamID` or `PlatformBinary` keys.

:::

:::warning

Specifying binaries by full path using `BinaryPath` is not very secure, as
binaries can easily be moved. This should only be used as a last resort.
Additionally, the `BinaryPath` key does not support glob patterns (`*`).

:::

## Rule Options

The `Options` dictionary within each rule supports the following keys:

- `RuleType` (required): Defines whether the rule is data-centric or process-centric:
  - `PathsWithAllowedProcesses`: Data-centric, only listed processes can access the paths
  - `PathsWithDeniedProcesses`: Data-centric, listed processes cannot access the paths
  - `ProcessesWithAllowedPaths`: Process-centric, listed processes can only access specified paths
  - `ProcessesWithDeniedPaths`: Process-centric, listed processes cannot access specified paths

- `AllowReadAccess` (optional): Boolean controlling whether read access is allowed. When `false`, both read and write access are monitored/blocked. When `true`, only write access is monitored/blocked. Defaults to `true` if not specified.

- `AuditOnly` (optional): Boolean. When `true`, violations are logged but not blocked. Defaults to `false`.

- `EventDetailURL` (optional): Rule-specific URL that overrides the top-level EventDetailURL.

- `EventDetailText` (optional): Custom button label text for this specific rule, overriding the root-level setting

- `EnableSilentMode` (optional): Boolean. When `true`, violations are logged but no notification is shown to the user

## Rule Type Selection

Choose your rule type based on what you're protecting:

| Goal                                                  | Rule Type                                                 |
| ----------------------------------------------------- | --------------------------------------------------------- |
| Protect specific files/paths from unauthorized access | `PathsWithAllowedProcesses` or `PathsWithDeniedProcesses` |
| Restrict what a specific process can access           | `ProcessesWithAllowedPaths` or `ProcessesWithDeniedPaths` |

**Data-centric example**: Protect browser cookies from theft by limiting access to the cookie files to only the browser processes.

**Process-centric example**: Prevent AirDrop processes from reading files in folders containing sensitive corporate data.

## EventDetailURL placeholders

When an FAA rule blocks access to a file, the user will be presented with a block notification dialog. On this dialog a
button can be displayed which will take the user to a page with more information about that event. For the button to
appear you must populate the `EventDetailURL` field, either at the top-level of the configuration or in an individual
rule. This URL can contain placeholders, which will be populated at runtime; the supported placeholders are:

| Placeholder         | Description                                                                                                               |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `%rule_version%`    | Version of the rule that was violated                                                                                     |
| `%rule_name%`       | Name of the rule that was violated                                                                                        |
| `%file_identifier%` | SHA-256 of the binary that was being executed                                                                             |
| `%accessed_path%`   | The path that was being accessed                                                                                          |
| `%username%`        | The executing user                                                                                                        |
| `%machine_id%`      | The ID of the machine, usually the hardware UUID unless [overridden](https://northpole.dev/configuration/keys/#MachineID) |
| `%serial%`          | The serial number of the machine                                                                                          |
| `%uuid%`            | The hardware UUID of the machine                                                                                          |
| `%hostname%`        | The system's full hostname                                                                                                |

## More Information

For complete example policies and use-cases, see the [File-Access Authorization
feature documentation](/features/faa) and the [FAA cookbook](/cookbook/faa).
