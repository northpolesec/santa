---
sidebar_position: 2
---

# File-Access Authorization

File Access Authorization is a feature that lets Santa control which processes
are allowed access to read/write files. This can be used to monitor and log
access or even block access altogether.

:::note[IMPORTANT]
This feature is only supported on macOS 13 and above.
:::

![File-access authorization notification dialog](/img/faa-dialog_dark.png#dark)
![File-access authorization notification dialog](/img/faa-dialog_light.png#light)

## Use-cases

There are many possible use-cases for File-Access Authorization, here are a few
examples to get you started:

- Restricting read access to credentials files or API keys to specific
  processes.

- Restricting read access to browser cookies only to browser processes.

- Restricting write access to important configuration files (sudoers, PAM,
  sshd_config, etc.) to company-installed management tools.

- Restrict read access for a risky process to a specific set of paths.

## Policy Configuration

FAA policies are defined using a plist configuration, either in a [separate
file](/configuration/keys#FileAccessPolicyPlist) or
[in-line](/configuration/keys#FileAccessPolicy) with the rest of the Santa
configuration.

If the policy is specified in a separate file, Santa will periodically re-read
this file. By default this will occur every 10 minutes but the interval can be
[overridden](/configuration/keys#FileAccessPolicyUpdateIntervalSec).

The full keys available in the policy file are [documented
here](/configuration/faa.md)

### Basic Policy Structure

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
				<key>EventDetailText</key>
				<string>Only some files can access the important file foo!</string>
			</dict>
			<key>Processes</key>
			<array>
				<dict>
					<!-- Platform binaries use a separate key rather than the `platform:com.apple.ls` format used in binary authorization rules -->
					<key>PlatformBinary</key>
					<true/>
					<key>SigningID</key>
					<string>com.apple.ls</string>
				</dict>
				<dict>
					<!-- Signing IDs are specified differently than in binary authorization rules, note the separate TeamID key -->
					<key>TeamID</key>
					<string>EQHXZ8M8AV</string>
					<key>SigningID</key>
					<string>com.google.Chrome.helper</string>
				</dict>
				<dict>
					<!-- Allow the Slack Team ID -->
					<key>TeamID</key>
					<string>BQR82RBBHL</string>
				</dict>
				<dict>
					<!-- Allow the binary at the path, AND require the TeamID specified -->
					<key>BinaryPath</key>
					<string>/usr/local/bin/my_foo_writer</string>
					<key>TeamID</key>
					<string>ABCDEF1234</string>
				</dict>
			</array>
		</dict>
	</dict>
</dict>
</plist>
```

The top-level policy includes a version, some [GUI
configuration](/configuration/faa.md) and then a dictionary of individual
rules under the `WatchItems` key.

The key for each entry in the `WatchItems` dictionary is a name for that rule,
which will be used in logs and in the block UI. The rule then contains `Paths`,
`Processes` and `Options` fields.

### Path Patterns

Paths can be specified using various patterns:

- Exact paths: `/etc/sudoers`
- Wildcards: `/Users/*/Documents/*`

:::important

If a configuration contains multiple rules with duplicate configured paths, only
one rule will be applied to the path. Which rule will be applied is undefined.
You should take care when crafting policies not to define rules with duplicate
paths.

:::

#### Globs

When an operation occurs on a path that matches multiple configured path
globs or prefixes, the rule that contains the "most specific" or longest match
is applied.

Path globs represent a point-in-time; globs are expanded when a configuration is
applied to generate the set of monitored paths and periodically re-evaluated.
This is not a _live_ representation of the filesystem. For instance, if a new
file or directory is added that would match a glob after the configuration is
already active, it would not immediately be monitored.

Within the main Santa configuration, the
[FileAccessPolicyUpdateIntervalSec](/configuration/keys.mdx#FileAccessPolicyUpdateIntervalSec)
key controls how often changes to the configuration are applied as well as how
often to re-evaluate path globs. This has a minimum value of 15 seconds.

The `BinaryPath` key does **not** support glob patterns (`*`).

Glob pattern support is provided by the libc
[`glob(3)`](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/glob.3.html)
function. Extended glob patterns, such as globstar (`**`), are not supported.

#### Prefix and Glob Evaluation

Combining path globs and the `IsPrefix` key in a configuration gives greater
control over the paths that should be matched.

A glob (`*`) will only ever match files/directories within a given path, it will
not recurse inside. Rules with `IsPrefix` set to true **will** match files
nested inside directories.

#### Path Resolution

All configured paths are case-sensitive (both paths specfied in the `Path` and
`BinaryPath` keys). The case must match the case of the path as it is stored on
the filesystem.

Due to system limitations, it is not feasible for Santa to know all of the links
for a given path. To help mitigate bypasses of this features, Santa will not
allow the creation of hard links for monitored paths. If hard links previously
existed for monitored paths, Santa cannot guarantee that access to watched
resources via these other links will be monitored.

Configured path globs must refer to resolved paths only. It is not supported to
monitor access on symbolic links. This is important as some common paths on
macOS are symbolic links (e.g. `/tmp` and `/var` are both symlinks into
`/private`)

### Process Matching

Processes can be matched using:

- Signing IDs: `com.google.Chrome.helper`

      :::tip

      Signing IDs are specified differently in FAA policies than in binary
      authorization rules. Instead of prefixing the Signing ID with a TeamID or
      `platform` you instead specify these in a separate `TeamID` or `PlatformBinary`
      key.

      :::

- Team IDs: `ZMCG7MLDV9`
- CDHash: `397d55ebec87943ea3c3fe6b4d4f47edc490d25e`
- Leaf Certificate Hash: `d84db96af8c2e60ac4c851a21ec460f6f84e0235beb17d24a78712b9b021ed57`
- Platform Binary: `false`
- Full paths: `/Applications/Safari.app/Contents/MacOS/Safari`

      :::warning

      Specifying binaries by full path is not very secure, given that binaries can
      easily be moved. This should only be used as a last resort.

      :::

### Data-centric vs Process-centric

FAA policies can be written to specify which processes can access a path (data-centric)
or which paths can be accessed by a process (process-centric).

As an example:

- To protect browser cookies from theft you could craft a policy that limits
  access to the cookie files to only processes related to the respective
  browser. This would be a **data-centric policy**.

- To protect against inadvertent uploads of company data outside, you could
  craft a policy that prevents AirDrop processes from reading files in folders
  that are known to contain potentially sensitive corporate data. This would
  be a **process-centric policy**.

When writing the policy configuration the policy type is defined by the
`RuleType` key:

| `RuleType`                  | Process/Data Centric |
| --------------------------- | -------------------- |
| `PathsWithAllowedProcesses` | Data                 |
| `PathsWithDeniedProcesses`  | Data                 |
| `ProcessesWithAllowedPaths` | Process              |
| `ProcessesWithDeniedPaths`  | Process              |

## Example Policies

### Protecting Browser Cookies (Data-centric)

This example policy will protect the Chrome Cookies files across all users and
all Chrome profiles. There are two exceptions defined: One for Chrome itself to
be able to manage the file, and another for the macOS Spotlight feature which
accesses most things on the files system and can create unnecessary noise.

```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Version</key>
	<string>v1.0</string>
	<key>WatchItems</key>
	<dict>
<!-- highlight-start -->
		<key>ChromeCookies</key>
		<dict>
			<key>Paths</key>
			<array>
				<dict>
					<key>Path</key>
					<string>/Users/*/Library/Application Support/Google/Chrome/*/Cookies</string>
					<key>IsPrefix</key>
					<true/>
				</dict>
			</array>
			<key>Options</key>
			<dict>
				<key>AllowReadAccess</key>
				<false/>
				<key>AuditOnly</key>
				<false/>
				<key>RuleType</key>
				<string>PathsWithAllowedProcesses</string>
			</dict>
			<key>Processes</key>
			<array>
				<dict>
					<key>SigningID</key>
					<string>com.google.Chrome.helper</string>
					<key>TeamID</key>
					<string>EQHXZ8M8AV</string>
				</dict>
				<dict>
					<key>SigningID</key>
					<string>com.apple.mdworker_shared</string>
					<key>PlatformBinary</key>
					<true/>
				</dict>
			</array>
		</dict>
<!-- highlight-end -->
	</dict>
</dict>
</plist>
```

### Restricting AirDrop Access (Process-centric)

This example policy will prevent any executions of the AirDrop process from
being able to access the defined paths.

This policy could easily be defined in a data-centric way as well, given the
small number of protected paths. However, as AirDrop is usually not opening
many files and the set of protected paths is otherwise accessed quite frequently
then specifying this policy in a process-centric way will be much more
performant.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Version</key>
	<string>v1.0</string>
	<key>WatchItems</key>
<!-- highlight-start -->
		<key>AirDrop</key>
		<dict>
			<key>Paths</key>
			<array>
				<dict>
					<key>Path</key>
					<string>/Users/*/Documents/confidential/*</string>
					<key>IsPrefix</key>
					<true/>
				</dict>
				<dict>
					<key>Path</key>
					<string>/Users/*/Desktop/sensitive/*</string>
					<key>IsPrefix</key>
					<true/>
				</dict>
			</array>
			<key>Options</key>
			<dict>
				<key>RuleType</key>
				<string>ProcessesWithDeniedPaths</string>
				<key>AuditOnly</key>
				<true/>
			</dict>
			<key>Processes</key>
			<array>
				<dict>
					<key>SigningID</key>
					<string>com.apple.finder.Open-AirDrop</string>
					<key>PlatformBinary</key>
					<true/>
				</dict>
			</array>
		</dict>
<!-- highlight-end -->
</dict>
</plist>
```

## Monitoring and Logging

When FAA is enabled, Santa will log all file access events that match your
policies. The logs include:

- Timestamp of the access attempt
- Process attempting the access
- File being accessed
- Action taken (allowed/denied)
- Policy that triggered the action

File access operations are evaluated against all defined rules to determine if
the operation violates any rule configuration. If a rule is matched, the
operation will be logged. Both string and protobuf logging are supported.

When the `EventLogType` configuration key is set to `syslog` or `file`, an
example log message will look like:

```
action=FILE_ACCESS|policy_version=v0.1-experimental|policy_name=UserFoo|path=/Users/local/tmp/foo/text.txt|access_type=OPEN|decision=AUDIT_ONLY|pid=12|ppid=56|process=cat|processpath=/bin/cat|uid=-2|user=nobody|gid=-1|group=nogroup|machineid=my_id
```

When the `EventLogType` configuration key is set to `protobuf`, a log is emitted
with the `FileAccess` message in the
[santa.proto](https://github.com/northpolesec/santa/blob/main/Source/common/santa.proto)
schema.

## Best Practices

1. **Start with monitoring**

   Begin by creating policies with `AuditOnly` set to true so that you can
   collect logs on what _would_ be blocked without inflicting pain on your
   users.

2. **Use Specific Paths**

   Be as specific as possible with path patterns to avoid unintended
   consequences. Using wildcards is often necessary to create policies without
   a huge amount of churn but use them sparingly as a large set of wild-card
   policies can have a negative performance impact.

3. **Test Thoroughly**

   Test policies in a controlled environment before deploying to production.

4. **Document Policies**

   Maintain clear documentation of what each policy is protecting and why.

5. **Regular Review**

   Periodically review and update policies as applications and security
   requirements change.
