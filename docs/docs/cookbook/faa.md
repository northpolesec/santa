# File-Access Authorization

This page lists well-known and/or community-contributed file-access
authorization policy fragments.

## Chrome Browser Cookies

This policy will prevent reads of cookies from Google Chrome, from any profile
managed by any user, except to Chrome itself and the Spotlight indexing
process.

```xml
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
					<string>com.google.Chrome*</string>
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
```

## Chrome Extensions Directory

This policy will prevent reads and writes of extensions used by Google Chrome, in any profile
managed by any user, excepting Chrome itself and the Spotlight indexing
process.

```xml
<key>ChromeExtensions</key>
<dict>
	<key>Paths</key>
	<array>
		<dict>
			<key>Path</key>
			<string>/Users/*/Library/Application Support/Google/Chrome/*/Extensions/</string>
			<key>IsPrefix</key>
			<true/>
		</dict>
	</array>
	<key>Options</key>
	<dict>
		<key>AuditOnly</key>
		<false/>
    <! -- Set to false if you don't want users to read extension content -->
		<key>AllowReadAccess</key>
		<true/>
		<key>RuleType</key>
		<string>PathsWithAllowedProcesses</string>
	</dict>
	<key>Processes</key>
	<array>
		<dict>
			<key>SigningID</key>
			<string>com.google.Chrome*</string>
			<key>TeamID</key>
			<string>EQHXZ8M8AV</string>
		</dict>
		<dict>
			<key>SigningID</key>
			<string>com.apple.mdworker_shared</string>
			<key>PlatformBinary</key>
			<true/>
		</dict>
		<dict>
			<key>SigningID</key>
			<string>com.apple.mds</string>
			<key>PlatformBinary</key>
			<true/>
		</dict>
		<dict>
			<key>SigningID</key>
			<string>com.apple.mdsync</string>
			<key>PlatformBinary</key>
			<true/>
		</dict>
		<dict>
			<key>SigningID</key>
			<string>com.apple.XProtectFramework.plugins.*</string>
			<key>PlatformBinary</key>
			<true/>
		</dict>
	</array>
</dict>
```

## Slack Cookies

This policy will prevent reads of cookies from the Slack app, except to Slack
itself and the Spotlight indexing process. This is almost identical to the
Chrome Browser rule above because Slack is built with Electron.

The utility of this was highlighted by SpecterOps in their talk
[Modern macOS Read Teaming Tactics](https://www.youtube.com/watch?v=t_L2bdbXkp0&t=2863s)

```xml
<key>SlackCookies</key>
<dict>
		<key>Paths</key>
		<array>
			<dict>
				<key>Path</key>
				<string>/Users/*/Library/Application Support/Slack/Cookies</string>
				<key>IsPrefix</key>
				<true/>
			</dict>
			<dict>
				<key>Path</key>
				<string>/Users/*/Library/Application Support/Slack/StaleCookies</string>
				<key>IsPrefix</key>
				<true/>
			</dict>
			<dict>
				<key>Path</key>
				<string>/Users/*/Library/Containers/com.tinyspeck.slackmacgap/Data/Library/Application Support/Slack/Cookies</string>
				<key>IsPrefix</key>
				<true/>
			</dict>
			<dict>
				<key>Path</key>
				<string>/Users/*/Library/Containers/com.tinyspeck.slackmacgap/Data/Library/Application Support/Slack/StaleCookies</string>
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
					<string>com.tinyspeck.slackmacgap*</string>
					<key>TeamID</key>
					<string>BQR82RBBHL</string>
				</dict>
				<dict>
					<key>SigningID</key>
					<string>com.apple.mdworker_shared</string>
					<key>PlatformBinary</key>
					<true/>
				</dict>
		</array>
</dict>
```

## Sudoers

This policy prevents the sudoers config file from being modified by any process
except sudo itself. With this installed, users will have to use
`sudo -e /etc/sudoers` to modify the policy.

```xml
<key>Sudoers</key>
<dict>
		<key>Paths</key>
		<array>
			<dict>
				<key>Path</key>
				<string>/private/etc/sudoers</string>
			</dict>
			<dict>
				<key>Path</key>
				<string>/private/etc/sudoers.d/*</string>
				<key>IsPrefix</key>
				<true/>
			</dict>
			<dict>
				<key>Path</key>
				<string>/private/var/db/sudo/ts/*</string>
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
					<string>com.apple.sudo</string>
					<key>PlatformBinary</key>
					<true/>
				</dict>
		</array>
</dict>
```

## Lockdown Spotlight Importers

Spotlight importers have been used as [a persistence trick for a
while](https://theevilbit.github.io/beyond/beyond_0011/), going back to Patrick Wardle's [talks in 2015](https://www.blackhat.com/docs/us-15/materials/us-15-Wardle-Writing-Bad-A-Malware-For-OS-X.pdf). This was recently used in the
[Sploitlight exploit](https://www.microsoft.com/en-us/security/blog/2025/07/28/sploitlight-analyzing-a-spotlight-based-macos-tcc-vulnerability/).

```xml
<!-- Block unauthorized Spotlight plugin installations (Sploitlight protection) -->
<key>SpotlightImporterProtection</key>
<dict>
	<key>Paths</key>
	<array>
		<dict>
			<key>Path</key>
			<string>/Users/*/Library/Spotlight</string>
			<key>IsPrefix</key>
			<true/>
		</dict>
		<dict>
			<key>Path</key>
			<string>/Library/Spotlight</string>
			<key>IsPrefix</key>
			<true/>
		</dict>
	</array>
	<key>Options</key>
	<dict>
		<key>AllowReadAccess</key>
		<true/>
		<key>AuditOnly</key>
		<false/>
		<key>EnableSilentMode</key>
		<true/>
		<key>RuleType</key>
		<string>PathsWithAllowedProcesses</string>
	</dict>
	<key>Processes</key>
	<array>
		<dict>
			<key>SigningID</key>
			<string>com.apple.mds</string>
			<key>PlatformBinary</key>
			<true/>
		</dict>
		<dict>
			<key>SigningID</key>
			<string>com.apple.mdworker</string>
			<key>PlatformBinary</key>
			<true/>
		</dict>
		<dict>
			<key>SigningID</key>
			<string>com.apple.mdworker_shared</string>
			<key>PlatformBinary</key>
			<true/>
		</dict>
		<dict>
			<key>SigningID</key>
			<string>com.apple.mdimport</string>
			<key>PlatformBinary</key>
			<true/>
		</dict>
		<!-- Remove this for more security -->
		<dict>
			<key>SigningID</key>
			<string>com.apple.installer</string>
			<key>PlatformBinary</key>
			<true/>
		</dict>
	</array>
</dict>
```
