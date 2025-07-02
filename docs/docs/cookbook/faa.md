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
