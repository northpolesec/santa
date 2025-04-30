---
sidebar_position: 6
---

# Profiles: Santa Configuration

Santa has _many_ configuration options controlling its behavior. The
configuration is expected to be deployed as a macOS [configuration
profile](https://developer.apple.com/business/documentation/Configuration-Profile-Reference.pdf)
by an MDM.

## Generating the profile

As Santa's profile is not part of macOS, there is no built-in support in any
MDM and you will instead need to deploy the configuration as a "Custom Profile".

The full set of configuration options is detailed on the
[Configuration: Keys](/configuration/keys) page and you can generate a profile
using the [Configuration: Generator](/configuration/generator) page.

Once you have the completed profile, you can upload or paste it into your MDM's
configuration page for deployment. The details of how to do this differ between
MDM vendors so you may need to refer to your MDM documentation for assistance.

## Example profile

Below is an example configuration profile that includes a _subset_ of the keys
available.

```xml showLineNumbers
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadContent</key>
			<dict>
				<key>com.northpolesec.santa</key>
				<dict>
					<key>Forced</key>
					<array>
						<dict>
							<key>mcx_preference_settings</key>
							<dict>
<!-- highlight-start -->
								<key>ClientMode</key>
								<integer>1</integer>
								<key>EnableSilentMode</key>
								<false/>
								<key>EventDetailText</key>
								<string>Open sync server</string>
								<key>EventDetailURL</key>
								<string>https://sync-server-hostname/blockables/%file_sha%</string>
								<key>FileChangesRegex</key>
								<string>^/(?!(?:private/tmp|Library/(?:Caches|Managed Installs/Logs|(?:Managed )?Preferences))/)</string>
								<key>MachineIDKey</key>
								<string>MachineUUID</string>
								<key>MachineIDPlist</key>
								<string>/Library/Preferences/com.company.machine-mapping.plist</string>
								<key>MachineOwnerKey</key>
								<string>Owner</string>
								<key>MachineOwnerPlist</key>
								<string>/Library/Preferences/com.company.machine-mapping.plist</string>
								<key>ModeNotificationLockdown</key>
								<string>Entering Lockdown mode</string>
								<key>ModeNotificationMonitor</key>
								<string>Entering Monitor mode&lt;br/&gt;Please be careful!</string>
								<key>MoreInfoURL</key>
								<string>https://sync-server-hostname/moreinfo</string>
								<key>StaticRules</key>
								<array>
									<dict>
										<!-- Always allow files signed by North Pole Security Inc -->
										<key>identifier</key>
										<string>ZMCG7MLDV9</string>
										<key>policy</key>
										<string>ALLOWLIST</string>
										<key>rule_type</key>
										<string>TEAMID</string>
									</dict>
									<dict>
										<!-- Always BLOCK the BundleExample.app binary in Santa's testdata files, for testing -->
										<key>identifier</key>
										<string>b7c1e3fd640c5f211c89b02c2c6122f78ce322aa5c56eb0bb54bc422a8f8b670</string>
										<key>policy</key>
										<string>BLOCKLIST</string>
										<key>rule_type</key>
										<string>BINARY</string>
									</dict>
								</array>
								<key>SyncBaseURL</key>
								<string>https://sync-server-hostname/api/santa/</string>
<!-- highlight-end -->
							</dict>
						</dict>
					</array>
				</dict>
			</dict>
			<key>PayloadEnabled</key>
			<true/>
			<key>PayloadIdentifier</key>
			<string>com.mycompany.santa.359E3C7D-396F-4C45-99E7-F429620B9B21</string>
			<key>PayloadType</key>
			<string>com.apple.ManagedClient.preferences</string>
			<key>PayloadUUID</key>
			<string>359E3C7D-396F-4C45-99E7-F429620B9B21</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
	</array>
	<key>PayloadDescription</key>
	<string>Manages Santa's configuration</string>
	<key>PayloadDisplayName</key>
	<string>Santa: Configuration</string>
	<key>PayloadIdentifier</key>
	<string>com.mycompany.santa</string>
	<key>PayloadOrganization</key>
	<string>My Company</string>
	<key>PayloadRemovalDisallowed</key>
	<true/>
	<key>PayloadScope</key>
	<string>System</string>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>AFA02DE3-ACA6-49C4-9980-A3664E22E446</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>
```
