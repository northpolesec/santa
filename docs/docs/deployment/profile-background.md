---
sidebar_position: 4
---

# Profiles: Background Apps

Santa has components that run in the background (e.g. for presenting
notifications to users, for syncing, etc.). Starting in macOS 13 Ventura, users
will receive notifications whenever a piece of software is installed that is
able to run in the background and so installing the Santa package can cause
these "Background Items Added" notifications to appear. These notifications can
be suppressed by installing a profile with your MDM.

## Generating the profile

The process for adding a "Service Management" profile to your machines will
differ depending on which MDM you are using. Many MDMs have specific support for
this kind of profile, usually labelled as a "Login & Background Items" or
"Service Management" profile.

You will need the following information to configure this profile:

- Identifier Type: Team Identifier

- Identifier: `ZMCG7MLDV9`

## Example profile

If your MDM doesn't have an option to add a Service Management profile but does
have the option for deploying custom profiles, you can use the following
example as a template.

```xml showLineNumbers
<!DOCTYPE plist PUBLIC “-//Apple//DTD PLIST 1.0//EN” “http://www.apple.com/DTDs/PropertyList-1.0.dtd”>
<plist version=”1.0”>
<dict>
	<key>PayloadUUID</key>
	<string>C5F3332F-9DEA-4FE5-924E-81708D962874</string>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadOrganization</key>
	<string>My Company</string>
	<key>PayloadIdentifier</key>
	<string>com.mycompany.santa.servicemanagement.C5F3332F-9DEA-4FE5-924E-81708D962874</string>
	<key>PayloadDisplayName</key>
	<string>Santa: Background Apps</string>
	<key>PayloadDescription</key>
	<string>Suppress notifications about Santa background apps</string>
	<key>PayloadScope</key>
	<key>PayloadVersion</key>
	<integer>1</integer>
	<key>PayloadEnabled</key>
	<true/>
	<key>PayloadRemovalDisallowed</key>
	<true/>
	<string>System</string>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadUUID</key>
			<string>1161A7ED-2E7B-4744-B933-D3B9F58A1AAE</string>
			<key>PayloadType</key>
			<string>com.apple.servicemanagement</string>
			<key>PayloadOrganization</key>
			<string>My Company</string>
			<key>PayloadIdentifier</key>
			<string>com.mycompany.santa.servicemanagement.1161A7ED-2E7B-4744-B933-D3B9F58A1AAE</string>
			<key>PayloadDisplayName</key>
			<string>Background Apps</string>
			<key>PayloadDescription</key>
			<string>Allows Santa background tasks without notifications</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
			<key>Rules</key>
			<array>
				<dict>
					<key>RuleType</key>
					<string>TeamIdentifier</string>
					<key>RuleValue</key>
					<string>ZMCG7MLDV9</string>
				</dict>
			</array>
		</dict>
	</array>
</dict>
</plist>
```
