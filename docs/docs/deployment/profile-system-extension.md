---
sidebar_position: 2
---

# Profiles: System Extension

One of the primary components of Santa is a [system
extension](https://developer.apple.com/documentation/systemextensions) that
receives callbacks from macOS when certain events occur and when appropriate
block those events from proceeding. Due to the high level of privilege this
grants, it is necessary to approve the loading of system extensions.

On a single user machine, allowing a system extension to load requires a trip to
the "Login Items & Extensions" pane in System Settings. However, for
organizations deploying Santa to all of their machines, this step can be skipped
by first sending an appropriate profile to the machine via an MDM.

## Generating the profile

The process for adding a System Extension profile to your machines will differ
depending on which MDM you are using. Many MDMs have specific support for this
kind of profile. In that case, you will need the following information:

- Team Identifier: `ZMCG7MLDV9`

* Allowed extension types: "Endpoint Security Extensions" or `EndpointSecurityExtension`.

- Allowed extensions: `com.northpolesec.santa.daemon`

:::tip
If your MDM requires you to pick between "Allow system extension types" or
"Allow specific system extensions", it is better to choose "Allow specific
system extensions".
:::

Your MDM _may_ also have options to prevent removal of the system extension,
either by itself or by a user (`NonRemovableSystemExtensions` or
`NonRemovableFromUISystemExtensions` keys). If these are available you should
strongly consider enabling them; they make it much more difficult for both users
and malicious scripts from bypassing Santa. If you decide at some later point to
uninstall Santa, you will need to remove the system extension profile before
attempting to uninstall.

## Example Profile

If your MDM doesn't have an option to add a System Extension profile but does
have the option for deploying custom profiles, you can use the following
example as a template.

```xml showLineNumbers
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1">
<dict>
	<!-- See https://developer.apple.com/documentation/devicemanagement/systemextensions for payload descriptions -->
	<key>PayloadUUID</key>
	<string>CAA3F5F6-4519-410D-960B-FDC323FA08E2</string>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadOrganization</key>
	<string>My Company</string>
	<key>PayloadIdentifier</key>
	<string>com.mycompany.santa.sysx-policy.CAA3F5F6-4519-410D-960B-FDC323FA08E2</string>
	<key>PayloadDisplayName</key>
	<string>Santa: System Extension</string>
	<key>PayloadDescription</key>
	<string>Automatically enable Santa's EndpointSecurityExtension</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
	<key>PayloadEnabled</key>
	<true/>
	<key>PayloadRemovalDisallowed</key>
	<true/>
	<key>PayloadScope</key>
	<string>System</string>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadUUID</key>
			<string>67EF74B6-F4FB-49FC-A086-5DE3E61B838A</string>
			<key>PayloadType</key>
			<string>com.apple.system-extension-policy</string>
			<key>PayloadOrganization</key>
			<string>My Company</string>
			<key>PayloadIdentifier</key>
			<string>com.mycompany.santa.sysx-policy.67EF74B6-F4FB-49FC-A086-5DE3E61B838A</string>
			<key>PayloadDisplayName</key>
			<string>Sysx</string>
			<key>PayloadDescription</key>
			<string>Allow Santa's system extension and prevent removal.</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
			<key>PayloadEnabled</key>
			<true/>
			<key>AllowedSystemExtensions</key>
			<dict>
				<key>ZMCG7MLDV9</key>
				<array>
					<string>com.northpolesec.santa.daemon</string>
				</array>
			</dict>
			<key>AllowedSystemExtensionTypes</key>
			<dict>
				<key>ZMCG7MLDV9</key>
				<array>
					<string>EndpointSecurityExtension</string>
				</array>
			</dict>
			<key>NonRemovableSystemExtensions</key>
			<dict>
				<key>ZMCG7MLDV9</key>
				<array>
					<string>com.northpolesec.santa.daemon</string>
				</array>
			</dict>
		</dict>
	</array>
</dict>
</plist>
```
