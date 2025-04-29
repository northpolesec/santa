---
sidebar_position: 3
---

# Profiles: TCC

macOS requires apps like Santa have "Full Disk Access" permissions in order to
perform authorization decisions and Santa cannot start until until this
permission is granted.  On macOS, this access is controlled by a system called
[Transparency, Consent, and Control
(TCC)](https://support.apple.com/guide/security/controlling-app-access-to-files-secddd1d86a6/web),
which limits access to files and devices to only those applications you have
explicitly approved.

Users can manually grant this permission to applications in System Settings, but
organizations deploying Santa and utilizing an MDM can instead install a
configuration profile that grants this permission.

## Generating the profile

The process for adding a TCC profile to your machines will differ depending on
which MDM you are using. Many MDMs have specific support for this kind of
profile, usually labelled as a "Privacy Configuration Profile" or similar. You
will need the following information to configure this profile:

#### App/Process #1:

- Identifier type: "Bundle ID"
- Identifier: `com.northpolesec.santa.daemon`
- Code Requirement:

  ```
  identifier "com.northpolesec.santa.daemon" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = ZMCG7MLDV9
  ```

- Statically validate this requirement: False
- Permission or Service: `SystemPolicyAllFiles` or `Full-disk Access`
- Access: Allow

#### App/Process #2:

- Identifier type: "Bundle ID"
- Identifier: `com.northpolesec.santa.bundleservice`
- Code Requirement:

  ```
  identifier "com.northpolesec.santa.bundleservice" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = ZMCG7MLDV9
  ```

- Statically validate this requirement: False
- Permission or Service: `SystemPolicyAllFiles` or `Full-disk Access`
- Access: Allow

## Example profile

If your MDM doesn't have an option to add a TCC profile but does have the option
for deploying custom profiles, you can use the following example as a template.

```xml showLineNumbers
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadUUID</key>
	<string>089CBCFB-F2AA-407C-9F2A-A12967FE20BC</string>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadOrganization</key>
	<string>My Company</string>
	<key>PayloadIdentifier</key>
	<string>com.mycompany.santa.tcc-policy.089CBCFB-F2AA-407C-9F2A-A12967FE20BC</string>
	<key>PayloadDisplayName</key>
	<string>Santa: TCC</string>
	<key>PayloadDescription</key>
	<string>Grant Santa full-disk access</string>
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
			<string>2416BA4B-CBFC-4719-B02F-20251B881D6F</string>
			<key>PayloadType</key>
			<string>com.apple.TCC.configuration-profile-policy</string>
			<key>PayloadOrganization</key>
			<string>My Company</string>
			<key>PayloadIdentifier</key>
			<string>com.mycompany.santa.tcc-policy.2416BA4B-CBFC-4719-B02F-20251B881D6F</string>
			<key>PayloadDisplayName</key>
			<string>TCC</string>
			<key>PayloadDescription</key>
			<string>Allows full-disk access for Santa</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
 			<!-- See https://developer.apple.com/documentation/devicemanagement/privacypreferencespolicycontrol for payload descriptions -->
			<key>Services</key>
			<dict>
				<key>SystemPolicyAllFiles</key>
				<array>
					<dict>
						<key>Allowed</key>
						<true/>
						<key>CodeRequirement</key>
						<string>identifier "com.northpolesec.santa.daemon" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = ZMCG7MLDV9</string>
						<key>Comment</key>
						<string></string>
						<key>Identifier</key>
						<string>com.northpolesec.santa.daemon</string>
						<key>IdentifierType</key>
						<string>bundleID</string>
						<key>StaticCode</key>
						<false/>
					</dict>
					<dict>
						<key>Allowed</key>
						<true/>
						<key>CodeRequirement</key>
						<string>identifier "com.northpolesec.santa.bundleservice" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = ZMCG7MLDV9</string>
						<key>Comment</key>
						<string></string>
						<key>Identifier</key>
						<string>com.northpolesec.santa.bundleservice</string>
						<key>IdentifierType</key>
						<string>bundleID</string>
						<key>StaticCode</key>
						<false/>
					</dict>
				</array>
			</dict>
		</dict>
	</array>
</dict>
</plist>
```
