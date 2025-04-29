---
sidebar_position: 5
---

# Profiles: Notifications

Santa can present native macOS notifications to users when it switches between
modes or when certain sync events happen. As these notifications go through the
native macOS notification system it is possible to manage how they are presented
using a profile.

:::note
These notifications are **not** related to the dialogs presented to users when
an action has been blocked, such as an application being prevented from
executing.
:::

## Generating the profile

The process for adding a "Notifications" profile to your machines will differ
depending on which MDM you are using. Many MDMs have specific support for this
kind of profile, usually labelled as a "Notifications" or "Notifications
Settings" profile.

You will need the following information to configure this profile:

- Bundle Identifier: `com.northpolesec.santa`

- Notifications Enabled: True

- Badges Enabled: True

- Critical Alert Enabled: True

- Show In Notification Center: True

- Show In Lock Screen: False

## Example profile

If your MDM doesn't have an option to add a Notifications profile but does have
the option for deploying custom profiles, you can use the following example as a
template.

```xml showLineNumbers
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>NotificationSettings</key>
			<array>
				<dict>
					<key>AlertType</key>
					<integer>1</integer>
					<key>BadgesEnabled</key>
					<true/>
					<key>BundleIdentifier</key>
					<string>com.northpolesec.santa</string>
					<key>CriticalAlertEnabled</key>
					<true/>
					<key>NotificationsEnabled</key>
					<true/>
					<key>ShowInLockScreen</key>
					<true/>
					<key>ShowInNotificationCenter</key>
					<true/>
					<key>SoundsEnabled</key>
					<false/>
				</dict>
			</array>
			<key>PayloadDisplayName</key>
			<string>Notifications Payload</string>
			<key>PayloadIdentifier</key>
			<string>com.northpolesec.santa.notificationsettings.F1817DA0-0044-43DD-9540-36EBC60FDA8F</string>
			<key>PayloadOrganization</key>
			<string></string>
			<key>PayloadType</key>
			<string>com.apple.notificationsettings</string>
			<key>PayloadUUID</key>
			<string>510236AE-D7F8-4131-A4CA-5CC930C51866</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
	</array>
	<key>PayloadDescription</key>
	<string>Configures your Mac to automatically enable Notifications settings for Santa</string>
	<key>PayloadDisplayName</key>
	<string>Santa: Notifications settings</string>
	<key>PayloadEnabled</key>
	<true/>
	<key>PayloadIdentifier</key>
	<string>com.mycompany.santa.notificationsettings.069CA123-6129-46A5-8FD1-49322E5A5755</string>
	<key>PayloadOrganization</key>
	<string></string>
	<key>PayloadRemovalDisallowed</key>
	<true/>
	<key>PayloadScope</key>
	<string>System</string>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>069CA123-6129-46A5-8FD1-49322E5A5755</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>
```
