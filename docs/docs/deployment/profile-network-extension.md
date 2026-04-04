---
sidebar_position: 3
---

# Profiles: Network Extension

Santa includes an optional network [system
extension](https://developer.apple.com/documentation/systemextensions) that can
monitor and control network traffic. It provides two capabilities: a content
filter for monitoring network flows and a DNS proxy for intercepting DNS queries.
:::info

The network extension requires a [Workshop](https://northpole.dev/) subscription
and will not activate without one.

:::

Like the endpoint security system extension, loading the network extension
requires approval. For organizations deploying Santa, this step can be automated
by sending an appropriate profile via an MDM.

Enabling the network extension requires two separate payloads: a
[Web Content Filter](https://developer.apple.com/documentation/devicemanagement/webcontentfilter)
payload for the content filter provider and a
[DNS Proxy](https://developer.apple.com/documentation/devicemanagement/dnsproxy)
payload for the DNS proxy provider.

:::warning

You must also update your [system extension profile](profile-system-extension.md)
to allow the network extension. Without this, macOS will not permit the extension
to load without manual user intervention.

:::

For installation and verification steps, see the
[Network Extension](network-extension.md) page.

## Generating the profile

The process for adding these payloads to your machines will differ depending on
which MDM you are using. Many MDMs have specific support for these kinds of
profiles. In that case, you will need the following information:

### Content Filter

- Filter Type: `Plugin`
- Plugin Bundle ID: `com.northpolesec.santa`
- Filter Data Provider Bundle Identifier: `com.northpolesec.santa.netd`
- Filter Data Provider Designated Requirement: `identifier "com.northpolesec.santa.netd" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] and certificate leaf[field.1.2.840.113635.100.6.1.13] and certificate leaf[subject.OU] = "ZMCG7MLDV9"`
- Filter Sockets: `true`
- Filter Packets: `false`

### DNS Proxy

- App Bundle Identifier: `com.northpolesec.santa`
- Provider Bundle Identifier: `com.northpolesec.santa.netd`

## Example Profile

If your MDM doesn't have an option to add Content Filter or DNS Proxy profiles
but does have the option for deploying custom profiles, you can use the following
example as a template.

```xml showLineNumbers
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadType</key>
			<string>com.apple.webcontent-filter</string>
			<key>PayloadIdentifier</key>
			<string>com.northpolesec.santa.content-filter</string>
			<key>PayloadUUID</key>
			<string>A1B2C3D4-5555-6666-7777-888899990000</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
			<key>PayloadDisplayName</key>
			<string>Santa Content Filter</string>
			<key>UserDefinedName</key>
			<string>Santa Content Filter</string>
			<key>FilterType</key>
			<string>Plugin</string>
			<key>PluginBundleID</key>
			<string>com.northpolesec.santa</string>
			<key>FilterDataProviderBundleIdentifier</key>
			<string>com.northpolesec.santa.netd</string>
			<key>FilterDataProviderDesignatedRequirement</key>
			<string>identifier "com.northpolesec.santa.netd" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] and certificate leaf[field.1.2.840.113635.100.6.1.13] and certificate leaf[subject.OU] = "ZMCG7MLDV9"</string>
			<key>FilterSockets</key>
			<true/>
			<key>FilterPackets</key>
			<false/>
		</dict>
		<dict>
			<key>PayloadType</key>
			<string>com.apple.dnsProxy.managed</string>
			<key>PayloadIdentifier</key>
			<string>com.northpolesec.santa.dns-proxy</string>
			<key>PayloadUUID</key>
			<string>A1B2C3D4-1111-2222-3333-444455556666</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
			<key>PayloadDisplayName</key>
			<string>Santa DNS Proxy</string>
			<key>AppBundleIdentifier</key>
			<string>com.northpolesec.santa</string>
			<key>ProviderBundleIdentifier</key>
			<string>com.northpolesec.santa.netd</string>
		</dict>
	</array>
	<key>PayloadDisplayName</key>
	<string>Santa Network Extension</string>
	<key>PayloadIdentifier</key>
	<string>com.northpolesec.santa.netd.profile</string>
	<key>PayloadUUID</key>
	<string>A1B2C3D4-AAAA-BBBB-CCCC-DDDDEEEEFFFF</string>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
	<key>PayloadScope</key>
	<string>System</string>
	<key>PayloadDescription</key>
	<string>Enables the Santa network content filter and DNS proxy extensions.</string>
</dict>
</plist>
```
