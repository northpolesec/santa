---
sidebar_position: 4
---

# Custom Branding

Santa can display your organization's name or logo on every window it shows, so that users can tell who manages the machine and who to contact.
Branding is configured with three keys, all documented on the [Configuration: Keys](/configuration/keys) page: `BrandingCompanyName`, `BrandingCompanyLogo`, and `BrandingCompanyLogoDark`.

All three were added in Santa 2026.1.

When any of them is set, Santa adds a "Managed by:" footer to the bottom of all notification dialogs (e.g. execution blocked, file access blocked, network flow blocked).

## Company name

`BrandingCompanyName` is the simplest option: the name is shown as text.

```xml
<key>BrandingCompanyName</key>
<string>Acme Corporation</string>
```

<img src="/img/branding-name-dialog_dark.png#dark" alt="Block dialog branded with a company name" width="420" height="358" />
<img src="/img/branding-name-dialog_light.png#light" alt="Block dialog branded with a company name" width="420" height="358" />

## Company logo

`BrandingCompanyLogo` replaces the name with an image.
The image is scaled down to fit within 84x28 points, so a wide wordmark works better than a tall or square logo.
Supply the artwork at twice that size so that it stays sharp on a Retina display.

Only the `file://` and `data:` URL schemes are supported.
HTTP and HTTPS URLs are not, as Santa will not fetch a logo over the network:

```xml
<key>BrandingCompanyLogo</key>
<string>file:///Library/Application%20Support/Acme/logo.png</string>
```

If you use a `file://` URL, deploy the image alongside the profile and put it somewhere that is readable by all users.
Otherwise, embed the image directly in the profile with a `data:` URL:

```xml
<key>BrandingCompanyLogo</key>
<string>data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAKgAAAA4CAYAAAC...</string>
```

### Dark mode

Santa's windows follow the user's appearance setting, so a single-color logo that reads well on a light background can disappear on a dark one.
`BrandingCompanyLogoDark` is used instead of `BrandingCompanyLogo` whenever the window is drawn in dark mode:

```xml
<key>BrandingCompanyLogo</key>
<string>file:///Library/Application%20Support/Acme/logo.png</string>
<key>BrandingCompanyLogoDark</key>
<string>file:///Library/Application%20Support/Acme/logo-dark.png</string>
```

The example below uses a dark wordmark for light windows and a light one for dark windows.

**Light appearance**

<img src="/img/branding-logo-dialog_light.png" alt="Block dialog in light mode branded with a dark company logo" width="420" height="369" />

**Dark appearance**

<img src="/img/branding-logo-dialog_dark.png" alt="Block dialog in dark mode branded with a light company logo" width="420" height="369" />

## Precedence

Only one piece of branding is ever displayed.
The keys are evaluated in this order:

| Order | Key                       | Used when                                     |
| ----- | ------------------------- | --------------------------------------------- |
| 1     | `BrandingCompanyLogoDark` | The window is in dark mode and the key is set |
| 2     | `BrandingCompanyLogo`     | The key is set                                |
| 3     | `BrandingCompanyName`     | Neither logo key applies                      |

A logo URL that uses any other scheme is ignored, as if the key was not set at all.
If a logo URL is accepted but the image cannot be loaded - for example the file is missing, or is not an image format that macOS can read - Santa falls back to `BrandingCompanyName`.
Set that key alongside the logo keys so that there is always something to display.

## Terminal messages

Blocks that happen in a terminal are also branded, but only ever with `BrandingCompanyName`, as logos cannot be drawn on a TTY:

```text
Santa

The following application has been blocked from executing
because its trustworthiness cannot be determined

Reason:      No matching rule
Path:        /Applications/Malware.app/Contents/MacOS/Malware
Identifier:  60055b1f6fb276bfacf61f91505a72201987f20ad8b6867cce3058f4c0f0f5e5
Parent:      bash (2511)

Managed by: Acme Corporation
```

## Custom messages

Branding covers who manages the machine.
To change what the dialogs _say_, see the `UnknownBlockMessage`, `BannedBlockMessage`, `FileAccessBlockMessage`, `BannedUSBBlockMessage`, `EventDetailURL`, and `EventDetailText` keys on the [Configuration: Keys](/configuration/keys) page.
Rules synced from a server can also carry their own message and URL, which override the configured defaults.
