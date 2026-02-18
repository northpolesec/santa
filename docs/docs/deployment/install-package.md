---
sidebar_position: 7
---

# Install Santa Package

With all of the profiles configured you are finally ready to install the Santa
package. We assume that your organization has some mechanism for deploying
packages already, whether that's with an MDM or a packaging tool like Munki.

## Releases

The latest release of Santa is always available
[on GitHub](https://github.com/northpolesec/santa/releases/latest).

Every release includes detailed notes about what has been added and changed and
includes 3 asset files:

- A DMG file, which contains the PKG file. This file is largely unnecessary
  nowadays but is still released for historical reasons.

- A PKG file, which installs Santa and immediately loads it. If an existing
  Santa install is running, the package will seamlessly upgrade.

- A `.tar.gz` file containing the signed `Santa.app` bundle that is installed
  by the PKG file, many configuration files and scripts involved in configuring
  and signing, and a folder containing all of the debug symbols for that
  release.

## Deployment

### MDM

If you already used an MDM to install the configuration profiles, you can also
use the MDM to install the package. The exact steps to configure this will
differ depending on which MDM you are using, but all should support this
ability.

When configuring this your MDM may support different kinds of applications to
be installed, Santa should be configured as an "Installer Package (.pkg)".
The packages that we distribute are signed and notarized, and in a format
suitable for direct MDM deployment.

The package contains preinstall and postinstall scripts to handle ensure Santa
is fully loaded once the package install is complete, so you should not need to
add extra scripts if this is sorted.

If your MDM supports it, an "Audit and Enforce" mode is ideal as this will
ensure that the Santa package is installed and not removed.

### Munki

Munki is a very popular open-source software management tool for macOS. Munki
is a client that runs on each macOS machine and retrieves packages from a server
managed by the company.

Munki natively supports macOS installer packages and can enforce that the
package is installed and re-install if the user attempts to remove it. It is
recommended to install Santa as one of the `managed_installs` in your
manifest.

Here's an example PkgInfo that can be imported into a catalog:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>name</key>
    <string>Santa</string>
    <key>version</key>
    <string>2025.3</string>
    <key>description</key>
    <string>Santa, the friendly security tool for macOS</string>
    <key>installs</key>
    <array>
        <dict>
            <key>type</key>
            <string>application</string>
            <key>path</key>
            <string>/Applications/Santa.app</string>
            <key>CFBundleIdentifier</key>
            <string>com.northpolesec.santa</string>
            <key>CFBundleName</key>
            <string>Santa</string>
            <key>CFBundleShortVersionString</key>
            <string>2025.3</string>
        </dict>
    </array>
    <key>blocking_applications</key>
    <array>
      <!-- The Santa package will handle upgrades even if Santa.app is running -->
    </array>
    <key>receipts</key>
    <array>
        <dict>
            <key>packageid</key>
            <string>com.northpolesec.santa</string>
            <key>version</key>
            <string>2025.3</string>
        </dict>
    </array>
    <key>installer_item_hash</key>
    <string>06a33253a015be318503523df054771786a2d71d99f5e679329f32968d808cc1</string>
    <key>installer_item_location</key>
    <string> ~ you must populate this with the path to santa-2025.3.pkg ~ </string>
    <key>uninstallable</key>
    <false/>
    <key>unattended_install</key>
    <true/>
</dict>
</plist>
```

### Manual Install

If you're installing Santa on a small number of machines and/or don't have an
MDM, you can manually install the Santa package. This can be done either by
double-clicking the package file in Finder, or using the command-line:

```shell
sudo installer -pkg santa-2025.3.pkg -tgt /
```

### Homebrew

If you're installing Santa on a small number of machines and/or don't have an
MDM, you can install Santa from homebrew:

```shell
brew install santa
```

You will likely be prompted for your sudo password during installation, this is
expected; Santa cannot be installed in a user folder like normal homebrew
packages.

:::info

The Santa homebrew cask is **not** maintained by the Santa team.

Homebrew has automation that updates the cask version within a few hours of a
new release being published and the install method just installs the package so
everything _should_ work but we cannot offer support for it.

:::

## Verification

You can check that Santa is installed and running using `santactl`:

```shell title="santactl version"
santad          | 2025.3 (build 97, commit 10bdfcc2)
santactl        | 2025.3 (build 97, commit 10bdfcc2)
SantaGUI        | 2025.3 (build 97, commit 10bdfcc2)
```

```shell title="santactl status"
>>> Daemon Info
  Mode                                            | Monitor
  Log Type                                        | file
  File Logging                                    | No
  Mountable Removable Media Blocking              | Yes
  Mountable Removable Media Remounting Mode       | rdonly, nosuid, noowners
  On Start Mountable Removable Media Options      | None
  Watchdog CPU Events                             | 0  (Peak: 3.31%)
  Watchdog RAM Events                             | 0  (Peak: 15.19MB)
>>> Cache Info
  Root cache count                                | 133
  Non-root cache count                            | 3
>>> Database Info
  Binary Rules                                    | 1
  Certificate Rules                               | 0
  TeamID Rules                                    | 8
  SigningID Rules                                 | 4
  CDHash Rules                                    | 2
  Compiler Rules                                  | 2
  Transitive Rules                                | 0
  Events Pending Upload                           | 117
>>> Static Rules
  Rules                                           | 1
>>> Watch Items
  Enabled                                         | Yes
  Policy Version                                  | v1.1
  Rule Count                                      | 1
  Config Path                                     | /var/db/santa/faa.plist
  Last Policy Update                              | 2025/04/17 12:55:46 -0400
>>> Sync Info
  Sync Server                                     | https://my-sync-server/santa/
  Clean Sync Required                             | No
  Last Successful Full Sync                       | 2025/04/17 12:56:01 -0400
  Last Successful Rule Sync                       | 2025/04/17 12:56:01 -0400
  Push Notifications                              | Connected
  Bundle Scanning                                 | Yes
```
