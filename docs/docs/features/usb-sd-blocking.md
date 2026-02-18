---
sidebar_position: 4
---

# Removable Media (e.g. USB/SD device) Blocking

Removable Media blocking allows blocking removable media such as USB Mass Storage/SD Card storage from mounting, or
forcing devices to be remounted as read-only. This is intended to prevent
data exfiltration.

![USB blocking notification dialog](/img/usb-dialog_dark.png#dark)
![USB blocking notification dialog](/img/usb-dialog_light.png#light)

With this feature [configured](/configuration/keys#BlockUSBMount), any time
a storage device is mounted Santa will evaluate the mount properties; if the
device is _removable_, or _ejectable_, _connected by USB_, or is an _SD card_
and is **not** internal or virtual, then the mount will be processed.

If no re-mount options are configured, matching mounts will be rejected.

You can optionally [configure re-mount
flags](/configuration/keys#RemountUSBMode) to apply to
new mounts. When Santa evaluates a mount it will check the mount flags against
those configured. If they match the mount will be allowed to proceed. Otherwise,
the mount will be rejected and the device will be re-mounted using the
configured flags. This can be used to force a mount to always be read-only,
disable SUID binaries, disable execs from the mount, disable browsing, etc.

Another option that can be configured is what [action should be taken on
start](/configuration/keys#OnStartUSBOptions). By default, any devices that
are mounted when Santa starts are ignored, even if they would have been blocked.
You can instead configure Santa to unmount or remount.
