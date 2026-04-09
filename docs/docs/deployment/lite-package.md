---
sidebar_position: 11
---

# Lite Package

Alongside the regular Santa deployment package, we also offer a "lite" package,
which is named `santa-lite-YYYY.X.pkg`. This package has a few features that are
only available to Workshop customers stripped out.

### Should I use the Lite package?

If you're a Workshop customer: no, this will prevent certain features from
working.

If you're not a Workshop customer: not unless you have a good reason. The lite
package will save you a few megabytes of disk space from the removed components.
but those components will not enable themselves without Workshop anyway.

### Why does the Lite package exist?

Santa includes an optional network extension for adding telemetry of network
events. While this extension can only be activated by Workshop customers, its
presence on disk is enough to make a small number of users uncomfortable.

### What's the downside of the Lite package?

The lite package is created from the exact same build as the regular package
but is signed, notarized, and packaged after the extra components are removed.
This package also receives less testing than we do for the full package -
specifically we regularly perform upgrade testing for each new release but we
cannot do this also for the Lite package as this increases our test matrix far
too much.

Should you ever want to activate the removed features, you'll need to do a
migration from Lite to full package.

### Can I upgrade from Lite to full package?

_Yes_ but the Santa system extension will not be replaced unless the version
number is higher. In practice this _shouldn't_ be a problem as the code for the
running extension should be identical but this scenario is not one that we test.
You may also find systems reporting that they're running the Lite version after
being replaced with the full version until the machines reboot.

### Can I downgrade from the full package to Lite?

_Yes_ with the same caveat as above and another exception: if Santa is connected
to Workshop it will prevent a downgrade to the Lite package to prevent
functionality from being broken.
