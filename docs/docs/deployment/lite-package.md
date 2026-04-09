---
sidebar_position: 11
---

# Lite Package

Alongside the regular Santa deployment package, we also make available a "lite"
package, which is named `santa-lite-YYYY.X.pkg`. This package has Workshop-only
components removed.

### Why does the Lite package exist?

Santa includes an optional network extension for adding telemetry of network
events. While this extension can only be activated by Workshop customers, its
mere presence on disk concerns some users, despite being inert without being
connected to Workshop.

### What's the downside of the Lite package?

The lite package is built from the same artifacts as the full package, then
re-signed and re-notarized after removing components. It receives less testing -
we run upgrade testing for each release but do not include the Lite variant, as
it would significantly expand our test matrix.

Should you ever want to activate the removed features, you'll need to do a
migration from Lite to full package.

### Should I use the Lite package?

If you're a Workshop customer: no, this will prevent certain features from
working.

If you're not a Workshop customer: we recommend the full package. The Lite
package only saves a few megabytes, and the removed components are inert without
Workshop.


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
