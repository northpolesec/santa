---
parent: Binaries
---

# santametricservice

The `santametricservice` is responsible for managing various counters and gauges
used by the Santa development team for monitoring important aspects of Santa
such as: CPU/memory usage, event counters, and event processing timers. Metrics are also often added for new and experimental features to help
ensure proper functionality.

Periodically, the state of all metrics are collected, converted to the
configured format and exported to the configured server.

**IMPORTANT:** Collected metrics are ***not*** sent back to North Pole Security. Metrics are
sent to whatever server is configured, which is nothing by default.
