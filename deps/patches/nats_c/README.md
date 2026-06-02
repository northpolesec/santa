# nats_c patches

Local patches applied to the [`nats.c`](https://github.com/nats-io/nats.c)
external repository, pinned at `v3.12.0` in `//deps:non_module_deps.bzl`. They
are applied during the Bazel repo fetch via
`git_repository(patches = [...], patch_args = ["-p1"])`.

## 0001-natssock-read-no-progress-bound.patch

Bounds the no-forward-progress retry loop in `natsSock_Read` (`src/comsock.c`).

Without it, a wedged TLS connection — one that stays readable but never yields
plaintext — makes the read loop retry `SSL_read`/`poll` with no bound, spinning a
CPU core at ~100% indefinitely and deadlocking the reconnect/close path (which
joins the spinning read-loop thread). Observed in the field as
`santasyncservice` pinning a core.

The patch caps consecutive no-progress reads in a single `natsSock_Read` call at
`NATS_SOCK_MAX_STALLED_READS` (250000), then returns `NATS_STALE_CONNECTION` so
the read loop exits and reconnects normally (which also releases the join). The
threshold is far above any legitimate per-call read count (a fragmented max-size
TLS record is ~16K reads worst case) and trips in well under a second of spin.

Upstream-bound: the defect is present on nats.c `main`. Remove this patch when a
fix lands in a pinned release.

**Full analysis** — root cause, the reconnect deadlock, the BoringSSL
reproduction, and the threshold / wall-clock rationale — is in **SNT-435**.
