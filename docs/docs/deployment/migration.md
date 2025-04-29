---
sidebar_position: 8
---

# Migration

This guide outlines the migration process from Google Santa to North Pole
Security (NPS) Santa, designed to ensure a smooth transition with minimal
security coverage gaps.

If you are not currently running Google Santa, you should instead read the
[Getting Started](/deployment/getting-started) page.

## Pre-requisites

- Active Google Santa installation
- MDM (Mobile Device Management)
  - If you do not use an MDM jump to [installing NPS Santa](#2-install-nps-santa)
- A method to deploy the NPS Santa installer package

## Migration Steps

### 1. Configure System Extensions

- (Optional) Add a Team ID rule for North Pole Security's Team ID (`ZMCG7MLDV9`)
  to Gogle Santa. This is to gauarantee that complex MDM setups don't allow Google
  Santa to block NPS Santa if they try to start simultaneously.

- Either add it as a Static Rule, use `santactl rule` or via your sync server.

- Update your MDM configuration to allow both Google and NPS Santa system
  extensions simultaneously. This dual-authorization is temporary but necessary
  for a seamless transition.

- Deploy an updated TCC profile for NPS Santa also

- See the prior pages in this section for how to configure profiles.

### 2. Install NPS Santa

Deploy the [latest NPS Santa
release](https://github.com/northpolesec/santa/releases/latest) to your systems.
The installer is designed with migration support.

- NPS Santa will remain dormant after installation - It will automatically
  monitor for the removal of Google Santa - At this point in time, NPS Santa will
  **not** appear in `systemextensionsctl list` output.

:::warning
To avoid system extension authorization popups, ensure the MDM has
applied the configurations from step #1 before deploying the NPS Santa
installer.
:::

### 3. Remove Google Santa

Through your MDM:

- Remove Google Santa from the allowed system extensions list - This will
  trigger the automatic unloading of Google Santa - NPS Santa will detect the
  removal and finish loading itself within a few seconds

:::warning
To minimize security coverage downtime, ensure the NPS Santa
installer has run before removing Google Santa from the allowed system
extensions list
:::

If you do not use an MDM:

- Remove Google Santa by dragging `/Applications/Santa.app` to the trash
- Respond affirmitively to the admin authorization popup dialog

### 4. Verification

NPS Santa should now be installed and running:

```shell
$ systemextensionsctl list
2 extension(s)
--- com.apple.system_extension.endpoint_security
enabled	active	teamID	bundleID (version)	name	[state]
		EQHXZ8M8AV	com.google.santa.daemon (2024.9/2024.9.674285143)	santad	[terminated waiting to uninstall on reboot]
*	*	ZMCG7MLDV9	com.northpolesec.santa.daemon (2024.10/2024.10.49)	santad	[activated enabled]
```

The terminated Google Santa entry will be cleared on the next reboot. In a
terminated state, Google Santa does not affect NPS Santa.

You should also verify that `santactl version` reports the NPS Santa version
that you installed:

```shell
$ santactl version
santad          | 2025.3 (build 94, commit 63bc558d)
santactl        | 2025.3 (build 94, commit 63bc558d)
SantaGUI        | 2025.3 (build 94, commit 63bc558d)
```
