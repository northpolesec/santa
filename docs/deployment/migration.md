---
title: Migration
parent: Deployment
nav_order: 7
---

# Migrating from Google Santa to NPS Santa

## Overview
This guide outlines the migration process from Google Santa to NPS Santa, designed to ensure a smooth transition with minimal security coverage gaps.

If you are not currently running Google Santa, you can skip this doc and go straight to [Getting Started](getting-started.md).

## Prerequisites
- Active Google Santa installation
- MDM (Mobile Device Management) - If you do not use an MDM jump to [2. Install NPS Santa](#2.-Install-NPS-Santa)
- NPS Santa installer package

## Migration Steps

### 1. Configure System Extensions
- First, update your MDM configuration to allow both Google and NPS system extensions simultaneously. This dual-authorization is temporary but necessary for a seamless transition.
- Also deploy a TCC full disk access MDM configuration for NPS Santa
- See [Getting Started](./getting-started.md) for examples of the system extention and TCC MDM configurations for NPS Santa.

### 2. Install NPS Santa
Deploy the lastest NPS Santa [release](https://github.com/northpolesec/santa/releases) to your systems. The installer is designed with built-in migration support:
- NPS Santa will remain dormant after installation
- It will automatically monitor for Google Santa removal
- At this point NPS Santa will NOT apear in `systemextensionsctl list`
```
% systemextensionsctl list
1 extension(s)
--- com.apple.system_extension.endpoint_security
enabled	active	teamID	bundleID (version)	name	[state]
*	*	EQHXZ8M8AV	com.google.santa.daemon (2024.9/2024.9.674285143)	santad	[activated enabled]
```

Note: To avoid system extension authorization popups, ensure the MDM has applied configurations from #1 before deploying the NPS Santa installer.

### 3. Remove Google Santa Authorization
Through your MDM:
- Remove Google Santa from the allowed system extensions list
- This will trigger the automatic unloading of Google Santa
- NPS Santa will detect the removal and will finish loading itself within second

Note: To minimize security coverage downtime, ensure the NPS Santa installer has run before removing Google Santa from the allowed system extensions list

If you do not use an MDM:
- Remove Google Santa by dragging `/Applications/Santa.app` to the trash
- Respond to the admin authentication popup dialog

### 4. Verification
- NPS Santa should now installed and running.
```
% systemextensionsctl list
2 extension(s)
--- com.apple.system_extension.endpoint_security
enabled	active	teamID	bundleID (version)	name	[state]
		EQHXZ8M8AV	com.google.santa.daemon (2024.9/2024.9.674285143)	santad	[terminated waiting to uninstall on reboot]
*	*	ZMCG7MLDV9	com.northpolesec.santa.daemon (2024.10/2024.10.49)	santad	[activated enabled]
```

## Notes
- The terminated Google Santa entry will be cleared on the next reboot. In a terminated state, Google Santa does not affect NPS Santa.
- Security coverage downtime is kept to a minimum throughout the transition
