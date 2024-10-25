# Migrating from Google Santa to NPS Santa

## Overview
This guide outlines the migration process from Google Santa to NPS Santa, designed to ensure a smooth transition with zero security coverage gaps.

If you are not currently running Google Santa, you can skip this doc and go straight to [Getting Started](getting-started.md).

## Prerequisites
- Active Google Santa installation
- MDM (Mobile Device Management)
- NPS Santa installer package

## Migration Steps

### 1. Configure System Extensions
First, update your MDM configuration to allow both Google and NPS system extensions simultaneously. This dual-authorization is temporary but necessary for a seamless transition.

### 2. Install NPS Santa
Deploy the NPS Santa installer to your systems. The installer is designed with built-in migration support:
- NPS Santa will remain dormant after installation
- It will automatically monitor for Google Santa removal

### 3. Remove Google Santa Authorization
Through your MDM:
- Remove Google Santa from the allowed system extensions list
- This will trigger the automatic unloading of Google Santa
- NPS Santa will detect the removal and will finish loading itself

## Notes
- No reboot is required during this process
- Security coverage is maintained throughout the transition
