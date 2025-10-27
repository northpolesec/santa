# NATS JWT Permission Fix Summary

## The Issue

The JWT permission violations occur because:
1. Machine ID in tests: `test-machine-12345` (contains dashes)
2. JWT allows subscription to: `santa.host.*` (single-level wildcard)
3. Client tries to subscribe to: `santa.host.test-machine-12345`
4. NATS treats this as NOT matching because the dash makes it look like multiple tokens

## Solutions

### Option 1: Use Hexadecimal Machine IDs (Recommended)
Update the machine ID to use only alphanumeric characters:
- Old: `test-machine-12345`
- New: `ABCDEF123456789`

This requires:
1. Updating test code to use hex machine IDs ✓ (done)
2. Regenerating JWT credentials for the hex machine ID (requires operator key)

### Option 2: Use Multi-level Wildcards
Change JWT permissions from `santa.host.*` to `santa.host.>`
- `santa.host.*` - matches only one level: `santa.host.foo`
- `santa.host.>` - matches any levels: `santa.host.foo.bar.baz`

### Option 3: For Testing Only
The integration tests currently pass because they use a local NATS server without JWT authentication. The Docker NATS server has JWT auth enabled, which is why you see the violations there.

## Current Status
- Test code updated to use hexadecimal machine IDs
- Tests pass with local NATS server (no JWT auth)
- Docker NATS server still shows violations because JWTs need regeneration