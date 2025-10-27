# NATS Push Notification Testing

This document describes how to test the NATS push notification client for Santa.

## Overview

The NATS client has been updated to:
- Always be enabled (no configuration option required)
- Wait for preflight configuration before connecting
- Use TLS by default (port 443) with `.push.northpole.security` domain suffix
- Authenticate using nkey and JWT from preflight
- Subscribe to device-specific topic (`santa.<machine-id>`) and tags

## Test Structure

The NATS client tests are split into several categories for better isolation:

1. **Unit Tests** - Test basic functionality without NATS server
   - `SNTPushClientNATSTest` - Basic client behavior
   - `SNTSyncManagerNATSTest` - Manager always creates NATS client

2. **Connection Tests** - Test NATS connection directly without preflight
   - `SNTPushClientNATSConnectionTest` - Direct configuration and connection

3. **Integration Tests** - Full end-to-end tests with preflight flow
   - `SNTPushClientNATSIntegrationTest` - Complete workflow tests

## Running Unit Tests

```bash
bazel test //Source/santasyncservice:SNTPushClientNATSTest
bazel test //Source/santasyncservice:SNTSyncManagerNATSTest
```

## Running Integration Tests

Integration tests require a running NATS server.

### Prerequisites

Install NATS server:
```bash
brew install nats-server
```

### Run Integration Tests

```bash
cd Testing/
./run_nats_integration_tests.sh
```

This script will:
1. Start a local NATS server on port 4222
2. Run the integration tests with TLS disabled for local testing
3. Clean up the NATS server when done

## Manual Testing

### 1. Start NATS Server

```bash
# For local testing without TLS
nats-server -p 4222
```

### 2. Run Mock Sync Server (optional)

If you want to test the full preflight flow:

```bash
cd Testing/
go run test_nats_with_mock_server.go -port 8080
```

### 3. Configure Santa

```bash
# Set sync server URL
sudo defaults write /Library/Preferences/com.northpolesec.santa.plist SyncBaseURL http://localhost:8080

# For local testing without TLS
export SANTA_NATS_DISABLE_TLS=1
```

### 4. Run Santa Sync Service

```bash
# Build
bazel build //Source/santasyncservice:santasyncservice

# Run with debug logging
sudo SANTA_NATS_DISABLE_TLS=1 ./bazel-bin/Source/santasyncservice/santasyncservice
```

### 5. Monitor Logs

In separate terminals:
```bash
# NATS server logs
tail -f /tmp/nats-server.log

# Mock sync server logs (if running)
tail -f /tmp/mock-sync-server.log

# Santa logs
log stream --predicate 'process == "santasyncservice"' --level debug
```

## Expected Behavior

1. **Initial State**: NATS client initializes but doesn't connect
2. **Preflight**: Client receives push configuration from sync server
3. **Connection**: Client connects to NATS with:
   - Server: `<push_server>.push.northpole.security:443` (or port 4222 if TLS disabled)
   - Authentication: nkey and JWT from preflight
4. **Subscriptions**: Client subscribes to:
   - `santa.<machine-id>` - device-specific messages
   - All tags from preflight response
5. **Reconnection**: When connection is lost and restored:
   - Client automatically reconnects to NATS server
   - Triggers a sync with random jitter (0-30 seconds) to avoid thundering herd
   - This ensures any missed push notifications are handled

## Troubleshooting

- **Connection fails**: Check NATS server is running and accessible
- **TLS errors**: Ensure `SANTA_NATS_DISABLE_TLS=1` is set for local testing
- **No preflight config**: Verify mock sync server is running and Santa is configured with correct URL
- **Authentication fails**: Check nkey and JWT format in preflight response

## JetStream Support

The NATS client now supports JetStream subscriptions by default for improved message delivery guarantees:

### Default JetStream Configuration

JetStream is now enabled by default with the following setup:
- **santa.host.*** topics: Durable consumer per device for device-specific messages
- **santa.tag.*** topics: Durable consumer for all tag-based messages
- Automatic catch-up on missed messages after reconnection
- Pull-based consumers for better flow control

### Testing JetStream

1. **Start NATS with JetStream**:
```bash
nats-server -js
```

2. **Create required streams**:
```bash
# Stream for host-specific messages
nats stream add SANTA_HOSTS --subjects "santa.host.*" --storage memory --replicas 1 --retention limits --discard old

# Stream for tag messages
nats stream add SANTA_TAGS --subjects "santa.tag.>" --storage memory --replicas 1 --retention limits --discard old
```

3. **Test message persistence**:
```bash
# Publish a test message while Santa is disconnected
nats pub santa.host.testdevice "test message"

# When Santa reconnects, it will catch up on missed messages
```

4. **Run JetStream tests**:
```bash
export NATS_JETSTREAM_TEST=1
bazel test //Source/santasyncservice:SNTPushClientNATSIntegrationTest --test_env=NATS_INTEGRATION_TEST=1 --test_env=NATS_JETSTREAM_TEST=1
```

### JetStream vs Core NATS

- **Core NATS**: Can be used as fallback with at-most-once delivery
- **JetStream**: Default mode with persistence, guaranteed delivery, and automatic catch-up on reconnect

### Disabling JetStream

To disable JetStream and use Core NATS:
```objc
// In code
[pushClient configureJetStream:NO];
```

## Production Deployment

In production:
- TLS is always enabled (port 443)
- Server domain is automatically appended with `.push.northpole.security`
- Valid nkey and JWT must be provided by the sync server
- No environment variables needed
- JetStream can be enabled per deployment based on requirements