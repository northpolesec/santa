#!/bin/bash
# Run NATS integration tests

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"

echo "Santa NATS Integration Test Runner"
echo "=================================="

# Check if NATS server is installed
if ! command -v nats-server &> /dev/null; then
    echo "❌ NATS server not found. Please install it first:"
    echo "   brew install nats-server"
    exit 1
fi

# Start NATS server
echo "Starting NATS server on port 4222..."
nats-server -p 4222 > /tmp/nats-test-server.log 2>&1 &
NATS_PID=$!
echo "NATS server started with PID: $NATS_PID"

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "Cleaning up..."
    if [ ! -z "$NATS_PID" ]; then
        kill $NATS_PID 2>/dev/null || true
    fi
}
trap cleanup EXIT

# Give server time to start
sleep 2

# Run the integration tests
cd "$PROJECT_ROOT"
echo ""
echo "Running NATS integration tests..."
echo "================================"

# Set environment variable to enable the tests and disable TLS for localhost
export NATS_INTEGRATION_TEST=1
export SANTA_NATS_DISABLE_TLS=1

# Run the tests
echo "Running integration tests..."
bazel test //Source/santasyncservice:SNTPushClientNATSIntegrationTest \
    --test_env=NATS_INTEGRATION_TEST=1 \
    --test_env=SANTA_NATS_DISABLE_TLS=1 \
    --test_output=all

echo ""
echo "Running connection tests..."
bazel test //Source/santasyncservice:SNTPushClientNATSConnectionTest \
    --test_env=NATS_INTEGRATION_TEST=1 \
    --test_env=SANTA_NATS_DISABLE_TLS=1 \
    --test_output=all

echo ""
echo "Integration tests completed!"