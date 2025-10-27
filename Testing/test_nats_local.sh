#!/bin/bash
# Script to test NATS client locally

echo "NATS Local Testing Script"
echo "========================"

# Check if NATS server is installed
if ! command -v nats-server &> /dev/null; then
    echo "❌ NATS server not found. Please install it first:"
    echo "   brew install nats-server"
    exit 1
fi

# Start NATS server in the background
echo "Starting NATS server on port 4222..."
nats-server -p 4222 &
NATS_PID=$!
echo "NATS server started with PID: $NATS_PID"

# Give the server time to start
sleep 2

# Set environment variable to disable TLS for local testing
export SANTA_NATS_DISABLE_TLS=1

echo ""
echo "To test the NATS client:"
echo "1. Build Santa with: bazel build //Source/santasyncservice:santasyncservice"
echo "2. Run the sync service with debug logging"
echo "3. The NATS client will wait for preflight configuration"
echo ""
echo "To simulate a preflight response with NATS config:"
echo "- pushServer: 'localhost' (will be appended with .push.northpole.security)"
echo "- pushNKey: 'test-nkey'"
echo "- pushJWT: 'test-jwt'"
echo "- pushTags: ['tag1', 'tag2']"
echo ""
echo "Press Ctrl+C to stop the NATS server"

# Keep the script running
wait $NATS_PID