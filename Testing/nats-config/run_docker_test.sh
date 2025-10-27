#!/bin/bash
# Test Santa NATS client against Docker instance with JWT auth

echo "Santa NATS Docker JWT Test"
echo "=========================="
echo ""
echo "This test verifies JWT permissions against the Docker NATS server."
echo ""

# Monitor Docker logs
echo "Starting log monitor..."
docker logs -f 0fd519624d0e --tail 0 > /tmp/nats-docker-test.log 2>&1 &
LOG_PID=$!

cleanup() {
    kill $LOG_PID 2>/dev/null || true
    echo ""
    echo "JWT Violations detected during test:"
    echo "===================================="
    grep -E "(Subscription|Publish) Violation" /tmp/nats-docker-test.log || echo "No violations detected"
    rm -f /tmp/nats-docker-test.log
}
trap cleanup EXIT

# Run Go test
echo "Testing JWT permissions..."
cd "$(dirname "$0")"
go run test_jwt_violations.go

echo ""
echo "Waiting for logs to flush..."
sleep 2