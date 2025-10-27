#!/bin/bash
# Script to trigger JWT violations for testing

echo "Triggering JWT violations in Docker NATS..."
echo ""

# Monitor logs
docker logs -f 0fd519624d0e --tail 0 > /tmp/jwt-violations.log 2>&1 &
LOG_PID=$!

cleanup() {
    kill $LOG_PID 2>/dev/null || true
    echo ""
    echo "JWT Violations:"
    echo "=============="
    grep -E "(Subscription|Publish) Violation" /tmp/jwt-violations.log
    rm -f /tmp/jwt-violations.log
}
trap cleanup EXIT

# Run the violations test
cd /Users/peterm/src/northpole-santa-local/Testing/nats-config
go run test_jwt_violations.go

sleep 2