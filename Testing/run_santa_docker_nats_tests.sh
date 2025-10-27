#!/bin/bash
# Run Santa NATS integration tests against Docker NATS instance with JWT auth

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"

echo "Santa NATS Docker Integration Test Runner"
echo "========================================"
echo ""

# Check if Docker NATS is running
if ! docker ps | grep -q nats; then
    echo "❌ Docker NATS server not running. Please start it first:"
    echo "   docker run -d -p 443:4222 -p 8222:8222 -v $PWD/nats-config/nats-server.conf:/etc/nats-server.conf:ro nats -c /etc/nats-server.conf"
    exit 1
fi

# Get container ID
CONTAINER_ID=$(docker ps | grep nats | awk '{print $1}')
echo "Using Docker NATS container: $CONTAINER_ID"

# Monitor Docker logs in background
echo "Starting Docker NATS log monitor..."
docker logs -f $CONTAINER_ID --tail 0 > /tmp/santa-nats-docker-test.log 2>&1 &
LOG_PID=$!

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "Cleaning up..."
    if [ ! -z "$LOG_PID" ]; then
        kill $LOG_PID 2>/dev/null || true
    fi
    
    echo ""
    echo "Docker NATS log summary:"
    echo "======================="
    
    # Count different types of violations
    SUB_VIOLATIONS=$(grep -c "Subscription Violation" /tmp/santa-nats-docker-test.log 2>/dev/null || echo "0")
    PUB_VIOLATIONS=$(grep -c "Publish Violation" /tmp/santa-nats-docker-test.log 2>/dev/null || echo "0")
    AUTH_ERRORS=$(grep -c "authentication error" /tmp/santa-nats-docker-test.log 2>/dev/null || echo "0")
    
    echo "Subscription Violations: $SUB_VIOLATIONS"
    echo "Publish Violations: $PUB_VIOLATIONS"
    echo "Authentication Errors: $AUTH_ERRORS"
    
    if [ $SUB_VIOLATIONS -gt 0 ] || [ $PUB_VIOLATIONS -gt 0 ]; then
        echo ""
        echo "JWT Violations detected:"
        echo "----------------------"
        grep -E "(Subscription|Publish) Violation" /tmp/santa-nats-docker-test.log | head -20
        
        echo ""
        echo "⚠️  Note: JWT violations are expected due to permission restrictions"
        echo "   - Client JWT can only publish to _INBOX.>"
        echo "   - Client JWT cannot subscribe to some subjects"
    fi
    
    rm -f /tmp/santa-nats-docker-test.log
}
trap cleanup EXIT

# Run the integration tests
cd "$PROJECT_ROOT"
echo ""
echo "Running NATS integration tests against Docker instance..."
echo "========================================================"

# Set environment variables to connect to Docker NATS
export NATS_INTEGRATION_TEST=1
export SANTA_NATS_DISABLE_TLS=1  # Docker NATS is on port 443 but not using TLS

# First, run connection tests
echo ""
echo "1. Running connection tests..."
echo "------------------------------"
bazel test //Source/santasyncservice:SNTPushClientNATSConnectionTest \
    --test_env=NATS_INTEGRATION_TEST=1 \
    --test_env=SANTA_NATS_DISABLE_TLS=1 \
    --test_output=all \
    --nocache_test_results || true

# Then run integration tests
echo ""
echo "2. Running integration tests..."
echo "-------------------------------"
bazel test //Source/santasyncservice:SNTPushClientNATSIntegrationTest \
    --test_env=NATS_INTEGRATION_TEST=1 \
    --test_env=SANTA_NATS_DISABLE_TLS=1 \
    --test_output=all \
    --nocache_test_results || true

# Give logs time to flush
echo ""
echo "Waiting for logs to flush..."
sleep 2

echo ""
echo "Tests completed!"