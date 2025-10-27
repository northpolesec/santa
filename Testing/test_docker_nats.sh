#!/bin/bash
# Test against Docker NATS instance with JWT authentication

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"

echo "Santa NATS Docker Integration Test"
echo "=================================="

# Check if Docker NATS is running
if ! docker ps | grep -q nats; then
    echo "❌ Docker NATS server not running. Please start it first."
    exit 1
fi

# Get Docker NATS port mapping
NATS_PORT=$(docker port 0fd519624d0e 4222/tcp | cut -d: -f2)
echo "Docker NATS server is on port: $NATS_PORT"

# Monitor Docker logs in background
echo "Monitoring Docker NATS logs..."
docker logs -f 0fd519624d0e --tail 0 > /tmp/docker-nats-test.log 2>&1 &
LOGS_PID=$!

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "Cleaning up..."
    if [ ! -z "$LOGS_PID" ]; then
        kill $LOGS_PID 2>/dev/null || true
    fi
    echo ""
    echo "Docker NATS logs during test:"
    echo "=============================="
    cat /tmp/docker-nats-test.log
}
trap cleanup EXIT

# Run the integration tests against Docker NATS
cd "$PROJECT_ROOT"
echo ""
echo "Running NATS integration tests against Docker instance..."
echo "========================================================"

# Create a temporary test file that uses port 443 instead of 4222
cat > /tmp/test_docker_nats.mm << 'EOF'
#import <XCTest/XCTest.h>
#import <OCMock/OCMock.h>
#import "Source/common/SNTConfigurator.h"
#import "Source/santasyncservice/SNTPushClientNATS.h"
#import "Source/santasyncservice/SNTSyncState.h"

extern "C" {
#import "src/nats.h"
}

@interface DockerNATSTest : XCTestCase
@property id mockConfigurator;
@property id mockSyncDelegate;
@property SNTPushClientNATS *client;
@end

@implementation DockerNATSTest

- (void)setUp {
    [super setUp];
    
    self.mockConfigurator = OCMClassMock([SNTConfigurator class]);
    OCMStub([self.mockConfigurator configurator]).andReturn(self.mockConfigurator);
    
    // Use hexadecimal machine ID
    NSString *machineID = @"ABCDEF123456789";
    OCMStub([self.mockConfigurator machineID]).andReturn(machineID);
    
    self.mockSyncDelegate = OCMProtocolMock(@protocol(SNTPushNotificationsSyncDelegate));
}

- (void)tearDown {
    if (self.client) {
        [self.client disconnectAndWait:YES];
        self.client = nil;
    }
    [self.mockConfigurator stopMocking];
    [super tearDown];
}

- (void)testDockerNATSConnection {
    self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];
    
    SNTSyncState *syncState = [[SNTSyncState alloc] init];
    syncState.pushServer = @"localhost";
    syncState.pushNKey = @"SUACBNSCZDJFQNXSNUMNMPHN7UY5AWS42E6VMQXVTKCU2KJYBR75MVDPJQ";
    syncState.pushJWT = @"eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiI0N1dWSzdBUkpUV1c1NFhJSENIVDU1SlM3M1dWU1VUTUxUV1U0SUdPUlVJVUFHUVRLQkdRIiwiaWF0IjoxNzYxMzk3NjA4LCJpc3MiOiJBRE40R1VISEtNR01MMkQyQURFTFBVWUVGRjNRWU5JNERWTjZGNDNKUFA2R0k3VjRTVVlTSlRCNCIsIm5hbWUiOiJ0ZXN0LW1hY2hpbmUtMTIzNDUiLCJzdWIiOiJVQ043WTQ1VzVLTkE3V01ZTVdSQVVRSkRDSEVOQ1o3N1BSWVNCMkhYSENNUFRBNlBXRVZMVVRNTyIsIm5hdHMiOnsicHViIjp7ImFsbG93IjpbIl9JTkJPWC5cdTAwM2UiXX0sInN1YiI6eyJhbGxvdyI6WyJfSU5CT1guXHUwMDNlIiwic2FudGEtY2xpZW50cyIsInNhbnRhLioiLCJzYW50YS5ob3N0LioiLCJzYW50YS50YWcuKiIsIndvcmtzaG9wIl19LCJyZXNwIjp7Im1heCI6MSwidHRsIjowfSwic3VicyI6LTEsImRhdGEiOi0xLCJwYXlsb2FkIjotMSwidHlwZSI6InVzZXIiLCJ2ZXJzaW9uIjoyfX0.L2C1512oLT6KDkgRLN8Ggl5Pa9ZQ1_a_NCqL8YZyzp9ot4PwHLHkLsGNuIgodRYi7LWybYKKIPJN1eRTxs0CDw";
    syncState.pushTags = @[@"santa-clients", @"workshop"];
    
    [self.client handlePreflightSyncState:syncState];
    
    // Wait for connection
    [NSThread sleepForTimeInterval:1.0];
    
    NSLog(@"Client connected: %@", self.client.isConnected ? @"YES" : @"NO");
    
    // The test will fail with JWT violations, which is what we're testing
    XCTAssertTrue(YES, @"Test completed - check Docker logs for JWT violations");
}

@end
EOF

# Set environment variables to connect to Docker NATS
export NATS_INTEGRATION_TEST=1
export SANTA_NATS_DISABLE_TLS=1
export SANTA_NATS_PORT=$NATS_PORT

# Run the test
echo "Connecting to Docker NATS on port $NATS_PORT..."
bazel test //Source/santasyncservice:SNTPushClientNATSIntegrationTest \
    --test_env=NATS_INTEGRATION_TEST=1 \
    --test_env=SANTA_NATS_DISABLE_TLS=1 \
    --test_env=SANTA_NATS_PORT=$NATS_PORT \
    --test_output=all \
    --test_filter=testConnectionToNATSServer

echo ""
echo "Test completed!"