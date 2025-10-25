/// Copyright 2025 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     https://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#import <XCTest/XCTest.h>
#import <OCMock/OCMock.h>

#import "Source/common/SNTConfigurator.h"
#import "Source/santasyncservice/SNTPushClientNATS.h"

// Include NATS C client header
extern "C" {
#import "src/nats.h"
}

// Expose private methods and properties for testing
@interface SNTPushClientNATS (ConnectionTesting)
@property(nonatomic) natsConnection *conn;
@property(nonatomic, copy) NSString *pushServer;
@property(nonatomic, copy) NSString *pushToken;
@property(nonatomic, copy) NSString *jwt;
@property(nonatomic, copy) NSArray<NSString *> *tags;
@property(nonatomic) BOOL hasSyncedWithServer;
@property(nonatomic, readwrite) BOOL isConnected;
- (void)connect;
@end

/// This test focuses on the NATS connection logic independent of preflight
/// It allows testing the connection behavior with pre-configured values
@interface SNTPushClientNATSConnectionTest : XCTestCase
@property id mockConfigurator;
@property id mockSyncDelegate;
@property SNTPushClientNATS *client;
@end

@implementation SNTPushClientNATSConnectionTest

- (void)setUp {
  [super setUp];
  
  // Skip these tests unless explicitly enabled
  if (!getenv("NATS_INTEGRATION_TEST")) {
    XCTSkip(@"NATS connection tests require NATS_INTEGRATION_TEST=1 and a running NATS server");
    return;
  }
  
  self.mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([self.mockConfigurator configurator]).andReturn(self.mockConfigurator);
  
  // Set up machine ID to match our test user credentials (hexadecimal only)
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

#pragma mark - Direct Configuration Tests

- (void)testDirectConfigurationAndConnection {
  // Given: Client is initialized
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];
  
  // When: Directly configure the client
  [self.client configureWithPushServer:@"localhost"
                            pushToken:@"SUACBNSCZDJFQNXSNUMNMPHN7UY5AWS42E6VMQXVTKCU2KJYBR75MVDPJQ"
                                  jwt:@"eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiJPR1NBRFVWVUdQV0NFNkk2UlNTRTdYTlpZVzRYQTRMNTZJV0NOVE9DQ0pYWjdHTVNDMjdBIiwiaWF0IjoxNzYxMzk2NjM5LCJpc3MiOiJBRE40R1VISEtNR01MMkQyQURFTFBVWUVGRjNRWU5JNERWTjZGNDNKUFA2R0k3VjRTVVlTSlRCNCIsIm5hbWUiOiJ0ZXN0LW1hY2hpbmUtMTIzNDUiLCJzdWIiOiJVQ043WTQ1VzVLTkE3V01ZTVdSQVVRSkRDSEVOQ1o3N1BSWVNCMkhYSENNUFRBNlBXRVZMVVRNTyIsIm5hdHMiOnsicHViIjp7fSwic3ViIjp7ImFsbG93IjpbInNhbnRhLWNsaWVudHMiLCJzYW50YS4qIiwic2FudGEuaG9zdC4qIiwic2FudGEudGFnLioiLCJ3b3Jrc2hvcCJdfSwicmVzcCI6eyJtYXgiOjEsInR0bCI6MH0sInN1YnMiOi0xLCJkYXRhIjotMSwicGF5bG9hZCI6LTEsInR5cGUiOiJ1c2VyIiwidmVyc2lvbiI6Mn19.ieJNiXBnlTPQ2sLy-A2-s-mobMWO0uNH621coUax4CZDbnprqFDR2X2OUp3w62dmxcNvkQeMSnhCOckEkMgTDw"
                                 tags:@[@"santa-clients", @"workshop"]];
  
  // Give async configuration time to complete
  [NSThread sleepForTimeInterval:0.1];
  
  // Then: Verify configuration was stored correctly
  XCTAssertTrue(self.client.hasSyncedWithServer);
  
  // Check if domain suffix is disabled
  if (getenv("SANTA_NATS_DISABLE_DOMAIN_SUFFIX")) {
    XCTAssertEqualObjects(self.client.pushServer, @"localhost");
  } else {
    XCTAssertEqualObjects(self.client.pushServer, @"localhost.push.northpole.security");
  }
  
  XCTAssertEqualObjects(self.client.pushToken, @"SUACBNSCZDJFQNXSNUMNMPHN7UY5AWS42E6VMQXVTKCU2KJYBR75MVDPJQ");
  XCTAssertTrue([self.client.jwt hasPrefix:@"eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ"]);
  XCTAssertEqual(self.client.tags.count, 2);
  
  // When: Explicitly connect
  [self.client connectIfConfigured];
  [NSThread sleepForTimeInterval:0.5];
  
  // Then: Should be connected (assuming local NATS server is running)
  XCTAssertTrue(self.client.isConnected);
  XCTAssertTrue(self.client.conn != NULL, @"Connection should be established");
}

- (void)testConnectWithoutConfiguration {
  // Given: Client is initialized but not configured
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];
  
  // When: Attempt to connect without configuration
  [self.client connectIfConfigured];
  [NSThread sleepForTimeInterval:0.2];
  
  // Then: Should not connect
  XCTAssertFalse(self.client.isConnected);
  XCTAssertTrue(self.client.conn == NULL, @"Connection should not be established");
}

- (void)testPartialConfiguration {
  // Given: Client with partial configuration (missing JWT)
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];
  
  [self.client configureWithPushServer:@"localhost"
                            pushToken:@"UADJHFAVSNFSSBVRCTGTTXWXHYRNTTDKEEKZFADF5CJ6KGZOKT2A7WZM"
                                  jwt:nil
                                 tags:@[@"test-tag"]];
  
  [NSThread sleepForTimeInterval:0.1];
  
  // When: Attempt to connect
  [self.client connectIfConfigured];
  [NSThread sleepForTimeInterval:0.2];
  
  // Then: Should not connect due to missing JWT
  XCTAssertFalse(self.client.isConnected);
}

- (void)testServerDomainAppending {
  // Given: Client configured with just a server name
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];
  
  [self.client configureWithPushServer:@"production"
                            pushToken:@"test-key"
                                  jwt:@"test-jwt"
                                 tags:nil];
  
  [NSThread sleepForTimeInterval:0.1];
  
  // Then: Server should have .push.northpole.security appended (unless disabled)
  if (getenv("SANTA_NATS_DISABLE_DOMAIN_SUFFIX")) {
    XCTAssertEqualObjects(self.client.pushServer, @"production");
  } else {
    XCTAssertEqualObjects(self.client.pushServer, @"production.push.northpole.security");
  }
}

- (void)testMultipleConfigurationCalls {
  // Given: Client is initialized
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];
  
  // When: Configure multiple times
  [self.client configureWithPushServer:@"server1"
                            pushToken:@"token1"
                                  jwt:@"jwt1"
                                 tags:@[@"tag1"]];
  
  [NSThread sleepForTimeInterval:0.1];
  
  [self.client configureWithPushServer:@"server2"
                            pushToken:@"token2"
                                  jwt:@"jwt2"
                                 tags:@[@"tag2", @"tag3"]];
  
  [NSThread sleepForTimeInterval:0.1];
  
  // Then: Should use latest configuration
  if (getenv("SANTA_NATS_DISABLE_DOMAIN_SUFFIX")) {
    XCTAssertEqualObjects(self.client.pushServer, @"server2");
  } else {
    XCTAssertEqualObjects(self.client.pushServer, @"server2.push.northpole.security");
  }
  XCTAssertEqualObjects(self.client.pushToken, @"token2");
  XCTAssertEqualObjects(self.client.jwt, @"jwt2");
  XCTAssertEqual(self.client.tags.count, 2);
}

- (void)testConnectionWithValidNKeyAndJWT {
  // Given: Client with valid NATS credentials
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];
  
  // Use the actual test credentials we generated
  NSString *validNKey = @"SUACBNSCZDJFQNXSNUMNMPHN7UY5AWS42E6VMQXVTKCU2KJYBR75MVDPJQ";
  NSString *validJWT = @"eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiI0N1dWSzdBUkpUV1c1NFhJSENIVDU1SlM3M1dWU1VUTUxUV1U0SUdPUlVJVUFHUVRLQkdRIiwiaWF0IjoxNzYxMzk3NjA4LCJpc3MiOiJBRE40R1VISEtNR01MMkQyQURFTFBVWUVGRjNRWU5JNERWTjZGNDNKUFA2R0k3VjRTVVlTSlRCNCIsIm5hbWUiOiJ0ZXN0LW1hY2hpbmUtMTIzNDUiLCJzdWIiOiJVQ043WTQ1VzVLTkE3V01ZTVdSQVVRSkRDSEVOQ1o3N1BSWVNCMkhYSENNUFRBNlBXRVZMVVRNTyIsIm5hdHMiOnsicHViIjp7ImFsbG93IjpbIl9JTkJPWC5cdTAwM2UiXX0sInN1YiI6eyJhbGxvdyI6WyJfSU5CT1guXHUwMDNlIiwic2FudGEtY2xpZW50cyIsInNhbnRhLioiLCJzYW50YS5ob3N0LioiLCJzYW50YS50YWcuKiIsIndvcmtzaG9wIl19LCJyZXNwIjp7Im1heCI6MSwidHRsIjowfSwic3VicyI6LTEsImRhdGEiOi0xLCJwYXlsb2FkIjotMSwidHlwZSI6InVzZXIiLCJ2ZXJzaW9uIjoyfX0.L2C1512oLT6KDkgRLN8Ggl5Pa9ZQ1_a_NCqL8YZyzp9ot4PwHLHkLsGNuIgodRYi7LWybYKKIPJN1eRTxs0CDw";
  
  [self.client configureWithPushServer:@"localhost"
                            pushToken:validNKey
                                  jwt:validJWT
                                 tags:@[@"santa-clients", @"workshop"]];
  
  [NSThread sleepForTimeInterval:0.1];
  
  // When: Connect with valid credentials
  [self.client connectIfConfigured];
  [NSThread sleepForTimeInterval:0.5];
  
  // Then: Should connect successfully
  // (This will fail with invalid credentials or if NATS server doesn't accept them)
  XCTAssertTrue(self.client.isConnected, @"Should connect with valid nkey/JWT");
}

@end