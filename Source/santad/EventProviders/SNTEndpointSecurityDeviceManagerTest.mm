/// Copyright 2022 Google Inc. All rights reserved.
/// Copyright 2024 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     http://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#import <DiskArbitration/DiskArbitration.h>
#include <EndpointSecurity/EndpointSecurity.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#import <bsm/libbsm.h>
#import <dispatch/dispatch.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <sys/mount.h>
#include <cstddef>

#include <memory>
#include <set>

#include "Source/common/Platform.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTDeviceEvent.h"
#import "Source/common/SNTStoredNetworkMountEvent.h"
#include "Source/common/TestUtils.h"
#include "Source/common/es/Message.h"
#include "Source/common/es/MockEndpointSecurityAPI.h"
#include "Source/common/es/MockEnricher.h"
#import "Source/common/es/SNTEndpointSecurityClient.h"
#include "Source/santad/EventProviders/AuthResultCache.h"
#import "Source/santad/EventProviders/DiskArbitrationTestUtil.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityDeviceManager.h"
#include "Source/santad/Metrics.h"

using santa::AuthResultCache;
using santa::EventDisposition;
using santa::FlushCacheMode;
using santa::FlushCacheReason;
using santa::Message;

class MockAuthResultCache : public AuthResultCache {
 public:
  using AuthResultCache::AuthResultCache;

  MOCK_METHOD(void, FlushCache, (FlushCacheMode mode, FlushCacheReason reason));
};

@interface SNTEndpointSecurityClient (Testing)
@property(nonatomic) double defaultBudget;
@property(nonatomic) int64_t minAllowedHeadroom;
@property(nonatomic) int64_t maxAllowedHeadroom;
@end

@interface SNTEndpointSecurityDeviceManager (Testing)
- (instancetype)init;
- (void)logDiskAppeared:(NSDictionary*)props allowed:(bool)allowed;
- (BOOL)shouldOperateOnDiskWithProperties:(NSDictionary*)diskInfo;
- (void)performStartupTasks:(SNTDeviceManagerStartupPreferences)startupPrefs;
- (uint32_t)updatedMountFlags:(struct statfs*)sfs remountArgs:(NSArray<NSString*>*)args;
- (DADissenterRef __nullable)handleEncryptedMountApproval:(DADiskRef)disk;
- (void)handleEncryptedRemountCompletion:(DADiskRef)disk
                               dissenter:(DADissenterRef __nullable)dissenter;
@property(nonatomic, readonly) dispatch_queue_t diskQueue;
@property(nonatomic) NSMutableSet<NSString*>* remountingDisks;
@end

@interface SNTEndpointSecurityDeviceManagerTest : XCTestCase
@property id mockConfigurator;
@property MockDiskArbitration* mockDA;
@property MockMounts* mockMounts;
@end

@implementation SNTEndpointSecurityDeviceManagerTest

- (void)setUp {
  [super setUp];

  self.mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([self.mockConfigurator configurator]).andReturn(self.mockConfigurator);
  OCMStub([self.mockConfigurator eventLogType]).andReturn(-1);

  self.mockDA = [MockDiskArbitration mockDiskArbitration];
  [self.mockDA reset];

  self.mockMounts = [MockMounts mockMounts];
  [self.mockMounts reset];

  fclose(stdout);
}

- (void)triggerTestMountEvent:(es_event_type_t)eventType
            diskInfoOverrides:(NSDictionary*)diskInfo
           expectedAuthResult:(es_auth_result_t)expectedAuthResult
           deviceManagerSetup:(void (^)(SNTEndpointSecurityDeviceManager*))setupDMCallback {
  struct statfs fs = {0};
  NSString* test_mntfromname = @"/dev/disk2s1";
  NSString* test_mntonname = @"/Volumes/KATE'S 4G";

  strncpy(fs.f_mntfromname, [test_mntfromname UTF8String], sizeof(fs.f_mntfromname));
  strncpy(fs.f_mntonname, [test_mntonname UTF8String], sizeof(fs.f_mntonname));

  MockDADisk* disk = [[MockDADisk alloc] init];
  disk.diskDescription = @{
    (__bridge NSString*)kDADiskDescriptionDeviceProtocolKey : @"USB",
    (__bridge NSString*)kDADiskDescriptionMediaRemovableKey : @YES,
    @"DAVolumeMountable" : @YES,
    @"DAVolumePath" : test_mntonname,
    @"DADeviceModel" : @"Some device model",
    @"DADevicePath" : test_mntonname,
    @"DADeviceVendor" : @"Some vendor",
    @"DAAppearanceTime" : @0,
    @"DAMediaBSDName" : test_mntfromname,
  };

  if (diskInfo != nil) {
    NSMutableDictionary* mergedDiskDescription = [disk.diskDescription mutableCopy];
    for (NSString* key in diskInfo) {
      mergedDiskDescription[key] = diskInfo[key];
    }
    disk.diskDescription = (NSDictionary*)mergedDiskDescription;
  }

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsESNewClient();

  auto mockEnricher = std::make_shared<santa::MockEnricher>();

  SNTEndpointSecurityDeviceManager* deviceManager = [[SNTEndpointSecurityDeviceManager alloc]
                            initWithESAPI:mockESApi
                                  metrics:nullptr
                                   logger:nullptr
                                 enricher:mockEnricher
                          authResultCache:nullptr
                     removableMediaAction:SNTRemovableMediaActionAllow
               removableMediaRemountFlags:nil
            encryptedRemovableMediaAction:SNTRemovableMediaActionAllow
      encryptedRemovableMediaRemountFlags:nil
                       startupPreferences:SNTDeviceManagerStartupPreferencesNone];

  setupDMCallback(deviceManager);

  // Stub the log method since a mock `Logger` object isn't used.
  id partialDeviceManager = OCMPartialMock(deviceManager);
  OCMStub([partialDeviceManager logDiskAppeared:OCMOCK_ANY allowed:OCMOCK_ANY])
      .ignoringNonObjectArgs();

  [self.mockDA insert:disk];

  es_file_t file = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&file);

  // This test is sensitive to ~1s processing budget.
  // Set a 5s headroom and 6s deadline
  deviceManager.minAllowedHeadroom = 5 * NSEC_PER_SEC;
  deviceManager.maxAllowedHeadroom = 5 * NSEC_PER_SEC;
  es_message_t esMsg = MakeESMessage(eventType, &proc, ActionType::Auth, 6000);

  dispatch_semaphore_t semaMetrics = dispatch_semaphore_create(0);

  __block int retainCount = 0;
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  EXPECT_CALL(*mockESApi, ReleaseMessage).WillRepeatedly(^{
    if (retainCount == 0) {
      XCTFail(@"Under retain!");
    }
    retainCount--;
    if (retainCount == 0) {
      dispatch_semaphore_signal(sema);
    }
  });
  EXPECT_CALL(*mockESApi, RetainMessage).WillRepeatedly(^{
    retainCount++;
  });

  if (eventType == ES_EVENT_TYPE_AUTH_MOUNT) {
    esMsg.event.mount.statfs = &fs;
  } else if (eventType == ES_EVENT_TYPE_AUTH_REMOUNT) {
    esMsg.event.remount.statfs = &fs;
  } else {
    // Programming error. Fail the test.
    XCTFail(@"Unhandled event type in test: %d", eventType);
  }

  XCTestExpectation* mountExpectation =
      [self expectationWithDescription:@"Wait for response from ES"];

  EXPECT_CALL(*mockESApi, RespondAuthResult(testing::_, testing::_, expectedAuthResult, false))
      .WillOnce(testing::InvokeWithoutArgs(^bool {
        [mountExpectation fulfill];
        return true;
      }));

  [deviceManager handleMessage:Message(mockESApi, &esMsg)
            recordEventMetrics:^(EventDisposition d) {
              XCTAssertEqual(
                  d, (deviceManager.removableMediaAction != SNTRemovableMediaActionAllow ||
                      deviceManager.encryptedRemovableMediaAction != SNTRemovableMediaActionAllow)
                         ? EventDisposition::kProcessed
                         : EventDisposition::kDropped);
              dispatch_semaphore_signal(semaMetrics);
            }];

  [self waitForExpectations:@[ mountExpectation ] timeout:60.0];

  XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");
  XCTAssertSemaTrue(sema, 5, "Failed waiting for message to be processed...");

  [partialDeviceManager stopMocking];
  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
  XCTBubbleMockVerifyAndClearExpectations(mockEnricher.get());
}

- (void)testUSBBlockDisabled {
  [self triggerTestMountEvent:ES_EVENT_TYPE_AUTH_MOUNT
            diskInfoOverrides:nil
           expectedAuthResult:ES_AUTH_RESULT_ALLOW
           deviceManagerSetup:^(SNTEndpointSecurityDeviceManager* dm) {
             dm.removableMediaAction = SNTRemovableMediaActionAllow;
           }];
}

- (void)testRemount {
  NSArray* wantRemountArgs = @[ @"noexec", @"rdonly" ];

  XCTestExpectation* expectation =
      [self expectationWithDescription:
                @"Wait for SNTEndpointSecurityDeviceManager's blockCallback to trigger"];

  __block NSString *gotmntonname, *gotmntfromname;
  __block NSArray<NSString*>* gotRemountedArgs;

  [self triggerTestMountEvent:ES_EVENT_TYPE_AUTH_MOUNT
            diskInfoOverrides:nil
           expectedAuthResult:ES_AUTH_RESULT_DENY
           deviceManagerSetup:^(SNTEndpointSecurityDeviceManager* dm) {
             dm.removableMediaAction = SNTRemovableMediaActionRemount;
             dm.removableMediaRemountFlags = wantRemountArgs;

             dm.deviceBlockCallback =
                 ^(SNTDeviceEvent* event, SNTStoredUSBMountEvent* usbMountEvent) {
                   gotRemountedArgs = event.remountArgs;
                   gotmntonname = event.mntonname;
                   gotmntfromname = event.mntfromname;
                   [expectation fulfill];
                 };
           }];

  XCTAssertEqual(self.mockDA.insertedDevices.count, 1);
  XCTAssertTrue([self.mockDA.insertedDevices allValues][0].wasMounted);

  [self waitForExpectations:@[ expectation ] timeout:60.0];

  XCTAssertEqualObjects(gotRemountedArgs, wantRemountArgs);
  XCTAssertEqualObjects(gotmntonname, @"/Volumes/KATE'S 4G");
  XCTAssertEqualObjects(gotmntfromname, @"/dev/disk2s1");
}

- (void)testBlockNoRemount {
  XCTestExpectation* expectation =
      [self expectationWithDescription:
                @"Wait for SNTEndpointSecurityDeviceManager's blockCallback to trigger"];

  __block NSString *gotmntonname, *gotmntfromname;
  __block NSArray<NSString*>* gotRemountedArgs;

  [self triggerTestMountEvent:ES_EVENT_TYPE_AUTH_MOUNT
            diskInfoOverrides:nil
           expectedAuthResult:ES_AUTH_RESULT_DENY
           deviceManagerSetup:^(SNTEndpointSecurityDeviceManager* dm) {
             dm.removableMediaAction = SNTRemovableMediaActionBlock;

             dm.deviceBlockCallback =
                 ^(SNTDeviceEvent* event, SNTStoredUSBMountEvent* usbMountEvent) {
                   gotRemountedArgs = event.remountArgs;
                   gotmntonname = event.mntonname;
                   gotmntfromname = event.mntfromname;
                   [expectation fulfill];
                 };
           }];

  [self waitForExpectations:@[ expectation ] timeout:60.0];

  XCTAssertNil(gotRemountedArgs);
  XCTAssertEqualObjects(gotmntonname, @"/Volumes/KATE'S 4G");
  XCTAssertEqualObjects(gotmntfromname, @"/dev/disk2s1");
}

- (void)testEnsureRemountsCannotChangePerms {
  NSArray* wantRemountArgs = @[ @"noexec", @"rdonly" ];

  XCTestExpectation* expectation =
      [self expectationWithDescription:
                @"Wait for SNTEndpointSecurityDeviceManager's blockCallback to trigger"];

  __block NSString *gotmntonname, *gotmntfromname;
  __block NSArray<NSString*>* gotRemountedArgs;

  [self triggerTestMountEvent:ES_EVENT_TYPE_AUTH_MOUNT
            diskInfoOverrides:nil
           expectedAuthResult:ES_AUTH_RESULT_DENY
           deviceManagerSetup:^(SNTEndpointSecurityDeviceManager* dm) {
             dm.removableMediaAction = SNTRemovableMediaActionRemount;
             dm.removableMediaRemountFlags = wantRemountArgs;

             dm.deviceBlockCallback =
                 ^(SNTDeviceEvent* event, SNTStoredUSBMountEvent* usbMountEvent) {
                   gotRemountedArgs = event.remountArgs;
                   gotmntonname = event.mntonname;
                   gotmntfromname = event.mntfromname;
                   [expectation fulfill];
                 };
           }];

  XCTAssertEqual(self.mockDA.insertedDevices.count, 1);
  XCTAssertTrue([self.mockDA.insertedDevices allValues][0].wasMounted);

  [self waitForExpectations:@[ expectation ] timeout:10.0];

  XCTAssertEqualObjects(gotRemountedArgs, wantRemountArgs);
  XCTAssertEqualObjects(gotmntonname, @"/Volumes/KATE'S 4G");
  XCTAssertEqualObjects(gotmntfromname, @"/dev/disk2s1");
}

- (void)testEnsureDMGsDoNotPrompt {
  NSArray* wantRemountArgs = @[ @"noexec", @"rdonly" ];
  NSDictionary* diskInfo = @{
    (__bridge NSString*)kDADiskDescriptionDeviceProtocolKey : @"Virtual Interface",
    (__bridge NSString*)kDADiskDescriptionDeviceModelKey : @"Disk Image",
    (__bridge NSString*)kDADiskDescriptionMediaNameKey : @"disk image",
  };

  [self triggerTestMountEvent:ES_EVENT_TYPE_AUTH_MOUNT
            diskInfoOverrides:diskInfo
           expectedAuthResult:ES_AUTH_RESULT_ALLOW
           deviceManagerSetup:^(SNTEndpointSecurityDeviceManager* dm) {
             dm.removableMediaAction = SNTRemovableMediaActionRemount;
             dm.removableMediaRemountFlags = wantRemountArgs;

             dm.deviceBlockCallback =
                 ^(SNTDeviceEvent* event, SNTStoredUSBMountEvent* usbMountEvent) {
                   XCTFail(@"Should not be called");
                 };
           }];

  XCTAssertEqual(self.mockDA.insertedDevices.count, 1);
  XCTAssertFalse([self.mockDA.insertedDevices allValues][0].wasMounted);
}

// Test that USB4/Thunderbolt external SSDs (PCI-Express protocol) are properly blocked.
// These devices report as non-removable, non-ejectable, and use PCI-Express protocol,
// but should still be subject to mount restrictions since they are external.
// See: https://github.com/northpolesec/santa/issues/719
- (void)testUSB4ThunderboltExternalSSDBlocked {
  NSArray* wantRemountArgs = @[ @"noexec", @"rdonly" ];
  // USB4/Thunderbolt SSDs report as PCI-Express, non-removable, non-ejectable, but NOT internal
  NSDictionary* diskInfo = @{
    (__bridge NSString*)kDADiskDescriptionDeviceProtocolKey : @"PCI-Express",
    (__bridge NSString*)kDADiskDescriptionDeviceInternalKey : @NO,
    (__bridge NSString*)kDADiskDescriptionMediaRemovableKey : @NO,
    (__bridge NSString*)kDADiskDescriptionMediaEjectableKey : @NO,
    (__bridge NSString*)kDADiskDescriptionMediaKindKey : @"IOMedia",
  };

  XCTestExpectation* expectation =
      [self expectationWithDescription:
                @"Wait for SNTEndpointSecurityDeviceManager's blockCallback to trigger"];

  __block NSString *gotmntonname, *gotmntfromname;
  __block NSArray<NSString*>* gotRemountedArgs;

  [self triggerTestMountEvent:ES_EVENT_TYPE_AUTH_MOUNT
            diskInfoOverrides:diskInfo
           expectedAuthResult:ES_AUTH_RESULT_DENY
           deviceManagerSetup:^(SNTEndpointSecurityDeviceManager* dm) {
             dm.removableMediaAction = SNTRemovableMediaActionRemount;
             dm.removableMediaRemountFlags = wantRemountArgs;

             dm.deviceBlockCallback =
                 ^(SNTDeviceEvent* event, SNTStoredUSBMountEvent* usbMountEvent) {
                   gotRemountedArgs = event.remountArgs;
                   gotmntonname = event.mntonname;
                   gotmntfromname = event.mntfromname;
                   [expectation fulfill];
                 };
           }];

  XCTAssertEqual(self.mockDA.insertedDevices.count, 1);
  XCTAssertTrue([self.mockDA.insertedDevices allValues][0].wasMounted);

  [self waitForExpectations:@[ expectation ] timeout:60.0];

  XCTAssertEqualObjects(gotRemountedArgs, wantRemountArgs);
  XCTAssertEqualObjects(gotmntonname, @"/Volumes/KATE'S 4G");
  XCTAssertEqualObjects(gotmntfromname, @"/dev/disk2s1");
}

- (void)testNotifyUnmountFlushesCache {
  es_file_t file = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&file);
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_UNMOUNT, &proc);

  dispatch_semaphore_t semaMetrics = dispatch_semaphore_create(0);

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsESNewClient();
  mockESApi->SetExpectationsRetainReleaseMessage();

  auto mockAuthCache = std::make_shared<MockAuthResultCache>(nullptr, nil);
  EXPECT_CALL(*mockAuthCache, FlushCache);

  SNTEndpointSecurityDeviceManager* deviceManager = [[SNTEndpointSecurityDeviceManager alloc]
                            initWithESAPI:mockESApi
                                  metrics:nullptr
                                   logger:nullptr
                                 enricher:nullptr
                          authResultCache:mockAuthCache
                     removableMediaAction:SNTRemovableMediaActionBlock
               removableMediaRemountFlags:nil
            encryptedRemovableMediaAction:SNTRemovableMediaActionAllow
      encryptedRemovableMediaRemountFlags:nil
                       startupPreferences:SNTDeviceManagerStartupPreferencesNone];

  deviceManager.removableMediaAction = SNTRemovableMediaActionBlock;

  [deviceManager handleMessage:Message(mockESApi, &esMsg)
            recordEventMetrics:^(EventDisposition d) {
              XCTAssertEqual(d, EventDisposition::kProcessed);
              dispatch_semaphore_signal(semaMetrics);
            }];

  XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
  XCTBubbleMockVerifyAndClearExpectations(mockAuthCache.get());
}

- (void)testPerformStartupTasks {
  SNTEndpointSecurityDeviceManager* deviceManager = [[SNTEndpointSecurityDeviceManager alloc] init];

  id partialDeviceManager = OCMPartialMock(deviceManager);
  OCMStub([partialDeviceManager shouldOperateOnDiskWithProperties:nil])
      .ignoringNonObjectArgs()
      .andReturn(YES);

  deviceManager.removableMediaAction = SNTRemovableMediaActionRemount;
  deviceManager.removableMediaRemountFlags = @[ @"noexec", @"rdonly" ];

  [self.mockMounts insert:[[MockStatfs alloc] initFrom:@"d1" on:@"v1" flags:@(0x0)]];
  [self.mockMounts insert:[[MockStatfs alloc] initFrom:@"d2"
                                                    on:@"v2"
                                                 flags:@(MNT_RDONLY | MNT_NOEXEC | MNT_JOURNALED)]];

  // Disabling clang format due to local/remote version differences.
  // clang-format off
  // Create mock disks with desired args
  MockDADisk * (^CreateMockDisk)(NSString *, NSString *) =
    ^MockDADisk *(NSString *mountOn, NSString *mountFrom) {
      MockDADisk *mockDisk = [[MockDADisk alloc] init];
      mockDisk.diskDescription = @{
        @"DAVolumePath" : mountOn,      // f_mntonname,
        @"DADevicePath" : mountOn,      // f_mntonname,
        @"DAMediaBSDName" : mountFrom,  // f_mntfromname,
      };

      return mockDisk;
    };
  // clang-format on

  // Reset the Mock DA property, setup disks and remount args, then trigger the test
  void (^PerformStartupTest)(NSArray<MockDADisk*>*, NSArray<NSString*>*,
                             SNTDeviceManagerStartupPreferences) =
      ^void(NSArray<MockDADisk*>* disks, NSArray<NSString*>* remountArgs,
            SNTDeviceManagerStartupPreferences startupPref) {
        [self.mockDA reset];

        for (MockDADisk* d in disks) {
          [self.mockDA insert:d];
        }

        deviceManager.removableMediaRemountFlags = remountArgs;

        [deviceManager performStartupTasks:startupPref];
      };

  // Unmount with RemountUSBMode set
  {
    MockDADisk* disk1 = CreateMockDisk(@"v1", @"d1");
    MockDADisk* disk2 = CreateMockDisk(@"v2", @"d2");

    PerformStartupTest(@[ disk1, disk2 ], @[ @"noexec", @"rdonly" ],
                       SNTDeviceManagerStartupPreferencesUnmount);

    XCTAssertTrue(disk1.wasUnmounted);
    XCTAssertFalse(disk1.wasMounted);
    XCTAssertFalse(disk2.wasUnmounted);
    XCTAssertFalse(disk2.wasMounted);
  }

  // Unmount with RemountUSBMode nil
  {
    MockDADisk* disk1 = CreateMockDisk(@"v1", @"d1");
    MockDADisk* disk2 = CreateMockDisk(@"v2", @"d2");

    PerformStartupTest(@[ disk1, disk2 ], nil, SNTDeviceManagerStartupPreferencesUnmount);

    XCTAssertTrue(disk1.wasUnmounted);
    XCTAssertFalse(disk1.wasMounted);
    XCTAssertTrue(disk2.wasUnmounted);
    XCTAssertFalse(disk2.wasMounted);
  }

  // Remount with RemountUSBMode set
  {
    MockDADisk* disk1 = CreateMockDisk(@"v1", @"d1");
    MockDADisk* disk2 = CreateMockDisk(@"v2", @"d2");

    PerformStartupTest(@[ disk1, disk2 ], @[ @"noexec", @"rdonly" ],
                       SNTDeviceManagerStartupPreferencesRemount);

    XCTAssertTrue(disk1.wasUnmounted);
    XCTAssertTrue(disk1.wasMounted);
    XCTAssertFalse(disk2.wasUnmounted);
    XCTAssertFalse(disk2.wasMounted);
  }

  // Unmount with RemountUSBMode nil
  {
    MockDADisk* disk1 = CreateMockDisk(@"v1", @"d1");
    MockDADisk* disk2 = CreateMockDisk(@"v2", @"d2");

    PerformStartupTest(@[ disk1, disk2 ], nil, SNTDeviceManagerStartupPreferencesRemount);

    XCTAssertTrue(disk1.wasUnmounted);
    XCTAssertFalse(disk1.wasMounted);
    XCTAssertTrue(disk2.wasUnmounted);
    XCTAssertFalse(disk2.wasMounted);
  }
}

- (void)testUpdatedMountFlags {
  struct statfs sfs;

  strlcpy(sfs.f_fstypename, "foo", sizeof(sfs.f_fstypename));
  sfs.f_flags = MNT_JOURNALED | MNT_NOSUID | MNT_NODEV;

  SNTEndpointSecurityDeviceManager* deviceManager = [[SNTEndpointSecurityDeviceManager alloc] init];
  NSArray<NSString*>* args = @[ @"noexec", @"rdonly" ];

  // For most filesystems, the flags are the union of what is in statfs and the remount args
  XCTAssertEqual([deviceManager updatedMountFlags:&sfs remountArgs:args],
                 sfs.f_flags | MNT_RDONLY | MNT_NOEXEC);

  // For APFS, flags are still unioned, but MNT_JOUNRNALED is cleared
  strlcpy(sfs.f_fstypename, "apfs", sizeof(sfs.f_fstypename));
  XCTAssertEqual([deviceManager updatedMountFlags:&sfs remountArgs:args],
                 (sfs.f_flags | MNT_RDONLY | MNT_NOEXEC) & ~MNT_JOURNALED);
}

- (void)testEnable {
  // Ensure the client subscribes to expected event types
  std::set<es_event_type_t> expectedEventSubs{
      ES_EVENT_TYPE_AUTH_MOUNT,
      ES_EVENT_TYPE_AUTH_REMOUNT,
      ES_EVENT_TYPE_NOTIFY_UNMOUNT,
  };
  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();

  id deviceClient =
      [[SNTEndpointSecurityDeviceManager alloc] initWithESAPI:mockESApi
                                                      metrics:nullptr
                                                    processor:santa::Processor::kDeviceManager];

  EXPECT_CALL(*mockESApi, ClearCache(testing::_))
      .After(EXPECT_CALL(*mockESApi, Subscribe(testing::_, expectedEventSubs))
                 .WillOnce(testing::Return(true)))
      .WillOnce(testing::Return(true));

  [deviceClient enable];

  for (const auto& event : expectedEventSubs) {
    XCTAssertNoThrow(santa::EventTypeToString(event));
  }

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

#if HAVE_MACOS_15

- (void)triggerTestNetworkMountEvent:(es_event_type_t)eventType
                        mountFromURL:(NSString*)mountFromURL
                          fsTypeName:(NSString*)fsTypeName
                  expectedAuthResult:(es_auth_result_t)expectedAuthResult
                  deviceManagerSetup:(void (^)(SNTEndpointSecurityDeviceManager*))setupDMCallback
                networkMountCallback:(void (^)(SNTStoredNetworkMountEvent*))networkMountCallback {
  struct statfs fs = {0};
  NSString* test_mntonname = @"/Volumes/NetworkShare";

  strncpy(fs.f_mntfromname, [mountFromURL UTF8String], sizeof(fs.f_mntfromname));
  strncpy(fs.f_mntonname, [test_mntonname UTF8String], sizeof(fs.f_mntonname));
  strncpy(fs.f_fstypename, [fsTypeName UTF8String], sizeof(fs.f_fstypename));
  fs.f_type = 0;  // Network mount type

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsESNewClient();

  auto mockEnricher = std::make_shared<santa::MockEnricher>();

  SNTEndpointSecurityDeviceManager* deviceManager = [[SNTEndpointSecurityDeviceManager alloc]
                            initWithESAPI:mockESApi
                                  metrics:nullptr
                                   logger:nullptr
                                 enricher:mockEnricher
                          authResultCache:nullptr
                     removableMediaAction:SNTRemovableMediaActionAllow
               removableMediaRemountFlags:nil
            encryptedRemovableMediaAction:SNTRemovableMediaActionAllow
      encryptedRemovableMediaRemountFlags:nil
                       startupPreferences:SNTDeviceManagerStartupPreferencesNone];

  setupDMCallback(deviceManager);

  if (networkMountCallback) {
    deviceManager.networkMountCallback = networkMountCallback;
  }

  // Stub the log method since a mock `Logger` object isn't used.
  id partialDeviceManager = OCMPartialMock(deviceManager);
  OCMStub([partialDeviceManager logDiskAppeared:OCMOCK_ANY allowed:OCMOCK_ANY])
      .ignoringNonObjectArgs();

  es_file_t file = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&file);

  // This test is sensitive to ~1s processing budget.
  // Set a 5s headroom and 6s deadline
  deviceManager.minAllowedHeadroom = 5 * NSEC_PER_SEC;
  deviceManager.maxAllowedHeadroom = 5 * NSEC_PER_SEC;
  es_message_t esMsg = MakeESMessage(eventType, &proc, ActionType::Auth, 6000);

  dispatch_semaphore_t semaMetrics = dispatch_semaphore_create(0);

  __block int retainCount = 0;
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  EXPECT_CALL(*mockESApi, ReleaseMessage).WillRepeatedly(^{
    if (retainCount == 0) {
      XCTFail(@"Under retain!");
    }
    retainCount--;
    if (retainCount == 0) {
      dispatch_semaphore_signal(sema);
    }
  });
  EXPECT_CALL(*mockESApi, RetainMessage).WillRepeatedly(^{
    retainCount++;
  });

  if (eventType == ES_EVENT_TYPE_AUTH_MOUNT) {
    esMsg.event.mount.statfs = &fs;
    esMsg.event.mount.disposition = ES_MOUNT_DISPOSITION_NETWORK;
  } else if (eventType == ES_EVENT_TYPE_AUTH_REMOUNT) {
    esMsg.event.remount.statfs = &fs;
    esMsg.event.remount.disposition = ES_MOUNT_DISPOSITION_NETWORK;
  } else {
    // Programming error. Fail the test.
    XCTFail(@"Unhandled event type in test: %d", eventType);
  }

  XCTestExpectation* mountExpectation =
      [self expectationWithDescription:@"Wait for response from ES"];

  EXPECT_CALL(*mockESApi, RespondAuthResult(testing::_, testing::_, expectedAuthResult, false))
      .WillOnce(testing::InvokeWithoutArgs(^bool {
        [mountExpectation fulfill];
        return true;
      }));

  [deviceManager
           handleMessage:Message(mockESApi, &esMsg)
      recordEventMetrics:^(EventDisposition d) {
        XCTAssertEqual(d, [self.mockConfigurator blockNetworkMount] ? EventDisposition::kProcessed
                                                                    : EventDisposition::kDropped);
        dispatch_semaphore_signal(semaMetrics);
      }];

  [self waitForExpectations:@[ mountExpectation ] timeout:60.0];

  XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");
  XCTAssertSemaTrue(sema, 5, "Failed waiting for message to be processed...");

  [partialDeviceManager stopMocking];
  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

// Convenience helper for the common network mount test pattern.
// Configures blockNetworkMount=YES with the given allowlist, then verifies
// that the mount-from string produces the expected auth result.
// When DENY is expected, also verifies the event's mountFromName matches.
- (void)verifyNetworkMount:(NSString*)mountFrom
                fsTypeName:(NSString*)fsTypeName
              allowedHosts:(NSArray<NSString*>*)allowedHosts
        expectedAuthResult:(es_auth_result_t)expectedAuthResult {
  OCMStub([self.mockConfigurator blockNetworkMount]).andReturn(YES);
  OCMStub([self.mockConfigurator allowedNetworkMountHosts]).andReturn(allowedHosts);

  XCTestExpectation* expectation = nil;
  if (expectedAuthResult == ES_AUTH_RESULT_DENY) {
    expectation = [self expectationWithDescription:@"Wait for networkMountCallback to trigger"];
  }

  [self triggerTestNetworkMountEvent:ES_EVENT_TYPE_AUTH_MOUNT
      mountFromURL:mountFrom
      fsTypeName:fsTypeName
      expectedAuthResult:expectedAuthResult
      deviceManagerSetup:^(SNTEndpointSecurityDeviceManager* dm) {
      }
      networkMountCallback:^(SNTStoredNetworkMountEvent* event) {
        if (expectedAuthResult == ES_AUTH_RESULT_DENY) {
          XCTAssertEqualObjects(event.mountFromName, mountFrom);
          [expectation fulfill];
        } else {
          XCTFail(@"Callback should not be called for allowed mount");
        }
      }];

  if (expectation) {
    [self waitForExpectations:@[ expectation ] timeout:60.0];
  }
}

- (void)testNetworkMountBlocked {
  if (@available(macOS 15.0, *)) {
    [self verifyNetworkMount:@"smb://server.example.com/share"
                  fsTypeName:@"smbfs"
                allowedHosts:@[]
          expectedAuthResult:ES_AUTH_RESULT_DENY];
  } else {
    XCTSkip(@"Test requires macOS 15 or later");
  }
}

- (void)testNetworkMountAllowedByHost {
  if (@available(macOS 15.0, *)) {
    [self verifyNetworkMount:@"smb://server.example.com/share"
                  fsTypeName:@"smbfs"
                allowedHosts:@[ @"server.example.com" ]
          expectedAuthResult:ES_AUTH_RESULT_ALLOW];
  } else {
    XCTSkip(@"Test requires macOS 15 or later");
  }
}

- (void)testNetworkMountDisabled {
  if (@available(macOS 15.0, *)) {
    OCMStub([self.mockConfigurator blockNetworkMount]).andReturn(NO);

    [self triggerTestNetworkMountEvent:ES_EVENT_TYPE_AUTH_MOUNT
        mountFromURL:@"smb://server.example.com/share"
        fsTypeName:@"smbfs"
        expectedAuthResult:ES_AUTH_RESULT_ALLOW
        deviceManagerSetup:^(SNTEndpointSecurityDeviceManager* dm) {
        }
        networkMountCallback:^(SNTStoredNetworkMountEvent* event) {
          XCTFail(@"Callback should not be called when blocking is disabled");
        }];
  } else {
    XCTSkip(@"Test requires macOS 15 or later");
  }
}

// NFS kernel format: "host:/path" — not a URL, requires scheme normalization
- (void)testNFSNetworkMountBlocked {
  if (@available(macOS 15.0, *)) {
    [self verifyNetworkMount:@"localhost:/"
                  fsTypeName:@"nfs"
                allowedHosts:@[]
          expectedAuthResult:ES_AUTH_RESULT_DENY];
  } else {
    XCTSkip(@"Test requires macOS 15 or later");
  }
}

- (void)testNFSNetworkMountAllowedByHost {
  if (@available(macOS 15.0, *)) {
    [self verifyNetworkMount:@"nfs-server.local:/exports/share"
                  fsTypeName:@"nfs"
                allowedHosts:@[ @"nfs-server.local" ]
          expectedAuthResult:ES_AUTH_RESULT_ALLOW];
  } else {
    XCTSkip(@"Test requires macOS 15 or later");
  }
}

// Real SMB kernel format: "//user@host/share" — already parseable by NSURL
- (void)testSMBNetworkMountWithUNCFormat {
  if (@available(macOS 15.0, *)) {
    [self verifyNetworkMount:@"//admin@192.168.64.3/admin"
                  fsTypeName:@"smbfs"
                allowedHosts:@[ @"192.168.64.3" ]
          expectedAuthResult:ES_AUTH_RESULT_ALLOW];
  } else {
    XCTSkip(@"Test requires macOS 15 or later");
  }
}

- (void)testNFSNetworkMountWithIPAddress {
  if (@available(macOS 15.0, *)) {
    [self verifyNetworkMount:@"192.168.1.10:/exports/share"
                  fsTypeName:@"nfs"
                allowedHosts:@[ @"192.168.1.10" ]
          expectedAuthResult:ES_AUTH_RESULT_ALLOW];
  } else {
    XCTSkip(@"Test requires macOS 15 or later");
  }
}

- (void)testNFSNetworkMountWithIPv6 {
  if (@available(macOS 15.0, *)) {
    [self verifyNetworkMount:@"[2001:db8::1]:/export/path"
                  fsTypeName:@"nfs"
                allowedHosts:@[ @"2001:db8::1" ]
          expectedAuthResult:ES_AUTH_RESULT_ALLOW];
  } else {
    XCTSkip(@"Test requires macOS 15 or later");
  }
}

// macOS SMB domain format uses semicolon: DOMAIN;user@host
- (void)testSMBNetworkMountWithDomainPrefix {
  if (@available(macOS 15.0, *)) {
    [self verifyNetworkMount:@"//CORP;admin@server.corp.com/share"
                  fsTypeName:@"smbfs"
                allowedHosts:@[ @"server.corp.com" ]
          expectedAuthResult:ES_AUTH_RESULT_ALLOW];
  } else {
    XCTSkip(@"Test requires macOS 15 or later");
  }
}

- (void)testSMBNetworkMountWithIPv6 {
  if (@available(macOS 15.0, *)) {
    [self verifyNetworkMount:@"//admin@[2001:db8::1]/share"
                  fsTypeName:@"smbfs"
                allowedHosts:@[ @"2001:db8::1" ]
          expectedAuthResult:ES_AUTH_RESULT_ALLOW];
  } else {
    XCTSkip(@"Test requires macOS 15 or later");
  }
}

// Anonymous/guest SMB: no user@ prefix
- (void)testSMBNetworkMountAnonymous {
  if (@available(macOS 15.0, *)) {
    [self verifyNetworkMount:@"//fileserver.local/public"
                  fsTypeName:@"smbfs"
                allowedHosts:@[ @"fileserver.local" ]
          expectedAuthResult:ES_AUTH_RESULT_ALLOW];
  } else {
    XCTSkip(@"Test requires macOS 15 or later");
  }
}

- (void)testSMBNetworkMountWithPort {
  if (@available(macOS 15.0, *)) {
    [self verifyNetworkMount:@"//admin@192.168.64.2:445/share"
                  fsTypeName:@"smbfs"
                allowedHosts:@[ @"192.168.64.2" ]
          expectedAuthResult:ES_AUTH_RESULT_ALLOW];
  } else {
    XCTSkip(@"Test requires macOS 15 or later");
  }
}

// AFP retains the afp:// scheme in f_mntfromname
- (void)testAFPNetworkMountAllowedByHost {
  if (@available(macOS 15.0, *)) {
    [self verifyNetworkMount:@"afp://admin@timecapsule.local/backups"
                  fsTypeName:@"afpfs"
                allowedHosts:@[ @"timecapsule.local" ]
          expectedAuthResult:ES_AUTH_RESULT_ALLOW];
  } else {
    XCTSkip(@"Test requires macOS 15 or later");
  }
}

// Host is correctly extracted but doesn't match any allowlist entry
- (void)testNFSNetworkMountBlockedNotOnAllowlist {
  if (@available(macOS 15.0, *)) {
    NSArray* allowedHosts = @[ @"trusted-nfs.corp.com", @"192.168.1.10" ];
    [self verifyNetworkMount:@"rogue-server.local:/exports/data"
                  fsTypeName:@"nfs"
                allowedHosts:allowedHosts
          expectedAuthResult:ES_AUTH_RESULT_DENY];
  } else {
    XCTSkip(@"Test requires macOS 15 or later");
  }
}

- (void)testNetworkMountFailClosedWithInvalidURL {
  if (@available(macOS 15.0, *)) {
    OCMStub([self.mockConfigurator blockNetworkMount]).andReturn(YES);
    OCMStub([self.mockConfigurator failClosed]).andReturn(YES);
    OCMStub([self.mockConfigurator allowedNetworkMountHosts]).andReturn(@[]);

    XCTestExpectation* expectation =
        [self expectationWithDescription:@"Wait for networkMountCallback to trigger"];

    // Use a string with spaces so NSURL returns nil even after scheme normalization
    [self triggerTestNetworkMountEvent:ES_EVENT_TYPE_AUTH_MOUNT
        mountFromURL:@"not a valid host"
        fsTypeName:@"smbfs"
        expectedAuthResult:ES_AUTH_RESULT_DENY
        deviceManagerSetup:^(SNTEndpointSecurityDeviceManager* dm) {
        }
        networkMountCallback:^(SNTStoredNetworkMountEvent* event) {
          XCTAssertEqualObjects(event.mountFromName, @"not a valid host");
          [expectation fulfill];
        }];

    [self waitForExpectations:@[ expectation ] timeout:60.0];
  } else {
    XCTSkip(@"Test requires macOS 15 or later");
  }
}

- (void)testNetworkMountFailOpenWithInvalidURL {
  if (@available(macOS 15.0, *)) {
    OCMStub([self.mockConfigurator blockNetworkMount]).andReturn(YES);
    OCMStub([self.mockConfigurator failClosed]).andReturn(NO);
    OCMStub([self.mockConfigurator allowedNetworkMountHosts]).andReturn(@[]);

    // Use a string with spaces so NSURL returns nil even after scheme normalization
    [self triggerTestNetworkMountEvent:ES_EVENT_TYPE_AUTH_MOUNT
        mountFromURL:@"not a valid host"
        fsTypeName:@"smbfs"
        expectedAuthResult:ES_AUTH_RESULT_ALLOW
        deviceManagerSetup:^(SNTEndpointSecurityDeviceManager* dm) {
        }
        networkMountCallback:^(SNTStoredNetworkMountEvent* event) {
          XCTFail(@"Callback should not be called when failing open");
        }];
  } else {
    XCTSkip(@"Test requires macOS 15 or later");
  }
}

#endif  // HAVE_MACOS_15

#pragma mark - Removable Media Policy Tests

- (void)testBaselineAllow_NoEncryptedOverride_BothAllowed {
  [self triggerTestMountEvent:ES_EVENT_TYPE_AUTH_MOUNT
            diskInfoOverrides:@{
              (__bridge NSString*)kDADiskDescriptionMediaEncryptedKey : @YES,
            }
           expectedAuthResult:ES_AUTH_RESULT_ALLOW
           deviceManagerSetup:^(SNTEndpointSecurityDeviceManager* dm) {
             dm.removableMediaAction = SNTRemovableMediaActionAllow;
           }];
}

- (void)testBaselineBlock_NoEncryptedOverride_EncryptedBlocked {
  XCTestExpectation* exp = [self expectationWithDescription:@"callback"];
  [self triggerTestMountEvent:ES_EVENT_TYPE_AUTH_MOUNT
            diskInfoOverrides:@{
              (__bridge NSString*)kDADiskDescriptionMediaEncryptedKey : @YES,
            }
           expectedAuthResult:ES_AUTH_RESULT_DENY
           deviceManagerSetup:^(SNTEndpointSecurityDeviceManager* dm) {
             // No encrypted override = configurator resolves encrypted to baseline (Block).
             dm.removableMediaAction = SNTRemovableMediaActionBlock;
             dm.encryptedRemovableMediaAction = SNTRemovableMediaActionBlock;
             dm.deviceBlockCallback = ^(SNTDeviceEvent* event, SNTStoredUSBMountEvent* usbEvent) {
               XCTAssertEqual(usbEvent.decision, SNTStoredUSBMountEventDecisionBlocked);
               [exp fulfill];
             };
           }];
  [self waitForExpectations:@[ exp ] timeout:10.0];
}

- (void)testBaselineRemount_EncryptedAllow_EncryptedDeviceAllowed {
  [self triggerTestMountEvent:ES_EVENT_TYPE_AUTH_MOUNT
            diskInfoOverrides:@{
              (__bridge NSString*)kDADiskDescriptionMediaEncryptedKey : @YES,
            }
           expectedAuthResult:ES_AUTH_RESULT_ALLOW
           deviceManagerSetup:^(SNTEndpointSecurityDeviceManager* dm) {
             dm.removableMediaAction = SNTRemovableMediaActionRemount;
             dm.removableMediaRemountFlags = @[ @"rdonly" ];
             dm.encryptedRemovableMediaAction = SNTRemovableMediaActionAllow;
           }];
}

- (void)testBaselineRemount_EncryptedAllow_UnencryptedRemounted {
  XCTestExpectation* exp = [self expectationWithDescription:@"callback"];
  [self triggerTestMountEvent:ES_EVENT_TYPE_AUTH_MOUNT
            diskInfoOverrides:@{
              (__bridge NSString*)kDADiskDescriptionMediaEncryptedKey : @NO,
            }
           expectedAuthResult:ES_AUTH_RESULT_DENY
           deviceManagerSetup:^(SNTEndpointSecurityDeviceManager* dm) {
             dm.removableMediaAction = SNTRemovableMediaActionRemount;
             dm.removableMediaRemountFlags = @[ @"rdonly" ];
             dm.encryptedRemovableMediaAction = SNTRemovableMediaActionAllow;
             dm.deviceBlockCallback = ^(SNTDeviceEvent* event, SNTStoredUSBMountEvent* usbEvent) {
               XCTAssertEqual(usbEvent.decision, SNTStoredUSBMountEventDecisionAllowedWithRemount);
               XCTAssertEqualObjects(usbEvent.remountArgs, (@[ @"rdonly" ]));
               [exp fulfill];
             };
           }];
  [self waitForExpectations:@[ exp ] timeout:10.0];
}

- (void)testBaselineBlock_EncryptedAllow_EncryptedAllowed {
  [self triggerTestMountEvent:ES_EVENT_TYPE_AUTH_MOUNT
            diskInfoOverrides:@{
              (__bridge NSString*)kDADiskDescriptionMediaEncryptedKey : @YES,
            }
           expectedAuthResult:ES_AUTH_RESULT_ALLOW
           deviceManagerSetup:^(SNTEndpointSecurityDeviceManager* dm) {
             dm.removableMediaAction = SNTRemovableMediaActionBlock;
             dm.encryptedRemovableMediaAction = SNTRemovableMediaActionAllow;
           }];
}

- (void)testBaselineBlock_EncryptedAllow_UnencryptedBlocked {
  XCTestExpectation* exp = [self expectationWithDescription:@"callback"];
  [self triggerTestMountEvent:ES_EVENT_TYPE_AUTH_MOUNT
            diskInfoOverrides:@{
              (__bridge NSString*)kDADiskDescriptionMediaEncryptedKey : @NO,
            }
           expectedAuthResult:ES_AUTH_RESULT_DENY
           deviceManagerSetup:^(SNTEndpointSecurityDeviceManager* dm) {
             dm.removableMediaAction = SNTRemovableMediaActionBlock;
             dm.encryptedRemovableMediaAction = SNTRemovableMediaActionAllow;
             dm.deviceBlockCallback = ^(SNTDeviceEvent* event, SNTStoredUSBMountEvent* usbEvent) {
               XCTAssertEqual(usbEvent.decision, SNTStoredUSBMountEventDecisionBlocked);
               [exp fulfill];
             };
           }];
  [self waitForExpectations:@[ exp ] timeout:10.0];
}

- (void)testBaselineRemount_EncryptedBlock_EncryptedBlocked {
  XCTestExpectation* exp = [self expectationWithDescription:@"callback"];
  [self triggerTestMountEvent:ES_EVENT_TYPE_AUTH_MOUNT
            diskInfoOverrides:@{
              (__bridge NSString*)kDADiskDescriptionMediaEncryptedKey : @YES,
            }
           expectedAuthResult:ES_AUTH_RESULT_DENY
           deviceManagerSetup:^(SNTEndpointSecurityDeviceManager* dm) {
             dm.removableMediaAction = SNTRemovableMediaActionRemount;
             dm.removableMediaRemountFlags = @[ @"rdonly" ];
             dm.encryptedRemovableMediaAction = SNTRemovableMediaActionBlock;
             dm.deviceBlockCallback = ^(SNTDeviceEvent* event, SNTStoredUSBMountEvent* usbEvent) {
               XCTAssertEqual(usbEvent.decision, SNTStoredUSBMountEventDecisionBlocked);
               [exp fulfill];
             };
           }];
  [self waitForExpectations:@[ exp ] timeout:10.0];
}

- (void)testBaselineRemount_EncryptedRemountDifferentFlags {
  XCTestExpectation* exp = [self expectationWithDescription:@"callback"];
  [self triggerTestMountEvent:ES_EVENT_TYPE_AUTH_MOUNT
            diskInfoOverrides:@{
              (__bridge NSString*)kDADiskDescriptionMediaEncryptedKey : @NO,
            }
           expectedAuthResult:ES_AUTH_RESULT_DENY
           deviceManagerSetup:^(SNTEndpointSecurityDeviceManager* dm) {
             dm.removableMediaAction = SNTRemovableMediaActionRemount;
             dm.removableMediaRemountFlags = @[ @"rdonly" ];
             dm.encryptedRemovableMediaAction = SNTRemovableMediaActionRemount;
             dm.encryptedRemovableMediaRemountFlags = @[ @"rdonly", @"noexec" ];
             dm.deviceBlockCallback = ^(SNTDeviceEvent* event, SNTStoredUSBMountEvent* usbEvent) {
               XCTAssertEqual(usbEvent.decision, SNTStoredUSBMountEventDecisionAllowedWithRemount);
               XCTAssertEqualObjects(usbEvent.remountArgs, (@[ @"rdonly" ]));
               [exp fulfill];
             };
           }];
  [self waitForExpectations:@[ exp ] timeout:10.0];
}

- (void)testMissingEncryptionKey_DeniedByDefault {
  XCTestExpectation* exp = [self expectationWithDescription:@"callback"];
  [self triggerTestMountEvent:ES_EVENT_TYPE_AUTH_MOUNT
            diskInfoOverrides:nil
           expectedAuthResult:ES_AUTH_RESULT_DENY
           deviceManagerSetup:^(SNTEndpointSecurityDeviceManager* dm) {
             dm.removableMediaAction = SNTRemovableMediaActionBlock;
             dm.encryptedRemovableMediaAction = SNTRemovableMediaActionAllow;
             dm.deviceBlockCallback = ^(SNTDeviceEvent* event, SNTStoredUSBMountEvent* usbEvent) {
               XCTAssertEqual(usbEvent.decision, SNTStoredUSBMountEventDecisionBlocked);
               [exp fulfill];
             };
           }];
  [self waitForExpectations:@[ exp ] timeout:10.0];
}

- (SNTEndpointSecurityDeviceManager*)createDeviceManagerForApprovalTests {
  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsESNewClient();
  auto mockEnricher = std::make_shared<santa::MockEnricher>();

  SNTEndpointSecurityDeviceManager* dm = [[SNTEndpointSecurityDeviceManager alloc]
                            initWithESAPI:mockESApi
                                  metrics:nullptr
                                   logger:nullptr
                                 enricher:mockEnricher
                          authResultCache:nullptr
                     removableMediaAction:SNTRemovableMediaActionAllow
               removableMediaRemountFlags:nil
            encryptedRemovableMediaAction:SNTRemovableMediaActionAllow
      encryptedRemovableMediaRemountFlags:nil
                       startupPreferences:SNTDeviceManagerStartupPreferencesNone];

  id partialDM = OCMPartialMock(dm);
  OCMStub([partialDM logDiskAppeared:OCMOCK_ANY allowed:OCMOCK_ANY]).ignoringNonObjectArgs();

  return dm;
}

- (MockDADisk*)createMockDiskWithEncrypted:(BOOL)encrypted {
  MockDADisk* mockDisk = [[MockDADisk alloc] init];
  NSMutableDictionary* desc = [@{
    @"DAMediaBSDName" : @"/dev/disk2s1",
    (__bridge NSString*)kDADiskDescriptionDeviceProtocolKey : @"USB",
    (__bridge NSString*)kDADiskDescriptionMediaRemovableKey : @YES,
    @"DAVolumeMountable" : @YES,
    @"DAVolumePath" : @"/Volumes/TestDisk",
    (__bridge NSString*)kDADiskDescriptionDeviceModelKey : @"Test Model",
    (__bridge NSString*)kDADiskDescriptionDeviceVendorKey : @"Test Vendor",
  } mutableCopy];
  desc[(__bridge NSString*)kDADiskDescriptionMediaEncryptedKey] = @(encrypted);
  mockDisk.diskDescription = desc;
  [self.mockDA insert:mockDisk];
  return mockDisk;
}

#pragma mark - DA Encrypted Mount Approval (Dissenter) Tests

- (void)testEncryptedMountApproval_EncryptedDevice_ReturnsDissenter {
  SNTEndpointSecurityDeviceManager* dm = [self createDeviceManagerForApprovalTests];
  dm.encryptedRemovableMediaAction = SNTRemovableMediaActionRemount;
  dm.encryptedRemovableMediaRemountFlags = @[ @"rdonly", @"noexec" ];

  MockDADisk* mockDisk = [self createMockDiskWithEncrypted:YES];

  DADissenterRef result = [dm handleEncryptedMountApproval:(__bridge DADiskRef)mockDisk];
  XCTAssertTrue(result != NULL,
                @"Should return a dissenter for encrypted device with Remount policy");

  XCTAssertTrue(mockDisk.wasMounted);
  dispatch_sync(dm.diskQueue, ^{
    XCTAssertFalse([dm.remountingDisks containsObject:@"/dev/disk2s1"]);
  });
}

- (void)testEncryptedMountApproval_SelfRemount_Approves {
  SNTEndpointSecurityDeviceManager* dm = [self createDeviceManagerForApprovalTests];
  dm.encryptedRemovableMediaAction = SNTRemovableMediaActionRemount;
  dm.encryptedRemovableMediaRemountFlags = @[ @"rdonly", @"noexec" ];

  MockDADisk* mockDisk = [self createMockDiskWithEncrypted:YES];

  dispatch_sync(dm.diskQueue, ^{
    [dm.remountingDisks addObject:@"/dev/disk2s1"];
  });

  DADissenterRef result = [dm handleEncryptedMountApproval:(__bridge DADiskRef)mockDisk];
  XCTAssertTrue(result == NULL, @"Should approve our own remount");
}

- (void)testEncryptedMountApproval_UnencryptedDevice_Approves {
  SNTEndpointSecurityDeviceManager* dm = [self createDeviceManagerForApprovalTests];
  dm.encryptedRemovableMediaAction = SNTRemovableMediaActionRemount;
  dm.encryptedRemovableMediaRemountFlags = @[ @"rdonly" ];

  MockDADisk* mockDisk = [self createMockDiskWithEncrypted:NO];

  DADissenterRef result = [dm handleEncryptedMountApproval:(__bridge DADiskRef)mockDisk];
  XCTAssertTrue(result == NULL, @"Should approve unencrypted device (ES handles it)");
}

- (void)testEncryptedMountApproval_EncryptedPolicyAllow_Approves {
  SNTEndpointSecurityDeviceManager* dm = [self createDeviceManagerForApprovalTests];
  dm.encryptedRemovableMediaAction = SNTRemovableMediaActionAllow;

  MockDADisk* mockDisk = [self createMockDiskWithEncrypted:YES];

  DADissenterRef result = [dm handleEncryptedMountApproval:(__bridge DADiskRef)mockDisk];
  XCTAssertTrue(result == NULL, @"Should approve when encrypted policy is Allow");
}

- (void)testEncryptedMountApproval_EncryptedPolicyBlock_Approves {
  SNTEndpointSecurityDeviceManager* dm = [self createDeviceManagerForApprovalTests];
  dm.encryptedRemovableMediaAction = SNTRemovableMediaActionBlock;

  MockDADisk* mockDisk = [self createMockDiskWithEncrypted:YES];

  DADissenterRef result = [dm handleEncryptedMountApproval:(__bridge DADiskRef)mockDisk];
  XCTAssertTrue(result == NULL,
                @"Should approve when encrypted policy is Block (ES handles blocking)");
}

- (void)testEncryptedMountApproval_NoEncryptedPolicy_Approves {
  SNTEndpointSecurityDeviceManager* dm = [self createDeviceManagerForApprovalTests];

  MockDADisk* mockDisk = [self createMockDiskWithEncrypted:YES];

  DADissenterRef result = [dm handleEncryptedMountApproval:(__bridge DADiskRef)mockDisk];
  XCTAssertTrue(result == NULL, @"Should approve when no encrypted policy configured");
}

- (void)testEncryptedMountApproval_InternalDevice_Approves {
  SNTEndpointSecurityDeviceManager* dm = [self createDeviceManagerForApprovalTests];
  dm.encryptedRemovableMediaAction = SNTRemovableMediaActionRemount;
  dm.encryptedRemovableMediaRemountFlags = @[ @"rdonly" ];

  MockDADisk* mockDisk = [[MockDADisk alloc] init];
  mockDisk.diskDescription = @{
    @"DAMediaBSDName" : @"/dev/disk0s1",
    (__bridge NSString*)kDADiskDescriptionDeviceProtocolKey : @"SATA",
    (__bridge NSString*)kDADiskDescriptionDeviceInternalKey : @YES,
    (__bridge NSString*)kDADiskDescriptionMediaEncryptedKey : @YES,
    @"DAVolumeMountable" : @YES,
  };
  [self.mockDA insert:mockDisk];

  DADissenterRef result = [dm handleEncryptedMountApproval:(__bridge DADiskRef)mockDisk];
  XCTAssertTrue(result == NULL, @"Should approve internal device");
}

- (void)testEncryptedMountApproval_NoRemountFlags_Approves {
  SNTEndpointSecurityDeviceManager* dm = [self createDeviceManagerForApprovalTests];
  dm.encryptedRemovableMediaAction = SNTRemovableMediaActionRemount;

  MockDADisk* mockDisk = [self createMockDiskWithEncrypted:YES];

  DADissenterRef result = [dm handleEncryptedMountApproval:(__bridge DADiskRef)mockDisk];
  XCTAssertTrue(result == NULL, @"Should approve when no remount flags configured");
}

- (void)testEncryptedRemountCompletion_CleansUpTrackingSet {
  SNTEndpointSecurityDeviceManager* dm = [self createDeviceManagerForApprovalTests];
  dm.encryptedRemovableMediaRemountFlags = @[ @"rdonly" ];

  MockDADisk* mockDisk = [self createMockDiskWithEncrypted:YES];

  dispatch_sync(dm.diskQueue, ^{
    [dm.remountingDisks addObject:@"/dev/disk2s1"];
  });

  [dm handleEncryptedRemountCompletion:(__bridge DADiskRef)mockDisk dissenter:NULL];

  dispatch_sync(dm.diskQueue, ^{
    XCTAssertFalse([dm.remountingDisks containsObject:@"/dev/disk2s1"],
                   @"Should remove from tracking set after completion");
  });
}

- (void)testEncryptedRemountCompletion_Success_FiresCallback {
  SNTEndpointSecurityDeviceManager* dm = [self createDeviceManagerForApprovalTests];
  dm.encryptedRemovableMediaAction = SNTRemovableMediaActionRemount;
  dm.encryptedRemovableMediaRemountFlags = @[ @"rdonly", @"noexec" ];

  MockDADisk* mockDisk = [self createMockDiskWithEncrypted:YES];

  dispatch_sync(dm.diskQueue, ^{
    [dm.remountingDisks addObject:@"/dev/disk2s1"];
  });

  __block BOOL callbackCalled = NO;
  __block SNTStoredUSBMountEventDecision gotDecision;
  __block NSArray<NSString*>* gotRemountArgs;
  dm.deviceBlockCallback = ^(SNTDeviceEvent* event, SNTStoredUSBMountEvent* usbEvent) {
    callbackCalled = YES;
    gotDecision = usbEvent.decision;
    gotRemountArgs = usbEvent.remountArgs;
  };

  [dm handleEncryptedRemountCompletion:(__bridge DADiskRef)mockDisk dissenter:NULL];

  XCTAssertTrue(callbackCalled, @"deviceBlockCallback should fire on successful remount");
  XCTAssertEqual(gotDecision, SNTStoredUSBMountEventDecisionAllowedWithRemount);
  XCTAssertEqualObjects(gotRemountArgs, dm.encryptedRemovableMediaRemountFlags);
}

- (void)testEncryptedRemountCompletion_Failure_DoesNotFireCallback {
  SNTEndpointSecurityDeviceManager* dm = [self createDeviceManagerForApprovalTests];
  dm.encryptedRemovableMediaRemountFlags = @[ @"rdonly" ];

  MockDADisk* mockDisk = [self createMockDiskWithEncrypted:YES];

  dispatch_sync(dm.diskQueue, ^{
    [dm.remountingDisks addObject:@"/dev/disk2s1"];
  });

  dm.deviceBlockCallback = ^(SNTDeviceEvent* event, SNTStoredUSBMountEvent* usbEvent) {
    XCTFail(@"deviceBlockCallback should not fire on failed remount");
  };

  DADissenterRef mockDissenter = DADissenterCreate(kCFAllocatorDefault, kDAReturnBusy, NULL);
  [dm handleEncryptedRemountCompletion:(__bridge DADiskRef)mockDisk dissenter:mockDissenter];

  dispatch_sync(dm.diskQueue, ^{
    XCTAssertFalse([dm.remountingDisks containsObject:@"/dev/disk2s1"],
                   @"Should still clean up tracking set on failure");
  });

  if (mockDissenter) CFRelease(mockDissenter);
}

@end
