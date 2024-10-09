/// Copyright 2015-2022 Google Inc. All rights reserved.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///    http://www.apache.org/licenses/LICENSE-2.0
///
///    Unless required by applicable law or agreed to in writing, software
///    distributed under the License is distributed on an "AS IS" BASIS,
///    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
///    See the License for the specific language governing permissions and
///    limitations under the License.

#include <Foundation/Foundation.h>
#include <dispatch/dispatch.h>
#include <mach/task.h>

#include <memory>

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTMetricSet.h"
#import "Source/common/SNTSystemInfo.h"
#import "Source/common/SystemResources.h"
#include "Source/santad/MachServiceDeadWaiter.h"
#import "Source/santad/Santad.h"
#include "Source/santad/SantadDeps.h"

using santa::SantadDeps;

// Number of seconds to wait between checks.
const int kWatchdogTimeInterval = 30;

extern "C" uint64_t watchdogCPUEvents;
extern "C" uint64_t watchdogRAMEvents;
extern "C" double watchdogCPUPeak;
extern "C" double watchdogRAMPeak;

struct WatchdogState {
  double prev_total_time;
  double prev_ram_use_mb;
};

///  The watchdog thread function, used to monitor santad CPU/RAM usage and print a warning
///  if it goes over certain thresholds.
static void SantaWatchdog(void *context) {
  WatchdogState *state = (WatchdogState *)context;

  // Amount of CPU usage to trigger warning, as a percentage averaged over kWatchdogTimeInterval
  // santad's usual CPU usage is 0-3% but can occasionally spike if lots of processes start at once.
  const int cpu_warn_threshold = 20.0;

  // Amount of RAM usage to trigger warning, in MB.
  // santad's usual RAM usage is between 5-50MB but can spike if lots of processes start at once.
  const int mem_warn_threshold = 250;

  std::optional<SantaTaskInfo> tinfo = GetTaskInfo();

  if (tinfo.has_value()) {
    // CPU
    double total_time =
      (tinfo->total_user_nanos + tinfo->total_system_nanos) / (double)NSEC_PER_SEC;
    double percentage =
      (((total_time - state->prev_total_time) / (double)kWatchdogTimeInterval) * 100.0);
    state->prev_total_time = total_time;

    if (percentage > cpu_warn_threshold) {
      LOGW(@"Watchdog: potentially high CPU use, ~%.2f%% over last %d seconds.", percentage,
           kWatchdogTimeInterval);
      watchdogCPUEvents++;
    }

    if (percentage > watchdogCPUPeak) watchdogCPUPeak = percentage;

    // RAM
    double ram_use_mb = (double)tinfo->resident_size / 1024 / 1024;
    if (ram_use_mb > mem_warn_threshold && ram_use_mb > state->prev_ram_use_mb) {
      LOGW(@"Watchdog: potentially high RAM use, RSS is %.2fMB.", ram_use_mb);
      watchdogRAMEvents++;
    }
    state->prev_ram_use_mb = ram_use_mb;

    if (ram_use_mb > watchdogRAMPeak) {
      watchdogRAMPeak = ram_use_mb;
    }
  }
}

static bool IsGoogleSantaActiveEnabled() {
  // `+[OSSystemExtensionRequest propertiesRequestForExtension:queue:]` is only usable when
  // inspecting system extensions signed with the same TEAM ID as the caller. Instead, look through
  // the system extension on-disk db.plist artifact. To prevent crashing on schema changes, check
  // the types of the values as the dictionary is walked.
  NSDictionary *system_extensions_db =
    [NSDictionary dictionaryWithContentsOfFile:@"/Library/SystemExtensions/db.plist"];
  if (![system_extensions_db isKindOfClass:[NSDictionary class]]) return false;

  NSArray *system_extensions = system_extensions_db[@"extensions"];
  if (![system_extensions isKindOfClass:[NSArray class]]) return false;

  for (NSDictionary *sysx in system_extensions) {
    if (![sysx isKindOfClass:[NSDictionary class]]) return false;

    NSString *identifier = sysx[@"identifier"];
    if (![identifier isKindOfClass:[NSString class]]) return false;

    NSString *state = sysx[@"identifier"];
    if (![state isKindOfClass:[NSString class]]) return false;

    if ([identifier isEqualToString:@"com.google.santa.daemon"] &&
        [state isEqualToString:@"activated_enabled"]) {
      return true;
    }
  }
  return false;
}

static void FinishInstall() {
  // Wait for com.google.santa.daemon to be removed.
  while (1) {
    // Record if com.google.santa.daemon is an active and enabled system extension.
    bool google_santa_active_enabled = IsGoogleSantaActiveEnabled();

    // Wait for its mach port to die. MachServiceDeadWaiter will return immediately if the service
    // can not be found. Perform this call unconditionally, if /Library/SystemExtensions/db.plist
    // changes its schema and `IsGoogleSantaActiveEnabled` returns a false negative, checking for
    // the mach service is still the correct thing to do.
    MachServiceDeadWaiter google_santa("EQHXZ8M8AV.com.google.santa.daemon.xpc");

    // If com.google.santa.daemon was recorded as being active and enabled, wait for 1 second and
    // check again. This should be enough time for com.google.santa.daemon to be updated or recover
    // from a crash, preventing this loop from spinning too fast. It also prevents
    // com.google.santa.daemon and com.northpolesec.santa.daemon from racing during a system reboot.
    if (google_santa_active_enabled) {
      LOGI(@"com.google.santa.daemon was active and enabled - waiting for removal");
      sleep(1);
      continue;
    }

    // com.google.santa.daemon has been uninstalled.
    break;
  }

  // Rename Santa_NPS.app to Santa.app.
  NSFileManager *fm = [NSFileManager defaultManager];
  if ([fm fileExistsAtPath:@"/Applications/Santa_NPS.app"]) {
    NSError *error;
    if (![fm removeItemAtPath:@"/Applications/Santa.app" error:&error]) {
      LOGE(@"NPS rename: remove error: %@", error);
    }
    if (![fm moveItemAtPath:@"/Applications/Santa_NPS.app"
                     toPath:@"/Applications/Santa.app"
                      error:&error]) {
      LOGE(@"NPS rename: move error: %@", error);
    }
  }
}

int main(int argc, char *argv[]) {
  @autoreleasepool {
    // Do not wait on child processes
    signal(SIGCHLD, SIG_IGN);

    NSString *product_version = [SNTSystemInfo santaProductVersion];
    NSString *build_version = [SNTSystemInfo santaBuildVersion];

    NSProcessInfo *pi = [NSProcessInfo processInfo];
    if ([pi.arguments containsObject:@"-v"]) {
      printf("%s (build %s)\n", [product_version UTF8String], [build_version UTF8String]);
      return 0;
    }

    FinishInstall();

    dispatch_queue_t watchdog_queue = dispatch_queue_create(
      "com.northpolesec.santa.daemon.watchdog", DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL);
    dispatch_source_t watchdog_timer =
      dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, watchdog_queue);

    WatchdogState state = {.prev_total_time = 0.0, .prev_ram_use_mb = 0.0};

    if (watchdog_timer) {
      dispatch_source_set_timer(watchdog_timer, DISPATCH_TIME_NOW,
                                kWatchdogTimeInterval * NSEC_PER_SEC, 0);
      dispatch_source_set_event_handler_f(watchdog_timer, SantaWatchdog);
      dispatch_set_context(watchdog_timer, &state);
      dispatch_resume(watchdog_timer);
    } else {
      LOGE(@"Failed to start Santa watchdog");
    }

    std::unique_ptr<SantadDeps> deps =
      SantadDeps::Create([SNTConfigurator configurator], [SNTMetricSet sharedInstance]);

    // This doesn't return
    SantadMain(deps->ESAPI(), deps->Logger(), deps->Metrics(), deps->WatchItems(), deps->Enricher(),
               deps->AuthResultCache(), deps->ControlConnection(), deps->CompilerController(),
               deps->NotifierQueue(), deps->SyncdQueue(), deps->ExecController(),
               deps->PrefixTree(), deps->TTYWriter(), deps->ProcessTree());
  }

  return 0;
}
