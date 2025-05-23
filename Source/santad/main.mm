/// Copyright 2015-2022 Google Inc. All rights reserved.
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

#import <Foundation/Foundation.h>
#include <dispatch/dispatch.h>
#include <mach/task.h>
#include <memory>

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTMetricSet.h"
#import "Source/common/SNTSystemInfo.h"
#import "Source/common/SystemResources.h"
#include "Source/santad/ProcessControl.h"
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

void InstallServices() {
  NSString *install_services_script = [[NSBundle mainBundle] pathForResource:@"install_services"
                                                                      ofType:@"sh"];
  NSTask *task = [[NSTask alloc] init];
  task.launchPath = @"/bin/bash";
  task.arguments = @[ install_services_script ];
  task.environment = @{@"CONF_DIR" : [[NSBundle mainBundle] resourcePath]};
  NSError *error;
  if (![task launchAndReturnError:&error]) {
    LOGE(@"install_services.sh error: %@", error);
  }
  [task waitUntilExit];
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

    InstallServices();

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
        SantadDeps::Create([SNTConfigurator configurator], [SNTMetricSet sharedInstance],
                           santa::ProdSuspendResumeBlock());

    // This doesn't return
    SantadMain(deps->ESAPI(), deps->Logger(), deps->Metrics(), deps->WatchItems(), deps->Enricher(),
               deps->AuthResultCache(), deps->ControlConnection(), deps->CompilerController(),
               deps->NotifierQueue(), deps->SyncdQueue(), deps->ExecController(),
               deps->PrefixTree(), deps->TTYWriter(), deps->ProcessTree());
  }

  return 0;
}
