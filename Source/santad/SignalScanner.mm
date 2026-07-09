/// Copyright 2026 North Pole Security, Inc.
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

#include "Source/santad/SignalScanner.h"

#import "Source/common/SNTLogging.h"
#include "absl/cleanup/cleanup.h"
#include "absl/status/status.h"
#include "telemetry/sleighconfig.pb.h"

namespace santa {

std::shared_ptr<SignalScanner> SignalScanner::Create(
    std::unique_ptr<SleighLauncher> sleigh_launcher, uint32_t timeout_secs,
    ReportHandlerBlock report_handler) {
  // Scans are best-effort background work (fork Sleigh + read a closed spool file); run at
  // utility QoS so they never contend with the latency-sensitive ES decision path.
  dispatch_queue_attr_t attr = dispatch_queue_attr_make_with_qos_class(
      DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL, QOS_CLASS_UTILITY, 0);
  dispatch_queue_t scan_q =
      dispatch_queue_create("com.northpolesec.santa.daemon.signal_scan", attr);
  // Not make_shared: the constructor is private (see header), accessible here because Create is a
  // static member. The extra control-block allocation is irrelevant for a daemon-lifetime object.
  return std::shared_ptr<SignalScanner>(
      new SignalScanner(std::move(sleigh_launcher), timeout_secs, report_handler, scan_q));
}

SignalScanner::SignalScanner(std::unique_ptr<SleighLauncher> sleigh_launcher, uint32_t timeout_secs,
                             ReportHandlerBlock report_handler, dispatch_queue_t scan_q)
    : sleigh_launcher_(std::move(sleigh_launcher)),
      timeout_secs_(timeout_secs),
      report_handler_(report_handler),
      scan_q_(scan_q) {}

void SignalScanner::SetSignals(NSArray<SNTSignal*>* signals) {
  std::vector<std::string> v;
  v.reserve(signals.count);
  for (SNTSignal* signal in signals) {
    NSData* data = signal.data;
    // Guard against a nil/empty data: std::string(nullptr, 0) is undefined, and an empty
    // signal is useless to Sleigh anyway.
    if (data.length == 0) {
      continue;
    }
    v.emplace_back(static_cast<const char*>(data.bytes), data.length);
  }

  absl::MutexLock lock(lock_);
  signals_ = std::move(v);
}

void SignalScanner::ScanFile(std::string path, std::shared_ptr<ScopedFile> file) {
  // No readable fd for the closed file (the spool layer's open failed): nothing to scan.
  if (!file) {
    return;
  }

  // Cap the number of opened-but-not-yet-scanned files (see kMaxInFlightScans). Checked here,
  // synchronously on the spool's queue, so an over-cap drop releases `file` (and its fd) right
  // away instead of letting it sit in the scan queue. Scans run serially, so ScanFile is never
  // called concurrently; only the decrement (below) races, which the atomic handles.
  if (in_flight_.fetch_add(1, std::memory_order_relaxed) >= kMaxInFlightScans) {
    in_flight_.fetch_sub(1, std::memory_order_relaxed);
    LOGW(@"Signal scan dropped for %s: already at %d in-flight scans", path.c_str(),
         kMaxInFlightScans);
    return;
  }

  auto shared_this = shared_from_this();
  dispatch_async(scan_q_, ^{
    absl::Cleanup decrement = [shared_this] {
      shared_this->in_flight_.fetch_sub(1, std::memory_order_relaxed);
    };

    std::vector<std::string> signals;
    {
      absl::MutexLock lock(shared_this->lock_);
      signals = shared_this->signals_;
    }

    // Nothing configured: don't even launch Sleigh. (The captured `file` closes on return.)
    if (signals.empty()) {
      return;
    }

    absl::StatusOr<::santa::telemetry::v1::SleighSignalScanResponse> response =
        shared_this->sleigh_launcher_->LaunchSignalScan(file->UnsafeFD(), signals,
                                                        shared_this->timeout_secs_);
    if (!response.ok()) {
      // Sleigh not installed (e.g. lite package) is accepted; don't warn.
      if (!absl::IsNotFound(response.status())) {
        LOGW(@"Signal scan failed for %s: %s", path.c_str(),
             std::string(response.status().message()).c_str());
      }
      return;
    }

    if (response->signal_reports_size() == 0) {
      return;
    }

    NSMutableArray<SNTStoredSignalReport*>* reports = [NSMutableArray array];
    for (const auto& report : response->signal_reports()) {
      std::string bytes;
      if (!report.SerializeToString(&bytes)) {
        continue;
      }
      SNTStoredSignalReport* stored = [[SNTStoredSignalReport alloc]
          initWithReportData:[NSData dataWithBytes:bytes.data() length:bytes.size()]];
      if (stored) {
        // Carry the signal name so the events database can deduplicate repeated firings.
        stored.name = [NSString stringWithUTF8String:report.name().c_str()];
        [reports addObject:stored];
      }
    }

    if (reports.count > 0 && shared_this->report_handler_) {
      shared_this->report_handler_(reports);
    }
  });
}

}  // namespace santa
