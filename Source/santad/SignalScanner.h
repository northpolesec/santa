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

#ifndef SANTA_SANTAD_SIGNALSCANNER_H
#define SANTA_SANTAD_SIGNALSCANNER_H

#import <Foundation/Foundation.h>
#include <dispatch/dispatch.h>

#include <atomic>
#include <memory>
#include <string>
#include <vector>

#import "Source/common/SNTSignal.h"
#import "Source/common/SNTStoredSignalReport.h"
#include "Source/common/ScopedFile.h"
#include "Source/santad/SleighLauncher.h"
#include "absl/base/thread_annotations.h"
#include "absl/synchronization/mutex.h"

namespace santa {

// Runs Sleigh signal scans over closed telemetry spool files. Holds the current
// set of synced detection signals in memory (refreshed via SetSignals when the
// signal_rules config changes), and on each closed spool file runs a Sleigh
// signal scan, handing the resulting reports to a caller-supplied handler
// (which persists + uploads them).
//
// Scans run on a private serial queue so they never block the spool's queue.
class SignalScanner : public std::enable_shared_from_this<SignalScanner> {
 public:
  using ReportHandlerBlock = void (^)(NSArray<SNTStoredSignalReport*>*);

  static std::shared_ptr<SignalScanner> Create(std::unique_ptr<SleighLauncher> sleigh_launcher,
                                               uint32_t timeout_secs,
                                               ReportHandlerBlock report_handler);

  ~SignalScanner() = default;

  SignalScanner(SignalScanner&) = delete;
  SignalScanner& operator=(SignalScanner&) = delete;

  // Replace the in-memory signal set. Thread-safe.
  void SetSignals(NSArray<SNTSignal*>* signals);

  // Asynchronously scan a just-closed spool file at `path`, read via `file` (a read-only fd open
  // on it). Returns immediately; the scan runs on the private serial queue. A no-op when no
  // signals are configured or `file` is null. Holding `file` open lets the scan read the data
  // even if the telemetry exporter unlinks the path before the scan runs; the fd is closed when
  // the scan completes.
  void ScanFile(std::string path, std::shared_ptr<ScopedFile> file);

 private:
  // Private: SignalScanner relies on shared_from_this(), so it must only ever be owned by a
  // std::shared_ptr. Construct via Create().
  SignalScanner(std::unique_ptr<SleighLauncher> sleigh_launcher, uint32_t timeout_secs,
                ReportHandlerBlock report_handler, dispatch_queue_t scan_q);

  // Upper bound on opened-but-not-yet-scanned files. Each pending scan retains an open fd to a
  // closed spool file; scans run serially (one Sleigh fork at a time), so under sustained heavy
  // telemetry the backlog — and the retained fds — would otherwise grow without limit, exhausting
  // the daemon's fd budget and pinning unlinked spool files on disk (defeating spool eviction).
  // When the cap is hit, new scans are dropped (and their fds released), shedding load the same
  // way the spool evicts its oldest files to stay bounded.
  static constexpr int kMaxInFlightScans = 32;

  std::unique_ptr<SleighLauncher> sleigh_launcher_;
  uint32_t timeout_secs_;
  ReportHandlerBlock report_handler_;
  dispatch_queue_t scan_q_;
  std::atomic<int> in_flight_{0};
  absl::Mutex lock_;
  // Each entry is a serialized santa.common.v1.Signal.
  std::vector<std::string> signals_ ABSL_GUARDED_BY(lock_);
};

}  // namespace santa

#endif  // SANTA_SANTAD_SIGNALSCANNER_H
