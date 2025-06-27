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

import ArgumentParser
import Foundation

import santa_common_SNTConfigurator

extension Santactl {
  struct Status: ParsableCommand {
    static let configuration = CommandConfiguration(
      abstract: "Show Santa status information."
    )

    @Flag(help: "Output in JSON format")
    var json: Bool = false

    private enum CodingKeys: String, CodingKey {
      case json
    }

    let proxy = daemonConn()
    let config = SNTConfigurator.configurator()
    let dateFormatter = {
      let df = DateFormatter()
      df.dateFormat = "yyyy/MM/dd HH:mm:ss Z"
      return df
    }()

    func validate() throws {
      if proxy == nil {
        print("Error: Failed to connect to daemon")
        throw ExitCode(1)
      }
    }

    func run() {
      if json {
        let status = [
          "daemon": daemonStatus(),
          "sync": syncStatus(),
          "rule_types": {
            let status = ruleCountsStatus()
            return [
              "binary_rules": status.binary,
              "certificate_rules": status.certificate,
              "teamid_rules": status.teamID,
              "signingid_rules": status.signingID,
              "cdhash_rules": status.cdhash,
            ]
          }(),
          "cache": {
            let status = cacheStatus()
            return [
              "root_cache_count": status.rootCacheCount,
              "non_root_cache_count": status.nonRootCacheCount,
            ]
          }(),
          "watch_items": {
            let status = watchItemsStatus()
            return [
              "enabled": status.enabled,
              "rule_count": status.ruleCount,
              "policy_version": status.policyVersion,
              "config_path": status.configPath,
              "last_policy_update": status.lastPolicyUpdate,
            ]
          }(),
          "metrics": {
            let status = metricsStatus()
            return [
              "enabled": status.enabled,
              "server": status.server,
              "export_interval_seconds": status.exportInterval,
            ]
          }(),
          "transitive_allowlisting": {
            let status = transitiveAllowlistingStatus()
            return [
              "enabled": status.enabled,
              "compiler_rules": status.compilerRules,
              "transitive_rules": status.transitiveRules,
            ]
          }(),
        ]
        let jsonData = try? JSONSerialization.data(withJSONObject: status, options: .prettyPrinted)
        if let jsonData = jsonData, let jsonString = String(data: jsonData, encoding: .utf8) {
          print(jsonString)
        }
      } else {
        // Helper to print the key at a constant width
        func key(_ key: String) -> String {
          return key.withCString { String(format: "%-25s", $0) }
        }

        do {
          print(">>> Daemon Info")
          let status = daemonStatus()
          print("  \(key("Mode")) | \(status["mode"] ?? "Unknown")")
          print("  \(key("Log Type")) | \(status["log_type"] ?? "Unknown")")
          print("  \(key("File Logging")) | \(status["file_logging"] as! Bool ? "Yes" : "No")")
          print("  \(key("USB Blocking")) | \(status["block_usb"] as! Bool ? "Yes" : "No")")
          print("  \(key("USB Remounting Mode")) | \(status["remount_usb_mode"] ?? "None")")
          print("  \(key("On Start USB Options")) | \(status["on_start_usb_options"] ?? "Unknown")")
          print("  \(key("Static Rules")) | \(status["static_rules"] ?? "Unknown")")
          print(
            "  \(key("Watchdog CPU Events")) | \(status["watchdog_cpu_events"] ?? "Unknown") (Peak: \(String(format:"%.2f%%", status["watchdog_cpu_peak"] as! Double)))"
          )
          print(
            "  \(key("Watchdog RAM Events")) | \(status["watchdog_ram_events"] ?? "Unknown") (Peak: \(String(format: "%.2fMB", status["watchdog_ram_peak"] as! Double)))"
          )
        }

        do {
          print(">>> Cache Info")
          let status = cacheStatus()
          print("  \(key("Root Cache Count")) | \(status.rootCacheCount)")
          print("  \(key("Non-Root Cache Count")) | \(status.nonRootCacheCount)")
        }

        do {
          print(">>> Transitive Allowlisting")
          let status = transitiveAllowlistingStatus()
          print("  \(key("Enabled")) | \(status.enabled ? "Yes" : "No")")
          print("  \(key("Compiler Rules")) | \(status.compilerRules)")
          print("  \(key("Transitive Rules")) | \(status.transitiveRules)")
        }

        do {
          print(">>> Rule Types")
          let status = ruleCountsStatus()
          print("  \(key("Binary Rules")) | \(status.binary)")
          print("  \(key("Certificate Rules")) | \(status.certificate)")
          print("  \(key("TeamID Rules")) | \(status.teamID)")
          print("  \(key("SigningID Rules")) | \(status.signingID)")
          print("  \(key("CDHash Rules")) | \(status.cdhash)")
        }

        do {
          print(">>> Watch Items")
          let status = watchItemsStatus()
          print("  \(key("Enabled")) | \(status.enabled ? "Yes" : "No")")
          if status.enabled {
            print("  \(key("Policy Version")) | \(status.policyVersion)")
            print("  \(key("Rule Count")) | \(status.ruleCount)")
            print("  \(key("Config Path")) | \(status.configPath)")
            print("  \(key("Last Policy Update")) | \(status.lastPolicyUpdate)")
          }
        }

        do {
          print(">>> Sync")
          let status = syncStatus()
          print("  \(key("Enabled")) | \(status["enabled"] as! Bool ? "Yes" : "No")")
          print("  \(key("Sync Server")) | \(status["server"] ?? "Unknown")")
          print("  \(key("Clean Sync Required")) | \(status["clean_required"] as! Bool ? "Yes" : "No")")
          print("  \(key("Last Successful Full Sync")) | \(status["last_successful_full"] ?? "Unknown")")
          print("  \(key("Last Successful Rule Sync")) | \(status["last_successful_rule"] ?? "Unknown")")
          print("  \(key("Push Notifications")) | \(status["push_notifications"] ?? "Unknown")")
          print("  \(key("Bundle Scanning")) | \(status["bundle_scanning"] as! Bool ? "Yes" : "No")")
          print("  \(key("Events Pending Upload")) | \(status["events_pending_upload"] ?? "Unknown")")
        }

        do {
          print(">>> Metrics")
          let status = metricsStatus()
          print("  \(key("Enabled")) | \(status.enabled ? "Yes" : "No")")
          if status.enabled {
            print("  \(key("Server")) | \(status.server)")
            print("  \(key("Export Interval")) | \(status.exportInterval)")
          }
        }
      }
    }

    private func daemonStatus() -> Dictionary<String, Any> {
      var status: Dictionary<String, Any> = [
        "log_type": config.eventLogTypeRaw.lowercased(),
        "file_logging": config.fileChangesRegex != nil,
      ]

      proxy?.clientMode { mode in
        status["mode"] =
          switch mode {
          case .monitor: "Monitor"
          case .lockdown: "Lockdown"
          case .standalone: "Standalone"
          default: "Unknown \(mode)"
          }
      }

      proxy?.watchdogInfo { cpuEvents, ramEvents, cpuPeak, ramPeak in
        status["watchdog_cpu_events"] = cpuEvents
        status["watchdog_ram_events"] = ramEvents
        status["watchdog_cpu_peak"] = cpuPeak
        status["watchdog_ram_peak"] = ramPeak
      }

      proxy?.blockUSBMount { blockUSBMount in
        status["block_usb"] = blockUSBMount
        status["remount_usb_mode"] = ""

        if blockUSBMount {
          proxy?.remountUSBMode { remountUSBMode in
            status["remount_usb_mode"] = remountUSBMode?.count ?? 0 > 0 ? remountUSBMode! : ""
          }
        }
      }

      status["on_start_usb_options"] =
        switch config.onStartUSBOptions {
        case .unmount: "Unmount"
        case .forceUnmount: "ForceUnmount"
        case .remount: "Remount"
        case .forceRemount: "ForceRemount"
        default: "None"
        }

      proxy?.staticRuleCount { staticRuleCount in
        status["static_rules"] = staticRuleCount
      }

      return status
    }

    private func syncStatus() -> Dictionary<String, Any> {
      var status: Dictionary<String, Any> = [:]

      if config.syncBaseURL == nil || config.syncBaseURL!.absoluteString == "" {
        status["enabled"] = false
        return status
      }

      status["enabled"] = true
      status["server"] = config.syncBaseURL!.absoluteString

      proxy?.syncTypeRequired { syncType in
        status["clean_required"] = (syncType == .clean || syncType == .cleanAll)
      }

      proxy?.fullSyncLastSuccess { date in
        status["last_successful_full"] = date != nil ? dateFormatter.string(from: date!) : "null"
      }

      proxy?.ruleSyncLastSuccess { date in
        status["last_successful_rule"] = date != nil ? dateFormatter.string(from: date!) : "null"
      }

      proxy?.databaseEventCount { count in
        status["events_pending_upload"] = count
      }

      proxy?.pushNotificationStatus { pushStatus in
        status["push_notifications"] =
          switch pushStatus {
          case .disabled: "Disabled"
          case .disconnected: "Disconnected"
          case .connected: "Connected"
          default: "Unknown \(pushStatus)"
          }
      }

      proxy?.enableBundles { enabled in
        status["bundle_scanning"] = enabled
      }

      return status
    }

    private func ruleCountsStatus() -> (
      binary: Int64, certificate: Int64, teamID: Int64, signingID: Int64, cdhash: Int64
    ) {
      var ret: (Int64, Int64, Int64, Int64, Int64) = (0, 0, 0, 0, 0)
      proxy?.databaseRuleCounts { counts in
        ret = (
          counts.binary, counts.certificate, counts.teamID, counts.signingID, counts.cdhash
        )
      }
      return ret
    }

    private func cacheStatus() -> (rootCacheCount: UInt64, nonRootCacheCount: UInt64) {
      var ret: (UInt64, UInt64) = (0, 0)
      proxy?.cacheCounts { rootCacheCount, nonRootCacheCount in
        ret = (rootCacheCount, nonRootCacheCount)
      }
      return ret
    }

    private func watchItemsStatus() -> (
      enabled: Bool, ruleCount: UInt64, policyVersion: String, configPath: String, lastPolicyUpdate: String
    ) {
      var ret: (Bool, UInt64, String, String, String) = (false, 0, "", "", "")
      proxy?.watchItemsState { enabled, ruleCount, policyVersion, configPath, lastUpdateEpoch in
        if enabled {
          ret = (
            true, ruleCount, policyVersion ?? "Unknown", configPath ?? "(embedded)",
            lastUpdateEpoch > 0 ? dateFormatter.string(from: Date(timeIntervalSince1970: lastUpdateEpoch)) : "Never"
          )
        }
      }
      return ret
    }

    private func metricsStatus() -> (enabled: Bool, server: String, exportInterval: UInt) {
      if config.exportMetrics {
        return (true, config.metricURL?.absoluteString ?? "null", config.metricExportInterval)
      }
      return (false, "", 0)
    }

    private func transitiveAllowlistingStatus() -> (enabled: Bool, compilerRules: Int64, transitiveRules: Int64) {
      var ret: (Bool, Int64, Int64) = (false, 0, 0)

      proxy?.enableTransitiveRules { enabled in
        ret.0 = enabled
      }

      if ret.0 {
        // Note: It'd be nice to avoid having a second call to databaseRuleCounts
        proxy?.databaseRuleCounts { counts in
          ret.1 = counts.compiler
          ret.2 = counts.transitive
        }
      }

      return ret
    }
  }
}
