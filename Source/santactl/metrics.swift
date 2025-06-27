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
import santa_common_SNTMetricSet

extension Santactl {
  struct Metrics: ParsableCommand {
    static let configuration = CommandConfiguration(
      abstract: "Show Santa metric information."
    )

    @Flag(help: "Show JSON output")
    var json: Bool = false

    @Argument(help: "The metrics to show. If a metric is prefixed with a '-' it will be hidden.")
    var filter: [String] = []

    private enum CodingKeys: String, CodingKey {
      case json
      case filter
    }

    let config = SNTConfigurator.configurator()

    func run() throws {
      guard let proxy = daemonConn() else {
        print("Failed to connect to daemon")
        throw ExitCode(1)
      }

      var metrics: [String: Any] = [:]
      proxy.metrics { result in
        metrics = result ?? [:]
      }

      let filteredMetrics = filterMetrics(metrics)
      let normalizedMetrics = SNTMetricConvertDatesToISO8601Strings(filteredMetrics)

      if json {
        do {
          try jsonPrint(normalizedMetrics)
        } catch {
          print("Failed to print JSON: \(error)")
        }
      } else {
        prettyPrint(normalizedMetrics)
      }
    }

    func filterMetrics(_ metrics: [String: Any]) -> [String: Any] {
      if filter.isEmpty {
        return metrics
      }

      let filteredMetrics = (metrics["metrics"] as? [String: Any])?.filter { key, _ in
        return filter.contains(where: { $0 == key })
      }

      return [
        "root_labels": metrics["root_labels"] ?? [],
        "metrics": filteredMetrics ?? [:],
      ]
    }

    func prettyPrint(_ metrics: [String: Any]) {
      func key(_ key: String) -> String {
        return key.withCString { String(format: "%-25s", $0) }
      }

      print(">>> Metrics Info")
      if config.exportMetrics {
        print("  \(key("Enabled")) | Yes")
        print("  \(key("Metrics Server")) | \(config.metricURL?.absoluteString ?? "Not configured")")
        print("  \(key("Metrics Format")) | \(SNTMetricStringFromMetricFormatType(config.metricFormat))")
        print("  \(key("Export Interval")) | \(config.metricExportInterval)s")
      } else {
        print("  \(key("Enabled")) | No")
      }
      print("")

      print(">>> Root Labels")
      for (k, v) in metrics["root_labels"] as? [String: Any] ?? [:] {
        print("  \(key(k)) | \(v)")
      }
      print("")

      print(">>> Metrics")
      if !config.exportMetrics {
        print("  WARNING: Metrics export is not enabled, many metrics will have missing data.")
        print("")
      }
      for (k, v) in metrics["metrics"] as? [String: [String?: Any]] ?? [:] {
        let metricType = SNTMetricType(rawValue: (v["type"] as? NSNumber)?.intValue ?? 0) ?? .unknown

        print("  \(key("Metric Name")) | \(k)")
        print("  \(key("Description")) | \(v["description"] ?? "")")
        print("  \(key("Type")) | \(SNTMetricMakeStringFromMetricType(metricType))")

        // Each metric has a set of fields. There is
        for (k, v) in v["fields"] as? [String: [[String: Any]]] ?? [:] {
          for v in v {
            let fieldDisplayName = "\(k)=\(v["value"] ?? "")"
            if fieldDisplayName != "=" {
              print("  \(key("Field")) | \(fieldDisplayName)")
            }
            print("  \(key("Created")) | \(v["created"] ?? "N/A")")
            print("  \(key("Updated")) | \(v["last_updated"] ?? "N/A")")
            print("  \(key("Data")) | \(v["data"] ?? "N/A")")
          }
        }

        print("")
      }
    }

    func jsonPrint(_ metrics: [String: Any]) throws {
      let json = try JSONSerialization.data(withJSONObject: metrics, options: .prettyPrinted)
      print(String(data: json, encoding: .utf8)!)
    }
  }
}
