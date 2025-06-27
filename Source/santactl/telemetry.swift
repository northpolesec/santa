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

import santa_common_SNTFileInfo
import santa_common_SNTXPCControlInterface

extension Santactl {
  struct Telemetry: ParsableCommand {
    static let configuration = CommandConfiguration(
      abstract: "Interact with Santa telemetry."
    )

    private enum CodingKeys: String, CodingKey {
      case operation
    }

    private enum Operation: String, EnumerableFlag {
      case export
    }

    @Flag(help: "The operation to perform")
    private var operation: Operation

    func run() {
      switch operation {
      case .export:
        exportTelemetry()
      }
    }

    private func exportTelemetry() {
      guard let proxy = daemonConn() else {
        print("Failed to get daemon connection")
        return
      }

      proxy.exportTelemetry { success in
        if success {
          print("Telemetry exported successfully.")
        } else {
          print("Telemetry export failed. Please consult logs for more information.")
          abort()
        }
      }
    }
  }
}
