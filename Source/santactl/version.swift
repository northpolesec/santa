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

extension Santactl {
  struct Version: ParsableCommand {
    static let configuration = CommandConfiguration(
      abstract: "Show Santa component versions."
    )

    @Flag(help: "Output in JSON format")
    var json: Bool = false

    private let kSantaDPath =
      "/Applications/Santa.app/Contents/Library/SystemExtensions/com.northpolesec.santa.daemon.systemextension/Contents/MacOS/com.northpolesec.santa.daemon"
    private let kSantaAppPath = "/Applications/Santa.app"

    private enum CodingKeys: String, CodingKey {
      case json
    }

    func run() {
      if json {
        let versions: [String: String] = [
          "santad": santadVersion(),
          "santactl": santactlVersion(),
          "SantaGUI": santaAppVersion(),
        ]

        if let versionsData = try? JSONSerialization.data(withJSONObject: versions, options: .prettyPrinted),
          let versionsStr = String(data: versionsData, encoding: .utf8)
        {
          print(versionsStr)
        } else {
          print("Error: Failed to serialize versions to JSON")
        }
      } else {
        print(String(format: "santad       | %@", santadVersion()))
        print(String(format: "santactl     | %@", santactlVersion()))
        print(String(format: "SantaGUI     | %@", santaAppVersion()))
      }
    }

    private func composeVersionsFromDict(_ dict: [AnyHashable: Any]) -> String {
      guard let bundleVersion = dict["CFBundleVersion"] as? String else {
        return ""
      }

      let productVersion = dict["CFBundleShortVersionString"] as? String ?? ""
      let buildVersion = bundleVersion.components(separatedBy: ".").last ?? ""

      var commitHash = dict["SNTCommitHash"] as? String ?? ""
      if commitHash.count > 8 {
        commitHash = String(commitHash.prefix(8))
      }

      return "\(productVersion) (build \(buildVersion), commit \(commitHash))"
    }

    private func santadVersion() -> String {
      guard let daemonInfo = try? SNTFileInfo(path: kSantaDPath, error: ()) else {
        return "Unknown"
      }
      return composeVersionsFromDict(daemonInfo.infoPlist())
    }

    private func santaAppVersion() -> String {
      guard let guiInfo = try? SNTFileInfo(path: kSantaAppPath, error: ()) else {
        return "Unknown"
      }
      return composeVersionsFromDict(guiInfo.infoPlist())
    }

    private func santactlVersion() -> String {
      guard let infoDictionary = Bundle.main.infoDictionary else {
        return "Unknown"
      }
      return composeVersionsFromDict(infoDictionary)
    }
  }
}
