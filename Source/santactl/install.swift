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
import Dispatch

extension Santactl {
  struct Install: ParsableCommand {
    static let configuration = CommandConfiguration(
      // The install command is used during migrations, while it's not harmful,
      // we don't need to display it in help output because users aren't
      // expected to run it directly.
      shouldDisplay: false,
    )

    private enum CodingKeys: CodingKey {}

    let installPath = "/var/db/santa/migration/Santa.app"
    let secondsToWait = 15

    func validate() throws {
      try! requireRoot()
    }

    func run() throws {
      let proxy = privilegedDaemonConn(synchronous: false)

      guard let proxy = proxy else {
        print("Failed to connect to daemon")
        throw ExitCode(2)
      }

      print("Asking daemon to install: \(installPath)")
      print("... waiting for up to \(secondsToWait) seconds...")

      let semaphore = DispatchSemaphore(value: 0)
      var success = false
      proxy.installSantaApp(installPath) { result in
        success = result
        semaphore.signal()
      }

      if semaphore.wait(timeout: .now() + .seconds(secondsToWait)) == .timedOut {
        print("Installation timed out.")
        throw ExitCode(3)
      }

      if success {
        print("Installation was successful")
      } else {
        print("Installation failed. Please consult logs for more information.")
        throw ExitCode(4)
      }

    }
  }
}
