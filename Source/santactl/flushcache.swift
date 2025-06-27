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

import santa_common_MOLXPCConnection
import santa_common_SNTXPCControlInterface

extension Santactl {
  struct Flushcache: ParsableCommand {
    static let configuration = CommandConfiguration(
      // The flushcache command is mostly for debugging purposes, so we don't
      // want to display it in help output.
      shouldDisplay: false,
    )

    func validate() throws {
      try! requireRoot()
    }

    func run() throws {
      let proxy = privilegedDaemonConn()

      if let proxy = proxy {
        var success = false
        proxy.flushCache { result in
          success = result
        }

        if success {
          print("Cache flushed")
        } else {
          print("Cache flush failed")
          throw ExitCode(1)
        }
      } else {
        print("Failed to connect to daemon")
        throw ExitCode(2)
      }
    }
  }
}
