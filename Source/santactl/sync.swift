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
import santa_common_SNTCommonEnums
import santa_common_SNTConfigurator
import santa_common_SNTDropRootPrivs
import santa_common_SNTXPCSyncServiceInterface

extension Santactl {
  class Sync: ParsableCommand, SNTSyncServiceLogReceiverXPC {
    static let configuration = CommandConfiguration(
      abstract: "Synchronizes Santa with a configured server."
    )

    @Flag(help: "Enable debug logging.")
    private var debug: Bool = false

    @Flag(
      help: """
            Perform a clean sync, erasing all existing non-transitive rules
            and requesting a clean sync from the server.
        """
    )
    private var clean: Bool = false

    @Flag(
      help: """
            Perform a full sync, erasing all existing rules
            and requesting a clean sync from the server.
        """
    )
    private var cleanAll: Bool = false

    required init() {}

    func validate() throws {
      let sbu = SNTConfigurator().syncBaseURL
      if sbu == nil || sbu!.absoluteString.isEmpty {
        throw ValidationError("No sync base URL configured")
      }
    }

    func run() throws {
      if !DropRootPrivileges() {
        print("Failed to drop root privileges")
        throw ExitCode(1)
      }

      let listener = NSXPCListener.anonymous()
      guard let lr = MOLXPCConnection(serverWith: listener) else {
        print("Failed to create return XPC connection for logging")
        throw ExitCode(1)
      }
      lr.exportedObject = self
      lr.unprivilegedInterface = NSXPCInterface(with: SNTSyncServiceLogReceiverXPC.self)
      lr.resume()

      let syncType =
        if cleanAll {
          SNTSyncType.cleanAll
        } else if clean {
          SNTSyncType.clean
        } else {
          SNTSyncType.normal
        }

      guard let syncService = syncService() else {
        throw ExitCode(1)
      }

      syncService.sync(withLogListener: listener.endpoint, syncType: syncType) { reply in
        if reply == SNTSyncStatusType.tooManySyncsInProgress {
          print("Too many syncs in progress")
        }
      }
    }

    func didReceiveLog(_ log: String, with: OSLogType) {
      if with == .debug && !self.debug {
        return
      }
      print(log)
    }

    private func syncService() -> SNTSyncServiceXPC? {
      guard let dc = SNTXPCSyncServiceInterface.configuredConnection() else {
        print("Failed to get configured connection")
        return nil
      }

      dc.invalidationHandler = {
        print("Failed to connect to sync service")
      }

      dc.resume()

      guard let proxy = dc.synchronousRemoteObjectProxy as? SNTSyncServiceXPC else {
        print("Failed to get remote object proxy")
        return nil
      }
      return proxy
    }
  }
}
