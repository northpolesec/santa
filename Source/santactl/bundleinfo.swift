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

import santa_common_SNTFileInfo
import santa_common_SNTStoredEvent
import santa_common_SNTXPCBundleServiceInterface

extension Santactl {
  class Bundleinfo: NSObject, ParsableCommand, SNTBundleServiceProgressXPC {
    static let configuration = CommandConfiguration(
      abstract: "Searches a bundle for binaries."
    )

    @Argument(help: "The path to the bundle to search.")
    var path: String

    override required init() {}

    var currentBinaryCount: UInt64 = 0
    var currentFileCount: UInt64 = 0
    var currentHashedCount: UInt64 = 0

    func run() throws {
      print("Bundle info for \(path)")
      print("Searching for files...")

      let fi: SNTFileInfo
      do {
        fi = try SNTFileInfo(path: path, error: ())
      } catch {
        // TODO: Write errors to stderr, why does Swift make this so hard?
        print("Failed to get file info: \(error.localizedDescription)")
        throw ExitCode(1)
      }

      if (fi.bundle() == nil) {
        print("Error: Not a bundle")
        return
      }

      let se = SNTStoredEvent()
      se.fileBundlePath = fi.bundlePath()

      let conn = SNTXPCBundleServiceInterface.configuredConnection()
      conn?.invalidationHandler = {
        print("Connection to Bundle Service invalidated")
      }
      conn?.resume()

      guard let proxy = conn?.synchronousRemoteObjectProxy as? SNTBundleServiceXPC else {
        print("Error: Failed to get bundle service interface")
        throw ExitCode(2)
      }

      let listener = NSXPCListener.anonymous()
      guard let lr = MOLXPCConnection(serverWith: listener) else {
        print("Failed to create return XPC connection for logging")
        throw ExitCode(3)
      }
      lr.exportedObject = self
      lr.privilegedInterface = NSXPCInterface(with: SNTBundleServiceProgressXPC.self)
      lr.resume()

      let progress = Progress(totalUnitCount: 1)
      progress.addObserver(self, forKeyPath: "fractionCompleted", options: .new, context: nil)
      progress.becomeCurrent(withPendingUnitCount: 100)

      proxy.hashBundleBinaries(for: se, listener: listener.endpoint) { hash, events, time in
        print("  Hash: \(hash ?? "unknown")")
        print("  Time: \(String(format: "%llums", time?.uint64Value ?? 0))")

        for event in events ?? [] {
          print("  * BundleID: \(event.fileBundleID ?? "Unknown")")
          print("    SHA-256: \(event.fileSHA256 ?? "Unknown")")

          if event.filePath != nil {
            let fp = event.filePath!.dropFirst(se.fileBundlePath.count + 1)
            print("    Path: \(fp)")
          }
        }
      }
    }

    override func observeValue(
      forKeyPath keyPath: String?,
      of object: Any?,
      change: [NSKeyValueChangeKey: Any]?,
      context: UnsafeMutableRawPointer?
    ) {
      if keyPath == "fractionCompleted" {
        let progress = object as! Progress

        // Return to the start of the previous line and clear it
        print("\u{001B}[1F\u{001B}[2K", terminator: "")

        if progress.fractionCompleted == 100.0 {
          print("\tComplete: 100%")

          // Return to start of previous line so the final output overwrites it.
          print("\u{001B}[1F", terminator: "")
        } else if self.currentHashedCount > 0 {
          print(
            "\tComplete: \((Int)(progress.fractionCompleted * 100))% | \(self.currentHashedCount) hashed / \(self.currentBinaryCount) binaries",
          )
        } else {
          print(
            "\tComplete: \((Int)(progress.fractionCompleted * 100))% | \(self.currentBinaryCount) binaries / \(self.currentFileCount) files",
          )
        }
      }
    }

    func updateCounts(for event: SNTStoredEvent, binaryCount: UInt64, fileCount: UInt64, hashedCount: UInt64) {
      self.currentBinaryCount = binaryCount
      self.currentFileCount = fileCount
      self.currentHashedCount = hashedCount
    }
  }
}
