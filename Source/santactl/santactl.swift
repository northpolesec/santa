import ArgumentParser
import Foundation

import santa_common_SNTXPCControlInterface

@main
struct Santactl: ParsableCommand {
  static let configuration = CommandConfiguration(
    abstract: "santactl is a tool for managing Santa.",
    subcommands: [  // Keep alphabetized!
      Bundleinfo.self,
      Doctor.self,
      EventUpload.self,
      Fileinfo.self,
      Flushcache.self,
      Metrics.self,
      Printlog.self,
      Rule.self,
      Status.self,
      Sync.self,
      Telemetry.self,
      Version.self,
    ]
  )

  private static func daemonXpcConn() -> Any? {
    guard let dc = SNTXPCControlInterface.configuredConnection() else {
      print("Failed to get configured connection")
      return nil
    }

    dc.invalidationHandler = {
      print("Daemon connection invalidated")
    }

    dc.resume()

    guard let proxy = dc.synchronousRemoteObjectProxy else {
      print("Failed to get remote object proxy")
      return nil
    }

    return proxy
  }

  static func daemonConn() -> SNTUnprivilegedDaemonControlXPC? {
    guard let proxy = daemonXpcConn() as? SNTUnprivilegedDaemonControlXPC else {
      print("Failed to get unprivileged daemon control proxy")
      return nil
    }
    return proxy
  }

  static func privilegedDaemonConn() -> SNTDaemonControlXPC? {
    guard let proxy = daemonXpcConn() as? SNTDaemonControlXPC else {
      print("Failed to get privileged daemon control proxy")
      return nil
    }
    return proxy
  }
}
