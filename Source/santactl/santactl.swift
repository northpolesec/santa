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
      Install.self,
      Metrics.self,
      Printlog.self,
      Rule.self,
      Status.self,
      Sync.self,
      Telemetry.self,
      Version.self,
    ]
  )

  private static func daemonXpcConn(synchronous: Bool) -> Any? {
    guard let dc = SNTXPCControlInterface.configuredConnection() else {
      print("Failed to get configured connection")
      return nil
    }

    dc.invalidationHandler = {
      print("Daemon connection invalidated")
    }

    dc.resume()

    if synchronous {
      guard let proxy = dc.synchronousRemoteObjectProxy else {
        print("Failed to get remote object proxy")
        return nil
      }
      return proxy
    }
    guard let proxy = dc.remoteObjectProxy else {
      print("Failed to get remote object proxy")
      return nil
    }
    return proxy
  }

  static func daemonConn() -> SNTUnprivilegedDaemonControlXPC? {
    guard let proxy = daemonXpcConn(synchronous: true) as? SNTUnprivilegedDaemonControlXPC else {
      print("Failed to get unprivileged daemon control proxy")
      return nil
    }
    return proxy
  }

  static func privilegedDaemonConn(synchronous: Bool = true) -> SNTDaemonControlXPC? {
    guard let proxy = daemonXpcConn(synchronous: synchronous) as? SNTDaemonControlXPC else {
      print("Failed to get privileged daemon control proxy")
      return nil
    }
    return proxy
  }

  static func requireRoot() throws {
    if geteuid() != 0 {
      throw ValidationError("This command must be run as root")
    }
  }
}
