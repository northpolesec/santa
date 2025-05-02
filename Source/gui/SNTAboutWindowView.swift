import SwiftUI

import santa_common_MOLXPCConnection
import santa_common_SNTCommonEnums
import santa_common_SNTConfigurator
import santa_common_SNTStoredEvent
import santa_common_SNTXPCSyncServiceInterface
import santa_gui_SNTMessageView

@objc public class SNTAboutWindowViewFactory: NSObject {
  @objc public static func createWith(window: NSWindow) -> NSViewController {
    return NSHostingController(
      rootView: SNTAboutWindowView(w: window).fixedSize()
    )
  }
}

struct SNTAboutWindowView: View {
  let w: NSWindow?
  let c = SNTConfigurator.configurator()
  let v = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "unknown"

  var body: some View {
    SNTMessageView() {
      if let t = c.aboutText {
        Text(t).multilineTextAlignment(.center)
      } else {
        Text(
          """
          Santa is a security system providing application,
          device, and file-access controls.
          """,
          comment: "Explanation in About view"
        ).multilineTextAlignment(.center)
      }

      // Calling .init explicitly to get Markdown rendering
      let versionString = NSLocalizedString("Version **%@**", comment: "Version in About view")
      Text(.init(String(format: versionString, v))).padding(10.0)

      HStack {
        if c.moreInfoURL?.absoluteString.isEmpty == false {
          Button(action: moreInfoButton) {
            Text("More Info...").frame(width: 90.0)
          }
        }

        Button(action: dismissButton) {
          Text("Dismiss").frame(width: 90.0)
        }
        .keyboardShortcut(.defaultAction)

        if c.syncBaseURL != nil {
          SyncButtonView()
        }
      }.padding(10.0)

      Text(
        """
        Santa is made with ❤️ by the elves at [North Pole Security](https://northpole.security)
        along with contributions from our wonderful community
        """
      )
      .font(.system(size: 10.0, weight: .regular))
      .padding([.bottom], 10.0)
      .foregroundColor(.secondary)
      .multilineTextAlignment(.center)
      .padding(10.0)
    }
  }

  func dismissButton() {
    w?.close()
  }

  func moreInfoButton() {
    if let u = c.moreInfoURL {
      NSWorkspace.shared.open(u)
    }
    w?.close()
  }
}

// SyncLogReceiver is a helper class to receive logs from the sync service,
// storing them in an array for later retrieval if the sync fails.
class SyncLogReceiver: NSObject, SNTSyncServiceLogReceiverXPC {
  private var logs: [String] = []

  func didReceiveLog(_ log: String) {
    logs.append(log)
  }

  func getLogs() -> [String] {
    return logs
  }

  func clear() {
    logs.removeAll()
  }
}

struct SyncButtonView: View {
  @State private var inProgress = false
  @State private var syncStatus: SNTSyncStatusType = .unknown
  @State private var lr: MOLXPCConnection?

  let logReceiver = SyncLogReceiver()

  func sync() {
    logReceiver.clear()
    inProgress = true

    let ss = SNTXPCSyncServiceInterface.configuredConnection()
    ss?.invalidationHandler = {
      DispatchQueue.main.sync {
        inProgress = false
        syncStatus = .failedXPCConnection
      }
    }
    ss?.resume()

    let logListener = NSXPCListener.anonymous()
    lr = MOLXPCConnection(serverWith: logListener)
    lr?.exportedObject = logReceiver
    lr?.unprivilegedInterface = NSXPCInterface(with: SNTSyncServiceLogReceiverXPC.self)
    lr?.resume()

    let proxy = ss?.remoteObjectProxy as? SNTSyncServiceXPC
    proxy?.sync(withLogListener: logListener.endpoint, syncType: .normal) { status in
      lr = nil

      DispatchQueue.main.sync {
        inProgress = false
        syncStatus = status
      }

      if status == .success {
        DispatchQueue.main.asyncAfter(deadline: .now() + 5) {
          inProgress = false
          syncStatus = .unknown
        }
      }
    }
  }

  var body: some View {
    @State var showAlert = (syncStatus != .success && syncStatus != .unknown)

    Button(action: {
      sync()
    }) {
      if inProgress {
        ProgressView().frame(width: 90.0).controlSize(.small)
      } else if syncStatus == .success {
        Image(systemName: "checkmark.circle.fill")
          .foregroundColor(.blue)
          .frame(width: 90.0)
      } else {
        Text("Sync").frame(width: 90.0)
      }
    }
    .disabled(inProgress || syncStatus != .unknown)
    .alert("Sync Failed", isPresented: $showAlert) {
      Text("The sync operation failed. Please try again.")
      Button("Copy Logs") {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(logReceiver.getLogs().joined(separator: "\n"), forType: .string)

        inProgress = false
        syncStatus = .unknown
      }
      Button("OK", role: .cancel) {
        inProgress = false
        syncStatus = .unknown
      }
    } message: {
      switch syncStatus {
      case .preflightFailed:
        Text("The preflight check failed. Please check your network connection and try again.")
      case .eventUploadFailed:
        Text("The event upload failed. Please check your network connection and try again.")
      case .ruleDownloadFailed:
        Text("The rule download failed. Please check your network connection and try again.")
      case .postflightFailed:
        Text("The postflight check failed. Please check your network connection and try again.")
      case .tooManySyncsInProgress:
        Text("Too many syncs are in progress. Please try again later.")
      case .failedXPCConnection:
        Text("Failed to connect to the sync service. Please try again later.")
      default:
        Text("An unknown error occurred. Please try again.")
      }
    }
  }
}

// Enable previews in Xcode.
struct SNTAboutWindow_Previews: PreviewProvider {
  static var previews: some View {
    SNTAboutWindowView(w: nil)
  }
}
