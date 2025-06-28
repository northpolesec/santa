/// Copyright 2024 North Pole Security, Inc.
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

import SwiftUI

import santa_common_SNTBlockMessage
import santa_common_SNTCommonEnums
import santa_common_SNTConfigState
import santa_common_SNTConfigurator
import santa_common_SNTStoredEvent
import santa_gui_SNTMessageView

// A small class that will ferry bundle hashing state from SNTBinaryMessageWindowController
// to SwiftUI.
@objc public class SNTBundleProgress: NSObject, ObservableObject {
  @Published @objc public var isFinished = false
  @Published @objc public var fractionCompleted = 0.0
  @Published @objc public var label = ""
}

@objc public class SNTBinaryMessageWindowViewFactory: NSObject {
  @objc public static func createWith(
    window: NSWindow,
    event: SNTStoredEvent,
    customMsg: NSString?,
    customURL: NSString?,
    configState: SNTConfigState,
    bundleProgress: SNTBundleProgress,
    uiStateCallback: ((TimeInterval) -> Void)?,
    replyCallback: ((Bool) -> Void)?
  ) -> NSViewController {
    return NSHostingController(
      rootView: SNTBinaryMessageWindowView(
        window: window,
        event: event,
        customMsg: customMsg,
        customURL: customURL,
        configState: configState,
        bundleProgress: bundleProgress,
        uiStateCallback: uiStateCallback,
        replyCallback: replyCallback
      )
      .fixedSize()
    )
  }
}

func copyDetailsToClipboard(e: SNTStoredEvent?, customURL: String?) {
  var s = "Santa blocked \((e?.fileBundleName?.isEmpty == false) ? e!.fileBundleName! : "an application")"
  if let publisher = e?.publisherInfo {
    s += "\nPublisher  : \(publisher)"
  }
  s += "\nUser       : \(e?.executingUser ?? "unknown")"
  s += "\nPath       : \(e?.filePath ?? "unknown")"

  if let signingID = e?.signingID {
    s += "\nSigningID  : \(signingID)"
  }
  if let bundleHash = e?.fileBundleHash {
    s += "\nBundle Hash: \(bundleHash)"
  }
  if let cdhash = e?.cdhash {
    s += "\nCDHash     : \(cdhash)"
  }
  s += "\nSHA-256    : \(e?.fileSHA256 ?? "unknown")"
  s += "\nParent     : \(e?.parentName ?? "") (\(String(format: "%d", e?.ppid.intValue ?? 0)))"

  let url = SNTBlockMessage.eventDetailURL(for: e, customURL: customURL as String?)
  s += "\nURL        : \(url?.absoluteString ?? "unknown")"
  s += "\n"

  let pasteboard = NSPasteboard.general
  pasteboard.clearContents()
  pasteboard.setString(s, forType: .string)
}

struct MoreDetailsView: View {
  let e: SNTStoredEvent?
  let customURL: NSString?

  @Environment(\.presentationMode) var presentationMode

  func addLabel(@ViewBuilder closure: () -> some View) -> some View {
    HStack(spacing: 5.0) {
      VStack(alignment: .leading, spacing: 2.0) {
        closure()
      }
      Spacer()
    }
    .frame(minWidth: MAX_OUTER_VIEW_WIDTH - 60)
  }

  var body: some View {
    HStack(spacing: 20.0) {
      VStack(spacing: 20.0) {
        addLabel {
          Text("Path").bold().font(Font.system(size: 12.0))
          Text(e?.filePath ?? "unknown").textSelection(.enabled)
        }

        Divider()

        if let signingID = e?.signingID {
          addLabel {
            Text("Signing ID").bold().font(Font.system(size: 12.0))
            Text(signingID).font(Font.system(size: 12.0).monospaced()).textSelection(.enabled)
          }
          Divider()
        }

        if let bundleHash = e?.fileBundleHash {
          addLabel {
            Text("Bundle Hash").bold().font(Font.system(size: 12.0))
            Text(bundleHash).font(Font.system(size: 12.0).monospaced()).frame(width: 240)
              .textSelection(.enabled)
          }
          Divider()
        }

        if let cdHash = e?.cdhash {
          addLabel {
            Text("CDHash").bold().font(Font.system(size: 12.0))
            Text(cdHash).font(Font.system(size: 12.0).monospaced()).textSelection(.enabled)
          }
          Divider()
        }

        addLabel {
          Text("SHA-256").bold().font(Font.system(size: 12.0))
          // Fix the max width of this to 240px so that the SHA-256 splits across 2 lines evenly.
          Text(e?.fileSHA256 ?? "unknown").font(Font.system(size: 12.0).monospaced()).frame(
            width: 240
          ).textSelection(.enabled)
        }

        Divider()

        addLabel {
          Text("Parent").bold().font(Font.system(size: 12.0))
          Text(verbatim: "\(e?.parentName ?? "") (\(e?.ppid.stringValue ?? "unknown"))")
            .textSelection(.enabled)
        }

        Spacer()

        HStack {
          CopyDetailsButton(action: {
            copyDetailsToClipboard(e: e, customURL: customURL as String?)
          })

          Button(action: { presentationMode.wrappedValue.dismiss() }) {
            HStack(spacing: 2.0) {
              Text("Dismiss", comment: "Dismiss button in more details dialog").foregroundColor(
                .blue
              )
              Image(systemName: "xmark.circle").foregroundColor(.blue)
            }
          }
          .buttonStyle(ScalingButtonStyle())
          .keyboardShortcut(.escape, modifiers: .command)
          .help("⌘ Esc")
        }

        Spacer()
      }.frame(maxWidth: MAX_OUTER_VIEW_WIDTH - 20).padding(20.0)
    }.frame(width: MAX_OUTER_VIEW_WIDTH - 20).fixedSize().background(Color.gray.opacity(0.2))
  }
}

struct SNTBinaryMessageEventView: View {
  let e: SNTStoredEvent?
  let customURL: NSString?

  @State private var isShowingDetails = false

  var body: some View {
    HStack(spacing: 20.0) {
      VStack(alignment: .trailing, spacing: 10.0) {
        if e?.fileBundleName != "" {
          Text("Application").bold().font(Font.system(size: 12.0))
        } else if e?.filePath != "" {
          Text("Filename").bold().font(Font.system(size: 12.0))
        }

        if e?.publisherInfo ?? "" != "" {
          Text("Publisher").bold().font(Font.system(size: 12.0))
        }

        Text("User").bold().font(Font.system(size: 12.0))
      }

      Divider()

      VStack(alignment: .leading, spacing: 10.0) {
        if let bundleName = e?.fileBundleName, !bundleName.isEmpty {
          TextWithLimit(bundleName)
        } else if let filePath = e?.filePath {
          TextWithLimit((filePath as NSString).lastPathComponent)
        }

        if let publisher = e?.publisherInfo {
          TextWithLimit(publisher)
        }

        TextWithLimit(e?.executingUser ?? "")
      }.textSelection(.enabled)
    }.sheet(isPresented: $isShowingDetails) {
      MoreDetailsView(e: e, customURL: customURL)
    }

    VStack(spacing: 2.0) {
      Spacer()

      HStack {
        MoreDetailsButton($isShowingDetails)

        CopyDetailsButton(action: {
          copyDetailsToClipboard(e: e, customURL: customURL as String?)
        })
      }

      Spacer()
    }
  }
}

struct SNTBinaryMessageWindowView: View {
  let window: NSWindow?
  let event: SNTStoredEvent?
  let customMsg: NSString?
  let customURL: NSString?
  let configState: SNTConfigState
  @StateObject var bundleProgress: SNTBundleProgress
  let uiStateCallback: ((TimeInterval) -> Void)?
  let replyCallback: ((Bool) -> Void)?

  @Environment(\.openURL) var openURL

  @State public var preventFutureNotifications = false
  @State public var preventFutureNotificationPeriod: TimeInterval = NotificationSilencePeriods[0]

  let c = SNTConfigurator.configurator()

  func getDismissText() -> String? {
    if event?.needsBundleHash ?? false && !bundleProgress.isFinished {
      return "Cancel"
    }
    return c.dismissText
  }

  var body: some View {
    SNTMessageView(
      SNTBlockMessage.attributedBlockMessage(for: event, customMessage: customMsg as String?)
    ) {
      SNTBinaryMessageEventView(e: event!, customURL: customURL)

      if configState.enableNotificationSilences {
        SNTNotificationSilenceView(silence: $preventFutureNotifications, period: $preventFutureNotificationPeriod)
      }

      // ProgressView supports showing both determinate and indeterminate progress.
      // Normally to show indeterminate progress you initialize without providing
      // any value, but passing nil has the same effect. Until bundle hashing has
      // made progress scanning the bundle we want to show an indeterminate spinner.
      if event?.needsBundleHash ?? false {
        ProgressView(value: (bundleProgress.fractionCompleted == 0.0 ? nil : bundleProgress.fractionCompleted)) {
          Text(bundleProgress.label)
        }
        .progressViewStyle(.linear)
        .frame(
          width: bundleProgress.isFinished ? 0.0 : .infinity,
          height: bundleProgress.isFinished ? 0.0 : .infinity
        )
        .animation(.spring(duration: 0.4), value: bundleProgress.isFinished)
      }

      // Display the standalone error message to the user if one is provided.
      if configState.clientMode == .standalone {
        let (canAuthz, err) = CanAuthorizeWithTouchID()
        if !canAuthz {
          if let errMsg = err {
            Text(errMsg.localizedDescription).foregroundColor(.red)
          }
        }
      }

      HStack(spacing: 15.0) {
        if shouldAddStandaloneButton() {
          StandaloneButton(action: standAloneButton)
        } else if shouldAddOpenButton() {
          OpenEventButton(
            customText: c.eventDetailText,
            disabled: (event?.needsBundleHash ?? false && !bundleProgress.isFinished),
            action: openButton
          )
        }

        DismissButton(
          customText: getDismissText(),
          silence: preventFutureNotifications,
          action: dismissButton
        )
      }
      Spacer()
    }
    .fixedSize()
  }

  func shouldAddStandaloneButton() -> Bool {
    var shouldDisplay = configState.clientMode == .standalone

    let (canAuthz, _) = CanAuthorizeWithTouchID()
    if !canAuthz {
      shouldDisplay = false
    }

    let blockedUnknownEvent = SNTEventState.blockUnknown;

    // Only display the standalone button if the event is for a block that fell
    // was the result of a fall through.
    if let decision = event?.decision {
      if decision != blockedUnknownEvent {
        shouldDisplay = false
      }
    }

    return shouldDisplay
  }

  func shouldAddOpenButton() -> Bool {
    if c.eventDetailURL?.isEmpty ?? true {
      return false
    }
    return true
  }

  func openButton() {
    if let callback = uiStateCallback {
      if self.preventFutureNotifications {
        callback(self.preventFutureNotificationPeriod)
      } else {
        callback(0)
      }
    }

    if let callback = replyCallback {
      callback(false)
    }

    window?.close()

    let detailsURL = SNTBlockMessage.eventDetailURL(for: event, customURL: customURL as String?)

    if let url = detailsURL {
      openURL(url)
    }
  }

  // This button is only shown when the standalone mode is enabled in place of
  // the "Open Event" button.
  func standAloneButton() {
    guard let e = self.event else {
      if let cb = self.replyCallback {
        cb(false)
      }
      return
    }

    let bundleName = e.fileBundleName ?? ""
    let filePath = e.filePath ?? ""
    let signingID = e.signingID ?? ""

    var msg = "authorize execution"

    if !bundleName.isEmpty {
      let format = NSLocalizedString(
        "authorize execution of the application %@",
        comment: "Authorize execution of an application with name"
      )
      msg = String.localizedStringWithFormat(format, bundleName)
    } else if !signingID.isEmpty {
      let format = NSLocalizedString(
        "authorize execution of %@",
        comment: "Authorize execution of an application with Signing ID or Path"
      )
      msg = String.localizedStringWithFormat(format, signingID)
    } else if !filePath.isEmpty {
      let format = NSLocalizedString(
        "authorize execution of %@",
        comment: "Authorize execution of an application with Signing ID or Path"
      )
      msg = String.localizedStringWithFormat(format, (filePath as NSString).lastPathComponent)
    }

    // Force unwrap the callback because it should always be set and is a
    // programming error if it isn't.
    //
    // Note: this may prevent other replyBlocks from being run, but should only
    // crash the GUI process meaning policy decisions will still be enforced.
    let callback = self.replyCallback!;

    AuthorizeViaTouchID(
      reason: msg,
      replyBlock: { success in
        callback(success)
        DispatchQueue.main.sync {
          window?.close()
        }
      }
    )
  }

  func dismissButton() {
    if let callback = uiStateCallback {
      if self.preventFutureNotifications {
        callback(self.preventFutureNotificationPeriod)
      } else {
        callback(0)
      }
    }

    // Close the window after responding to the block.
    if let callback = replyCallback {
      callback(false)
    }
    window?.close()
  }
}
