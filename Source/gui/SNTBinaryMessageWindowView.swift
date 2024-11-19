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
    bundleProgress: SNTBundleProgress,
    uiStateCallback: ((TimeInterval) -> Void)?
  ) -> NSViewController {
    return NSHostingController(
      rootView: SNTBinaryMessageWindowView(
        window: window,
        event: event,
        customMsg: customMsg,
        customURL: customURL,
        bundleProgress: bundleProgress,
        uiStateCallback: uiStateCallback
      )
      .fixedSize()
    )
  }
}

func copyDetailsToClipboard(e: SNTStoredEvent?, customURL: String?) {
  var s = "Santa blocked \(e?.fileBundleName ?? "an application:")"
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
  @StateObject var bundleProgress: SNTBundleProgress

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
          Button(action: { copyDetailsToClipboard(e: e, customURL: customURL as String?) }) {
            HStack(spacing: 2.0) {
              Text("Copy Details", comment: "Copy Details button in more details dialog")
                .foregroundColor(.blue)
              Image(systemName: "pencil.and.list.clipboard").foregroundColor(.blue)
            }
          }
          .buttonStyle(ScalingButtonStyle())
          .keyboardShortcut("d", modifiers: .command)
          .help("⌘ d")

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
  @StateObject var bundleProgress: SNTBundleProgress

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
        if let bundleName = e?.fileBundleName {
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
      MoreDetailsView(e: e, customURL: customURL, bundleProgress: bundleProgress)
    }

    VStack(spacing: 2.0) {
      Spacer()

      ZStack {
        MoreDetailsButton($isShowingDetails)

        // This button is hidden and exists only to allow using the Cmd+D keyboard shortcut
        // to copy the event details to the clipboard even if the "More Details" button hasn't been pressed.
        Button(action: { copyDetailsToClipboard(e: e, customURL: customURL as String?) }) {
          Text(verbatim: "Copy Details")
        }
        .buttonStyle(ScalingButtonStyle())
        .opacity(0.0)  // Invisible!
        .keyboardShortcut("d", modifiers: .command)
        .help("⌘ d")
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
  @StateObject var bundleProgress: SNTBundleProgress
  let uiStateCallback: ((TimeInterval) -> Void)?

  @Environment(\.openURL) var openURL

  @State public var preventFutureNotifications = false
  @State public var preventFutureNotificationPeriod: TimeInterval = NotificationSilencePeriods[0]

  let c = SNTConfigurator.configurator()

  var body: some View {
    SNTMessageView(
      SNTBlockMessage.attributedBlockMessage(for: event, customMessage: customMsg as String?)
    ) {
      SNTBinaryMessageEventView(e: event!, customURL: customURL, bundleProgress: bundleProgress)

      VStack(spacing: 15.0) {
        SNTNotificationSilenceView(
          silence: $preventFutureNotifications,
          period: $preventFutureNotificationPeriod
        )

        if event?.needsBundleHash ?? false && !bundleProgress.isFinished {
          if bundleProgress.fractionCompleted == 0.0 {
            ProgressView {
              Text(bundleProgress.label)
            }.progressViewStyle(.linear)
          } else {
            ProgressView(value: bundleProgress.fractionCompleted) {
              Text(bundleProgress.label)
            }
          }
        }

        HStack(spacing: 15.0) {
          if !(c.eventDetailURL?.isEmpty ?? false)
            && !(event?.needsBundleHash ?? false && !bundleProgress.isFinished)
          {
            OpenEventButton(customText: c.eventDetailText, action: openButton)
          }
          DismissButton(
            customText: c.dismissText,
            silence: preventFutureNotifications,
            action: dismissButton
          )
        }
      }

      Spacer()
    }
    .fixedSize()
  }

  func openButton() {
    if let callback = uiStateCallback {
      if self.preventFutureNotifications {
        callback(self.preventFutureNotificationPeriod)
      } else {
        callback(0)
      }
    }

    let url = SNTBlockMessage.eventDetailURL(for: event, customURL: customURL as String?)
    window?.close()
    if let url = url {
      openURL(url)
    }
  }

  func dismissButton() {
    if let callback = uiStateCallback {
      if self.preventFutureNotifications {
        callback(self.preventFutureNotificationPeriod)
      } else {
        callback(0)
      }
    }
    window?.close()
  }
}
