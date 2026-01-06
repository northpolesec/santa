/// Copyright 2023 Google LLC
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
import santa_common_SNTConfigBundle
import santa_common_SNTStoredNetworkMountEvent
import santa_gui_SNTMessageView

@objc public class SNTNetworkMountMessageWindowViewFactory: NSObject {
  @objc public static func createWith(
    window: NSWindow,
    event: SNTStoredNetworkMountEvent,
    configBundle: SNTConfigBundle,
    uiStateCallback: ((TimeInterval) -> Void)?
  ) -> NSViewController {
    return NSHostingController(
      rootView: SNTNetworkMountMessageWindowView(
        window: window,
        event: event,
        configBundle: configBundle,
        uiStateCallback: uiStateCallback
      ).fixedSize()
    )
  }
}

func copyDetailsToClipboard(e: SNTStoredNetworkMountEvent?) {
  var s = "Santa blocked mounting a network share."

  s += "\nNetwork Share  : \(e?.mountFromName ?? "<unknown>")"
  s += "\nDestination    : \(e?.mountOnName ?? "<unknown>")"
  s += "\nFS Type        : \(e?.fsType ?? "<unknown>")"
  s += "\nProcess:"
  s += "\n  Path         : \(e?.process?.filePath ?? "<unknown>")"
  s += "\n  SHA-256      : \(e?.process?.fileSHA256 ?? "<unknown>")"
  if let cdhash = e?.process?.cdhash {
    s += "\n  CDHash       : \(cdhash)"
  }
  if let signingID = e?.process?.signingID {
    s += "\n  SigningID    : \(signingID)"
  }
  s += "\n  User         : \(e?.process?.executingUser ?? "<unknown>")"
  s += " (ID: \(e?.process?.executingUserID?.stringValue ?? "<unknown>"))"  // Continuation, no newline

  let pasteboard = NSPasteboard.general
  pasteboard.clearContents()
  pasteboard.setString(s, forType: .string)
}

struct MoreDetailsView: View {
  let e: SNTStoredNetworkMountEvent?

  @Environment(\.presentationMode) var presentationMode

  func addLabel(@ViewBuilder closure: () -> some View) -> some View {
    HStack(spacing: 5.0) {
      VStack(alignment: .leading, spacing: 2.0) {
        closure()
      }
      Spacer()
    }.frame(width: MAX_OUTER_VIEW_WIDTH - 60).fixedSize()
  }

  var body: some View {
    HStack(spacing: 20.0) {
      VStack(spacing: 20.0) {
        Spacer()
        addLabel {
          Text("Network Share").bold().font(Font.system(size: 12.0))
          Text(e?.mountFromName ?? "unknown").font(Font.system(size: 12.0).monospaced()).textSelection(.enabled)
        }

        Divider()

        addLabel {
          Text("Destination").bold().font(Font.system(size: 12.0))
          Text(e?.mountOnName ?? "unknown").font(Font.system(size: 12.0).monospaced()).textSelection(.enabled)
        }

        Divider()

        addLabel {
          Text("FS Type").bold().font(Font.system(size: 12.0))
          Text(e?.fsType ?? "unknown").font(Font.system(size: 12.0).monospaced()).textSelection(.enabled)
        }

        Divider()

        if let signingID = e?.process?.signingID {
          addLabel {
            Text("Signing ID").bold().font(Font.system(size: 12.0))
            Text(signingID).font(Font.system(size: 12.0).monospaced()).textSelection(.enabled)
          }
          Divider()
        }

        if let cdHash = e?.process?.cdhash {
          addLabel {
            Text("CDHash").bold().font(Font.system(size: 12.0))
            Text(cdHash).font(Font.system(size: 12.0).monospaced()).textSelection(.enabled)
          }
          Divider()
        }

        if let fileSHA256 = e?.process?.fileSHA256 {
          addLabel {
            Text("SHA-256").bold().font(Font.system(size: 12.0))
            // Fix the max width of this to 240px so that the SHA-256 splits across 2 lines evenly.
            Text(fileSHA256).font(Font.system(size: 12.0).monospaced()).frame(width: 240)
              .textSelection(.enabled)
          }
          Divider()
        }

        if let parentFilePath = e?.process?.parent?.filePath {
          addLabel {
            Text("Parent").bold().font(Font.system(size: 12.0))
            Text(
              verbatim:
                "\((parentFilePath as NSString).lastPathComponent) (\(e?.process?.parent?.pid?.stringValue ?? "unknown PID"))"
            )
            .font(
              Font.system(size: 12.0).monospaced()
            ).textSelection(.enabled)
          }
        }

        Spacer()

        HStack {
          CopyDetailsButton(action: {
            copyDetailsToClipboard(e: e)
          })

          Button(action: { presentationMode.wrappedValue.dismiss() }) {
            HStack(spacing: 2.0) {
              Text("Dismiss", comment: "Dismiss button in more details dialog").foregroundColor(.blue)
              Image(systemName: "xmark.circle").foregroundColor(.blue)
            }
          }
          .buttonStyle(ScalingButtonStyle())
          .keyboardShortcut(.escape, modifiers: .command)
          .help("⌘ Esc")
        }

        Spacer()
      }.frame(maxWidth: MAX_OUTER_VIEW_WIDTH - 20).fixedSize()
    }.frame(width: MAX_OUTER_VIEW_WIDTH - 20).fixedSize().background(Color.gray.opacity(0.2))
  }
}

struct Event: View {
  let e: SNTStoredNetworkMountEvent?
  let window: NSWindow?

  @State private var isShowingDetails = false

  var body: some View {
    HStack(spacing: 20.0) {
      VStack(alignment: .trailing, spacing: 10.0) {
        Text("Network Share").bold().font(Font.system(size: 12.0))
        Text("Destination").bold()
      }

      Divider()

      VStack(alignment: .leading, spacing: 10.0) {
        TextWithLimit(e?.mountFromName ?? "<unknown>").textSelection(.enabled)
        TextWithLimit(e?.mountOnName ?? "<unknown>").textSelection(.enabled)

      }
    }.sheet(isPresented: $isShowingDetails) {
      MoreDetailsView(e: e)
    }

    VStack(spacing: 2.0) {
      Spacer()

      HStack {
        MoreDetailsButton($isShowingDetails)

        CopyDetailsButton(action: {
          copyDetailsToClipboard(e: e)
        })
      }

      Spacer()
    }
  }
}

struct SNTNetworkMountMessageWindowView: View {
  let window: NSWindow?
  let event: SNTStoredNetworkMountEvent?
  let configBundle: SNTConfigBundle
  let uiStateCallback: ((TimeInterval) -> Void)?

  @State public var preventFutureNotifications = false
  @State public var preventFutureNotificationPeriod: TimeInterval = NotificationSilencePeriods[0]

  var body: some View {
    SNTMessageView(getBlockMessage()) {
      Event(e: event, window: window)

      if getEnableNotificationSilences() {
        SNTNotificationSilenceView(silence: $preventFutureNotifications, period: $preventFutureNotificationPeriod)
      }

      Spacer()

      HStack(spacing: 15.0) {
        DismissButton(customText: nil, silence: preventFutureNotifications, action: dismissButton)
      }

      Spacer()
    }.fixedSize()
  }

  func getBlockMessage() -> NSAttributedString {
    var customMessage: String? = nil
    configBundle.bannedNetworkMountBlockMessage { message in
      customMessage = message
    }
    return SNTBlockMessage.attributedBlockMessageForNetworkMountEvent(withCustomMessage: customMessage)
  }

  func getEnableNotificationSilences() -> Bool {
    var silencesEnabled: Bool = true
    configBundle.enableNotificationSilences { val in
      silencesEnabled = val
    }
    return silencesEnabled
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
