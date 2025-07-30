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
import santa_common_SNTConfigState
import santa_common_SNTStoredFileAccessEvent
import santa_gui_SNTMessageView

@objc public class SNTFileAccessMessageWindowViewFactory: NSObject {
  @objc public static func createWith(
    window: NSWindow,
    event: SNTStoredFileAccessEvent,
    customMessage: NSString?,
    customURL: NSString?,
    customText: NSString?,
    configState: SNTConfigState,
    uiStateCallback: ((TimeInterval) -> Void)?
  ) -> NSViewController {
    return NSHostingController(
      rootView: SNTFileAccessMessageWindowView(
        window: window,
        event: event,
        customMessage: customMessage,
        customURL: customURL as String?,
        customText: customText as String?,
        configState: configState,
        uiStateCallback: uiStateCallback
      )
      .frame(minWidth: MAX_OUTER_VIEW_WIDTH, minHeight: MAX_OUTER_VIEW_HEIGHT)
      .fixedSize()
    )
  }
}

struct MoreDetailsView: View {
  let e: SNTStoredFileAccessEvent

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
          Text("Accessed Path").bold().font(Font.system(size: 12.0))
          Text(e.accessedPath ?? "").font(Font.system(size: 12.0).monospaced()).textSelection(.enabled)
        }

        Divider()

        addLabel {
          Text("Binary Path").bold().font(Font.system(size: 12.0))
          Text(e.process?.filePath ?? "").font(Font.system(size: 12.0).monospaced()).textSelection(.enabled)
        }

        Divider()

        if let signingID = e.process?.signingID {
          addLabel {
            Text("Signing ID").bold().font(Font.system(size: 12.0))
            Text(signingID).font(Font.system(size: 12.0).monospaced()).textSelection(.enabled)
          }
          Divider()
        }

        if let cdHash = e.process?.cdhash {
          addLabel {
            Text("CDHash").bold().font(Font.system(size: 12.0))
            Text(cdHash).font(Font.system(size: 12.0).monospaced()).textSelection(.enabled)
          }
          Divider()
        }

        addLabel {
          Text("SHA-256").bold().font(Font.system(size: 12.0))
          // Fix the max width of this to 240px so that the SHA-256 splits across 2 lines evenly.
          Text(e.process?.fileSHA256 ?? "").font(Font.system(size: 12.0).monospaced()).frame(width: 240)
            .textSelection(.enabled)
        }

        Divider()

        addLabel {
          Text("Parent").bold().font(Font.system(size: 12.0))
          Text(
            verbatim:
              "\((e.process?.parent?.filePath as NSString?)?.lastPathComponent ?? "") (\(e.process?.parent?.pid?.stringValue ?? ""))"
          )
          .font(
            Font.system(size: 12.0).monospaced()
          ).textSelection(.enabled)
        }

        Spacer()

        Button(action: { presentationMode.wrappedValue.dismiss() }) {
          HStack(spacing: 2.0) {
            Text("Dismiss", comment: "Dismiss button in more details dialog").foregroundColor(.blue)
            Image(systemName: "xmark.circle").foregroundColor(.blue)
          }
        }
        .buttonStyle(ScalingButtonStyle())
        .keyboardShortcut(.escape, modifiers: .command)
        .help("⌘ Esc")

        Spacer()
      }.frame(maxWidth: MAX_OUTER_VIEW_WIDTH - 20).fixedSize()
    }.frame(width: MAX_OUTER_VIEW_WIDTH - 20).fixedSize().background(Color.gray.opacity(0.2))
  }
}

struct Event: View {
  let e: SNTStoredFileAccessEvent
  let window: NSWindow?

  @State private var isShowingDetails = false

  var body: some View {
    HStack(spacing: 20.0) {
      VStack(alignment: .trailing, spacing: 10.0) {
        Text("Path Accessed").bold().font(Font.system(size: 12.0))
        Text("Application").bold()
        Text("User").bold()
        Text("Rule Name").bold()
        Text("Rule Version").bold()
      }

      Divider()

      VStack(alignment: .leading, spacing: 10.0) {
        TextWithLimit(e.accessedPath ?? "<unknown>").textSelection(.enabled)
        TextWithLimit((e.process?.filePath as NSString?)?.lastPathComponent ?? "").textSelection(.enabled)
        TextWithLimit(e.process?.executingUser ?? "<unknown>").textSelection(.enabled)
        TextWithLimit(e.ruleName ?? "<unknown>").textSelection(.enabled)
        TextWithLimit(e.ruleVersion ?? "<unknown>").textSelection(.enabled)

      }
    }.sheet(isPresented: $isShowingDetails) {
      MoreDetailsView(e: e)
    }

    VStack(spacing: 2.0) {
      Spacer()
      MoreDetailsButton($isShowingDetails)
      Spacer()
    }
  }
}

struct SNTFileAccessMessageWindowView: View {
  let window: NSWindow?
  let event: SNTStoredFileAccessEvent?
  let customMessage: NSString?
  let customURL: String?
  let customText: String?
  let configState: SNTConfigState
  let uiStateCallback: ((TimeInterval) -> Void)?

  @Environment(\.openURL) var openURL

  @State public var preventFutureNotifications = false
  @State public var preventFutureNotificationPeriod: TimeInterval = NotificationSilencePeriods[0]

  var body: some View {
    SNTMessageView(
      SNTBlockMessage.attributedBlockMessage(for: event, customMessage: customMessage as String?)
    ) {
      Event(e: event!, window: window)

      VStack(spacing: 15.0) {
        if configState.enableNotificationSilences {
          SNTNotificationSilenceView(silence: $preventFutureNotifications, period: $preventFutureNotificationPeriod)
        }

        HStack(spacing: 15.0) {
          if customURL != nil {
            OpenEventButton(customText: customText, action: openButton)
          }
          DismissButton(silence: preventFutureNotifications, action: dismissButton)
        }
        Spacer()
      }
    }
    .fixedSize()
  }

  func openButton() {
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
