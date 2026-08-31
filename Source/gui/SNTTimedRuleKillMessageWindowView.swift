/// Copyright 2026 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     http://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

import SwiftUI

import santa_gui_SNTMessageView

// TextWithLimit's bound (SNTMessageView.swift), which is what every other view
// applies to a process-derived string. Applied to the name rather than to the
// composed sentence so the localized format keeps both of its arguments, which
// is what lets ja reorder them.
private let maxApplicationNameLength = 50

// The number of lines the sentence may occupy. The block-message slot bounds
// long free text at 15 lines; this view holds one sentence, so a name that
// survives truncation with newlines in it still cannot grow the window.
private let maxMessageLines = 3

@objc public class SNTTimedRuleKillMessageWindowViewFactory: NSObject {
  @objc public static func createWith(
    window: NSWindow,
    application: String,
    deadline: Date
  ) -> NSViewController {
    return NSHostingController(
      rootView: SNTTimedRuleKillMessageWindowView(
        window: window,
        application: application,
        deadline: deadline
      ).fixedSize()
    )
  }
}

struct SNTTimedRuleKillMessageWindowView: View {
  let window: NSWindow?
  let application: String
  let deadline: Date

  var body: some View {
    // The warning is the whole message, so it takes the content slot rather than
    // SNTMessageView's block-message slot: the application name is read from a
    // running process, and the block-message slot renders HTML.
    SNTMessageView {
      Text(warningMessage())
        .multilineTextAlignment(.center)
        .lineLimit(maxMessageLines)
        .fixedSize(horizontal: false, vertical: true)
        // The other half of what TextWithLimit does with a bounded string: a
        // name the bound elided is still recoverable by hovering it.
        .help(application)

      Spacer()

      HStack(spacing: 15.0) {
        DismissButton(customText: nil, silence: false, action: dismissButton)
      }

      Spacer()
    }.fixedSize()
  }

  // The name is whatever the running process calls itself, so it is bounded the
  // same way TextWithLimit bounds one: middle elided, so both ends stay readable.
  func boundedApplicationName() -> String {
    guard application.count > maxApplicationNameLength else { return application }
    let half = maxApplicationNameLength / 2
    return "\(application.prefix(half))…\(application.suffix(half))"
  }

  func warningMessage() -> String {
    // Time of day only. A deadline is always the end of the window the process
    // was launched in, so the date would say nothing the user needs.
    let formatter = DateFormatter()
    formatter.timeStyle = .short
    formatter.dateStyle = .none

    return String(
      format: NSLocalizedString(
        "\"%@\" will quit at %@.",
        comment: "Window message warning that an app will be quit at a time"
      ),
      boundedApplicationName(),
      formatter.string(from: deadline)
    )
  }

  func dismissButton() {
    window?.close()
  }
}
