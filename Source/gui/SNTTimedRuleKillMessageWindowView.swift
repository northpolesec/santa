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

import santa_common_SNTRuleTimeWindow
import santa_common_SNTTimedRuleKillDetails
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
    details: SNTTimedRuleKillDetails
  ) -> NSViewController {
    return NSHostingController(
      rootView: SNTTimedRuleKillMessageWindowView(
        window: window,
        details: details
      ).fixedSize()
    )
  }
}

// The sentence, the Reason row and the copied text all render the deadline, so
// they compose it here once and cannot drift apart.
func deadlineText(_ deadline: Date) -> String {
  let tf = DateFormatter()
  tf.timeStyle = .short
  let time = tf.string(from: deadline)
  if Calendar.current.isDateInToday(deadline) { return time }
  let df = DateFormatter()
  df.dateStyle = .medium
  return String(
    format: NSLocalizedString("%@ on %@", comment: "a time of day on a date"),
    time,
    df.string(from: deadline)
  )
}

// The rule identifier is not repeated here: the Signing ID row already shows it
// for Signing ID and Team ID rules, and the CDHash row shows it for CDHash ones.
// Binary and Certificate rules show no row carrying their identifier, and
// deliberately: the path, publisher and signing rows describe what was quit
// better than a bare hash would. A type without a case here carries the deadline
// alone rather than an empty parenthetical.
func reasonText(_ details: SNTTimedRuleKillDetails) -> String {
  let ends = deadlineText(details.deadline)
  let type: String
  switch details.ruleType {
  case .signingID: type = NSLocalizedString("Signing ID", comment: "")
  case .teamID: type = NSLocalizedString("Team ID", comment: "")
  case .cdHash: type = NSLocalizedString("CDHash", comment: "")
  case .binary: type = NSLocalizedString("Binary", comment: "")
  case .certificate: type = NSLocalizedString("Certificate", comment: "")
  default:
    return String(
      format: NSLocalizedString(
        "Time based rule: window ends at %@",
        comment: "quit reason for a rule type this build cannot name"
      ),
      ends
    )
  }
  return String(
    format: NSLocalizedString("Time based rule (%@): window ends at %@", comment: "quit reason"),
    type,
    ends
  )
}

// A window with no readable form renders empty, which hides the row the same way
// a missing window does.
func timeWindowText(_ details: SNTTimedRuleKillDetails) -> String {
  return details.timeWindow?.displayString() ?? ""
}

func copyDetailsToClipboard(details: SNTTimedRuleKillDetails) {
  var s = String(
    format: NSLocalizedString(
      "Santa will quit %@ at %@",
      comment: "Lead line of the copied warning details"
    ),
    details.application,
    deadlineText(details.deadline)
  )
  s += "\nReason     : \(reasonText(details))"

  let timeWindow = timeWindowText(details)
  if !timeWindow.isEmpty {
    s += "\nTime Window: \(timeWindow)"
  }
  if let publisher = details.publisher, !publisher.isEmpty {
    s += "\nPublisher  : \(publisher)"
  }
  if let user = details.user, !user.isEmpty {
    s += "\nUser       : \(user)"
  }
  if let path = details.path, !path.isEmpty {
    s += "\nPath       : \(path)"
  }
  if let signingID = details.signingID, !signingID.isEmpty {
    s += "\nSigningID  : \(signingID)"
  }
  if let cdhash = details.cdhash, !cdhash.isEmpty {
    s += "\nCDHash     : \(cdhash)"
  }
  if let parentName = details.parentName, !parentName.isEmpty, let ppid = details.ppid {
    s += "\nParent     : \(parentName) (\(ppid.stringValue))"
  }
  s += "\n"

  let pasteboard = NSPasteboard.general
  pasteboard.clearContents()
  pasteboard.setString(s, forType: .string)
}

struct SNTTimedRuleKillMoreDetailsView: View {
  let details: SNTTimedRuleKillDetails

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
          Text("Reason").bold().font(Font.system(size: 12.0))
          Text(reasonText(details)).textSelection(.enabled)
        }

        // Each row after the first owns its leading Divider, so a row missing in
        // the degraded dialog takes its divider with it.
        if let path = details.path, !path.isEmpty {
          Divider()
          addLabel {
            Text("Path").bold().font(Font.system(size: 12.0))
            Text(verbatim: path).textSelection(.enabled)
          }
        }

        if let signingID = details.signingID, !signingID.isEmpty {
          Divider()
          addLabel {
            Text("Signing ID").bold().font(Font.system(size: 12.0))
            Text(signingID).font(Font.system(size: 12.0).monospaced()).textSelection(.enabled)
          }
        }

        if let cdhash = details.cdhash, !cdhash.isEmpty {
          Divider()
          addLabel {
            Text("CDHash").bold().font(Font.system(size: 12.0))
            Text(cdhash).font(Font.system(size: 12.0).monospaced()).textSelection(.enabled)
          }
        }

        if let parentName = details.parentName, !parentName.isEmpty, let ppid = details.ppid {
          Divider()
          addLabel {
            Text("Parent").bold().font(Font.system(size: 12.0))
            Text(verbatim: "\(parentName) (\(ppid.stringValue))")
              .textSelection(.enabled)
          }
        }

        Spacer()

        HStack {
          CopyDetailsButton(action: {
            copyDetailsToClipboard(details: details)
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
          .keyboardShortcut(.cancelAction)
          .help("Esc")
        }

        Spacer()
      }.frame(maxWidth: MAX_OUTER_VIEW_WIDTH - 20).padding(20.0)
    }.frame(width: MAX_OUTER_VIEW_WIDTH - 20).fixedSize().background(Color.gray.opacity(0.2))
  }
}

struct SNTTimedRuleKillEventView: View {
  let details: SNTTimedRuleKillDetails

  @State private var isShowingDetails = false

  var body: some View {
    let timeWindow = timeWindowText(details)

    HStack(spacing: 20.0) {
      VStack(alignment: .trailing, spacing: 10.0) {
        Text("Application").bold().font(Font.system(size: 12.0))

        if details.publisher?.isEmpty == false {
          Text("Publisher").bold().font(Font.system(size: 12.0))
        }

        if details.user?.isEmpty == false {
          Text("User").bold().font(Font.system(size: 12.0))
        }

        if !timeWindow.isEmpty {
          Text("Time Window").bold().font(Font.system(size: 12.0))
        }
      }

      Divider()

      VStack(alignment: .leading, spacing: 10.0) {
        TextWithLimit(details.application)

        if let publisher = details.publisher, !publisher.isEmpty {
          TextWithLimit(publisher)
        }

        if let user = details.user, !user.isEmpty {
          TextWithLimit(user)
        }

        if !timeWindow.isEmpty {
          TextWithLimit(timeWindow)
        }
      }.textSelection(.enabled)
    }.sheet(isPresented: $isShowingDetails) {
      SNTTimedRuleKillMoreDetailsView(details: details)
    }

    VStack(spacing: 2.0) {
      Spacer()

      HStack {
        MoreDetailsButton($isShowingDetails)

        CopyDetailsButton(action: {
          copyDetailsToClipboard(details: details)
        })
      }

      Spacer()
    }
  }
}

struct SNTTimedRuleKillMessageWindowView: View {
  let window: NSWindow?
  let details: SNTTimedRuleKillDetails

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
        .help(details.application)

      SNTTimedRuleKillEventView(details: details)

      HStack(spacing: 15.0) {
        DismissButton(customText: nil, silence: false, action: dismissButton)
      }
    }.fixedSize()
  }

  // The name is whatever the running process calls itself, so it is bounded the
  // same way TextWithLimit bounds one: middle elided, so both ends stay readable.
  func boundedApplicationName() -> String {
    let application = details.application
    guard application.count > maxApplicationNameLength else { return application }
    let half = maxApplicationNameLength / 2
    return "\(application.prefix(half))…\(application.suffix(half))"
  }

  func warningMessage() -> String {
    return String(
      format: NSLocalizedString(
        "\"%@\" will quit at %@.",
        comment: "Window message warning that an app will be quit at a time"
      ),
      boundedApplicationName(),
      deadlineText(details.deadline)
    )
  }

  func dismissButton() {
    window?.close()
  }
}
