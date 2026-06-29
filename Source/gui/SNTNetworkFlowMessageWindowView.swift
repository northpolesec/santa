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

import santa_common_SNTBlockMessage
import santa_common_SNTConfigBundle
import santa_common_SNTStoredNetworkFlowEvent
import santa_gui_SNTMessageView

@objc public class SNTNetworkFlowMessageWindowViewFactory: NSObject {
  @objc public static func createWith(
    window: NSWindow,
    event: SNTStoredNetworkFlowEvent,
    configBundle: SNTConfigBundle,
    silenceable: Bool,
    uiStateCallback: ((TimeInterval) -> Void)?
  ) -> NSViewController {
    return NSHostingController(
      rootView: SNTNetworkFlowMessageWindowView(
        window: window,
        event: event,
        configBundle: configBundle,
        silenceable: silenceable,
        uiStateCallback: uiStateCallback
      ).fixedSize()
    )
  }
}

// Human-readable description of the policy decision.
func networkFlowDecisionDescription(_ decision: SNTNetworkFlowDecision) -> String {
  switch decision {
  case .allow: return "Allow"
  case .block: return "Block"
  case .audit: return "Audit"
  default: return "Unspecified"
  }
}

// Human-readable description of how the matching rule's remote matcher matched the flow.
func networkFlowTierDescription(_ tier: SNTNetworkFlowTier) -> String {
  switch tier {
  case .exactIP: return "Exact IP"
  case .CIDR: return "CIDR"
  case .hostname: return "Hostname"
  case .domain: return "Domain"
  case .anyRemote: return "Any remote"
  default: return "Unspecified"
  }
}

// Human-readable flow direction.
func networkFlowDirectionDescription(_ direction: SNTNetworkFlowDirection) -> String {
  switch direction {
  case .outgoing: return "Outgoing"
  case .incoming: return "Incoming"
  case .unspecified: return "Unspecified"
  default: return "Any"
  }
}

// Human-readable socket address family (values match Darwin AF_INET / AF_INET6).
func networkFlowSocketFamilyDescription(_ family: SNTNetworkFlowSocketFamily) -> String {
  switch family.rawValue {
  case 2: return "IPv4"
  case 30: return "IPv6"
  default: return "Unspecified"
  }
}

// Human-readable transport protocol from its IANA number.
func networkFlowProtocolDescription(_ proto: Int32) -> String {
  switch proto {
  case 6: return "TCP"
  case 17: return "UDP"
  default: return "\(proto)"
  }
}

func networkFlowRemote(_ e: SNTStoredNetworkFlowEvent?) -> String {
  return "\(e?.remoteAddress ?? "<unknown>"):\(e?.remotePort ?? 0)"
}

// Build a plain-text dump of the event for an admin to paste alongside other telemetry.
func copyNetworkFlowDetailsToClipboard(e: SNTStoredNetworkFlowEvent?) {
  var s =
    "Santa blocked \((e?.process?.filePath as NSString?)?.lastPathComponent ?? "<unknown>") from reaching a network destination"
  s += "\nProcess:"
  s += "\n  Path           : \(e?.process?.filePath ?? "<unknown>")"
  s += "\n  SHA-256        : \(e?.process?.fileSHA256 ?? "<unknown>")"
  if let cdhash = e?.process?.cdhash { s += "\n  CDHash         : \(cdhash)" }
  if let signingID = e?.process?.signingID { s += "\n  Signing ID     : \(signingID)" }
  if let teamID = e?.process?.teamID { s += "\n  Team ID        : \(teamID)" }
  if let pid = e?.process?.pid { s += "\n  PID            : \(pid.stringValue)" }
  s += "\n  User           : \(e?.process?.executingUser ?? "<unknown>")"
  if let parent = e?.process?.parent {
    s +=
      "\n  Parent         : \((parent.filePath as NSString?)?.lastPathComponent ?? "<unknown>") (\(parent.pid?.stringValue ?? "unknown PID"))"
  }
  s += "\nConnection:"
  s += "\n  Direction      : \(networkFlowDirectionDescription(e?.direction ?? .unspecified))"
  s += "\n  Protocol       : \(networkFlowProtocolDescription(e?.`protocol` ?? 0))"
  s += "\n  Remote         : \(networkFlowRemote(e))"
  if let host = e?.hostname, !host.isEmpty { s += "\n  Hostname       : \(host)" }
  if let local = e?.localAddress, !local.isEmpty {
    s += "\n  Local          : \(local):\(e?.localPort ?? 0)"
  }
  s += "\n  Address Family : \(networkFlowSocketFamilyDescription(e?.socketFamily ?? .unspecified))"
  if let flowTime = e?.flowTime { s += "\n  Time           : \(flowTime)" }
  s += "\nRule:"
  s += "\n  Decision       : \(networkFlowDecisionDescription(e?.decision ?? .unspecified))"
  s += "\n  Match          : \(networkFlowTierDescription(e?.decisionTier ?? .unspecified))"
  if let ruleName = e?.ruleName, !ruleName.isEmpty { s += "\n  Rule Name      : \(ruleName)" }
  s += "\n"

  let pasteboard = NSPasteboard.general
  pasteboard.clearContents()
  pasteboard.setString(s, forType: .string)
}

// Fine-grained detail pane, surfaced via "More Details". Aimed at an admin correlating this
// block with other telemetry (process identity + the full connection 5-tuple + rule context).
struct NetworkFlowMoreDetailsView: View {
  let e: SNTStoredNetworkFlowEvent?

  @Environment(\.presentationMode) var presentationMode

  func row(_ label: String, _ value: String) -> some View {
    HStack(alignment: .top, spacing: 8.0) {
      Text(label).bold().font(Font.system(size: 12.0)).frame(width: 110.0, alignment: .leading)
      Text(value).font(Font.system(size: 12.0).monospaced()).frame(
        maxWidth: .infinity,
        alignment: .leading
      ).textSelection(.enabled)
    }
    .padding(.leading, 12.0)
  }

  func header(_ title: String) -> some View {
    Text(title).bold().font(Font.system(size: 13.0)).frame(maxWidth: .infinity, alignment: .leading)
      .padding(.top, 6.0)
  }

  var body: some View {
    VStack(spacing: 12.0) {
      VStack(alignment: .leading, spacing: 6.0) {
        header("Process")
        if let path = e?.process?.filePath { row("Binary Path", path) }
        if let sha256 = e?.process?.fileSHA256 { row("SHA-256", sha256) }
        if let cdhash = e?.process?.cdhash { row("CDHash", cdhash) }
        if let signingID = e?.process?.signingID { row("Signing ID", signingID) }
        if let teamID = e?.process?.teamID { row("Team ID", teamID) }
        if let pid = e?.process?.pid { row("PID", pid.stringValue) }
        if let user = e?.process?.executingUser { row("User", user) }
        if let parent = e?.process?.parent {
          row(
            "Parent",
            "\((parent.filePath as NSString?)?.lastPathComponent ?? "<unknown>") (\(parent.pid?.stringValue ?? "unknown PID"))"
          )
        }

        header("Connection")
        row("Direction", networkFlowDirectionDescription(e?.direction ?? .unspecified))
        row("Protocol", networkFlowProtocolDescription(e?.`protocol` ?? 0))
        row("Remote", networkFlowRemote(e))
        if let host = e?.hostname, !host.isEmpty { row("Hostname", host) }
        if let localAddress = e?.localAddress, !localAddress.isEmpty {
          row("Local", "\(localAddress):\(e?.localPort ?? 0)")
        }
        row("Address Family", networkFlowSocketFamilyDescription(e?.socketFamily ?? .unspecified))
        if let flowTime = e?.flowTime { row("Time", "\(flowTime)") }

        header("Rule")
        row("Decision", networkFlowDecisionDescription(e?.decision ?? .unspecified))
        row("Match", networkFlowTierDescription(e?.decisionTier ?? .unspecified))
        if let ruleName = e?.ruleName, !ruleName.isEmpty { row("Rule Name", ruleName) }
      }

      HStack {
        CopyDetailsButton(action: { copyNetworkFlowDetailsToClipboard(e: e) })

        Button(action: { presentationMode.wrappedValue.dismiss() }) {
          HStack(spacing: 2.0) {
            Text("Dismiss", comment: "Dismiss button in more details dialog").foregroundColor(.blue)
            Image(systemName: "xmark.circle").foregroundColor(.blue)
          }
        }
        .buttonStyle(ScalingButtonStyle())
        .keyboardShortcut(.cancelAction)
        .help("Esc")
      }
    }
    .padding(20.0)
    .frame(width: MAX_OUTER_VIEW_WIDTH - 20)
    .fixedSize(horizontal: false, vertical: true)
    .background(Color.gray.opacity(0.2))
  }
}

struct NetworkFlowDetail: View {
  let e: SNTStoredNetworkFlowEvent?

  @State private var isShowingDetails = false

  var destinationText: String {
    let host = e?.hostname ?? ""
    let dest = host.isEmpty ? (e?.remoteAddress ?? "<unknown>") : host
    return "\(dest):\(e?.remotePort ?? 0)"
  }

  var body: some View {
    HStack(spacing: 20.0) {
      VStack(alignment: .trailing, spacing: 10.0) {
        Text("Application").bold()
        Text("Destination").bold()
      }

      Divider()

      VStack(alignment: .leading, spacing: 10.0) {
        TextWithLimit((e?.process?.filePath as NSString?)?.lastPathComponent ?? "<unknown>")
          .textSelection(.enabled)
        TextWithLimit(destinationText).textSelection(.enabled)
      }
    }
    .sheet(isPresented: $isShowingDetails) {
      NetworkFlowMoreDetailsView(e: e)
    }

    VStack(spacing: 2.0) {
      Spacer()

      HStack {
        MoreDetailsButton($isShowingDetails)
        CopyDetailsButton(action: { copyNetworkFlowDetailsToClipboard(e: e) })
      }

      Spacer()
    }
  }
}

struct SNTNetworkFlowMessageWindowView: View {
  let window: NSWindow?
  let event: SNTStoredNetworkFlowEvent?
  let configBundle: SNTConfigBundle
  let silenceable: Bool
  let uiStateCallback: ((TimeInterval) -> Void)?

  @State public var preventFutureNotifications = false
  @State public var preventFutureNotificationPeriod: TimeInterval = NotificationSilencePeriods[0]

  var body: some View {
    SNTMessageView(
      SNTBlockMessage.attributedBlockMessageForNetworkFlowEvent(withCustomMessage: nil)
    ) {
      NetworkFlowDetail(e: event)

      if configBundle.notificationSilencesEnabled() && silenceable {
        SNTNotificationSilenceView(
          silence: $preventFutureNotifications,
          period: $preventFutureNotificationPeriod
        )
      }

      HStack {
        DismissButton(silence: preventFutureNotifications, action: dismissButton)
      }
    }
    .fixedSize()
  }

  func dismissButton() {
    if let callback = uiStateCallback {
      callback(preventFutureNotifications ? preventFutureNotificationPeriod : 0)
    }
    window?.close()
  }
}
