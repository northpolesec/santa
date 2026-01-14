import SwiftUI

import santa_common_SNTConfigState
import santa_common_SNTConfigurator
import santa_common_SNTCommonEnums
import santa_common_SNTDeviceEvent
import santa_common_SNTStoredExecutionEvent
import Source_gui_SNTDeviceMessageWindowView
import Source_gui_SNTBinaryMessageWindowView
import Source_gui_SNTAboutWindowView

func ShowWindow(_ vc: NSViewController, _ window: NSWindow, appearance: AppearanceMode = .system) {
  window.contentRect(forFrameRect: NSMakeRect(0, 0, 0, 0))
  window.styleMask = [.closable, .resizable, .titled]
  window.backingType = .buffered
  window.titlebarAppearsTransparent = true
  window.isMovableByWindowBackground = true
  window.standardWindowButton(.zoomButton)?.isHidden = true
  window.standardWindowButton(.closeButton)?.isHidden = true
  window.standardWindowButton(.miniaturizeButton)?.isHidden = true

  switch appearance {
  case .light:
    window.appearance = NSAppearance(named: .aqua)
  case .dark:
    window.appearance = NSAppearance(named: .darkAqua)
  case .system:
    window.appearance = nil
  }

  window.contentViewController = vc
  window.makeKeyAndOrderFront(nil)
  window.setFrame(window.frame, display: true)
  window.center()
}

class SNTDebugStoredEvent: SNTStoredExecutionEvent {
  let staticPublisher: String

  override var publisherInfo: String {
    get {
      return self.staticPublisher
    }
  }

  init(staticPublisher: String) {
    self.staticPublisher = staticPublisher
    super.init()
  }

  required init(coder: NSCoder) {
    self.staticPublisher = ""
    super.init(coder: coder)!
  }
}

enum SpecialDates {
  case Apr1
  case May4
  case Oct31
  case Nov25
}

enum AppearanceMode {
  case system
  case light
  case dark
}

struct BinaryView: View {
  @State var application: String = "Bad Malware"
  @State var publisher: String = "Developer ID: Cozy Bear (X4P54F4992)"
  @State var sha256: String = "60055b1f6fb276bfacf61f91505a72201987f20ad8b6867cce3058f4c0f0f5e5"
  @State var cdhash: String = "e38e71023d09c2e8e78a0e382669d1338ee8876a"
  @State var teamID: String = "9X9633G7QW"
  @State var path: String = "/Applications/Malware.app/Contents/MacOS"
  @State var parent: String = "launchd"

  @State var unknownBlockMessage: String = ""
  @State var eventDetailURL: String = "http://sync-server-hostname/blockables/%bundle_or_file_identifier%"
  @State var dateOverride: SpecialDates = .Nov25
  @State var clientModeOverride: SNTClientMode = .lockdown
  @State var allowNotificationSilence: Bool = true
  @State var brandingCompanyName: String = ""
  @State var brandingCompanyLogo: String = ""
  @State var brandingCompanyLogoDark: String = ""
  @State var appearanceMode: AppearanceMode = .system

  @State var customMsg: String = ""
  @State var customURL: String = ""

  var body: some View {
    VStack(spacing: 15.0) {
      GroupBox(label: Label("Event Properties", systemImage: "")) {
        Form {
          TextField(text: $application, label: { Text(verbatim: "Application") })
          TextField(text: $publisher, label: { Text(verbatim: "Publisher") })
          TextField(text: $sha256, label: { Text(verbatim: "SHA-256") })
          TextField(text: $cdhash, label: { Text(verbatim: "CDHash") })
          TextField(text: $teamID, label: { Text(verbatim: "TeamID") })
          TextField(text: $path, label: { Text(verbatim: "Path") })
          TextField(text: $parent, label: { Text(verbatim: "Parent") })
        }
      }

      GroupBox(label: Label("Config Overrides", systemImage: "")) {
        Form {
          HStack {
            TextField(text: $unknownBlockMessage, label: { Text(verbatim: "Banned Block Message") }).frame(width: 550.0)
            Button(action: {
              unknownBlockMessage =
                "<img src='https://static.wikia.nocookie.net/villains/images/8/8a/Robot_Santa.png/revision/latest?cb=20200520230856' /><br /><br />Isn't Santa fun?"
            }) {
              Text(verbatim: "Populate (With Image)").font(Font.subheadline)
            }
            Button(action: { unknownBlockMessage = "You may not run this thing" }) {
              Text(verbatim: "Populate (1-line)").font(Font.subheadline)
            }
            Button(action: {
              unknownBlockMessage =
                "That the choice for mankind lay between freedom and happiness, and that, for the great bulk of mankind, happiness was better. All work and no play makes Jack a dull boy. Draw your chair up and hand me my violin, for the only problem we have still to solve is how to while away these bleak autumnal evenings."
            }) {
              Text(verbatim: "Populate (multiline)").font(Font.subheadline)
            }
            Button(action: { unknownBlockMessage = "" }) { Text("Clear").font(Font.subheadline) }
          }

          HStack {
            TextField(text: $eventDetailURL, label: { Text(verbatim: "Event Detail URL") })
            Button(action: { eventDetailURL = "http://sync-server-hostname/blockables/%bundle_or_file_identifier%" }) {
              Text("Populate").font(Font.subheadline)
            }
            Button(action: { eventDetailURL = "" }) { Text(verbatim: "Clear").font(Font.subheadline) }
          }
          HStack {
            Picker(selection: $dateOverride, label: Text(verbatim: "Date")) {
              Text(verbatim: "Nov 25").tag(SpecialDates.Nov25)
              Text(verbatim: "Apr 1").tag(SpecialDates.Apr1)
              Text(verbatim: "May 4").tag(SpecialDates.May4)
              Text(verbatim: "Oct 31").tag(SpecialDates.Oct31)
            }.pickerStyle(.segmented)
          }
          HStack {
            Picker(selection: $clientModeOverride, label: Text(verbatim: "Client Mode")) {
              Text(verbatim: "Monitor").tag(SNTClientMode.monitor)
              Text(verbatim: "Lockdown").tag(SNTClientMode.lockdown)
              Text(verbatim: "Standalone").tag(SNTClientMode.standalone)
            }.pickerStyle(.segmented)
          }
          HStack {
            TextField(text: $brandingCompanyName, label: { Text(verbatim: "Branding: Company Name") }).frame(
              width: 750.0
            )
            Button(action: { brandingCompanyName = "North Pole Security, Inc." }) {
              Text(verbatim: "Populate").font(Font.subheadline)
            }
            Button(action: { brandingCompanyName = "" }) { Text("Clear").font(Font.subheadline) }
          }
          HStack {
            TextField(text: $brandingCompanyLogo, label: { Text(verbatim: "Branding: Company Logo") }).frame(
              width: 750.0
            )
            Button(action: {
              brandingCompanyLogo =
                "data:image/png;base64,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"
            }) {
              Text(verbatim: "Populate").font(Font.subheadline)
            }
            Button(action: { brandingCompanyLogo = "" }) { Text("Clear").font(Font.subheadline) }
          }
          HStack {
            TextField(text: $brandingCompanyLogoDark, label: { Text(verbatim: "Branding: Company Logo Dark") }).frame(
              width: 750.0
            )
            Button(action: {
              brandingCompanyLogoDark =
                "data:image/svg;base64,PHN2ZyB3aWR0aD0iMzM1IiBoZWlnaHQ9IjcxIiB2aWV3Qm94PSIwIDAgMzM1IDcxIiBmaWxsPSJub25lIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPgo8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTQ5LjY0NTggNjcuMjkxM0M0OS42NDU4IDY3LjI5MTMgNDkuNzEyIDY3LjI5MTMgNDkuNzQ4NCA2Ny4yODE0QzQ5LjcxNTMgNjcuMjgxNCA0OS42ODIyIDY3LjI4MTQgNDkuNjQ1OCA2Ny4yOTEzWiIgZmlsbD0id2hpdGUiLz4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik0zMi42MTkyIDM5LjQ5MzFDMzIuNTE2NiAzOS40NzY0IDMyLjI1NTEgMzkuNDQzMSAzMi4yMjIgMzkuNDMzMUMzMi4wNTk5IDM5LjQwNjUgMzEuOTA3NiAzOS4zNzMyIDMxLjc0ODggMzkuMzQ2NkMzMS4zODQ3IDM5LjI4IDMxLjAxMDcgMzkuMjIwMSAzMC42NDY3IDM5LjE2NjhDMjkuNjUzOCAzOS4wMzAzIDI4Ljc3MzUgMzkuMDAzNiAyNy43ODM5IDM5LjE2NjhDMjYuOTc5NyAzOS4yOTMzIDI2LjQ0NjkgNDAuMjA1NiAyNi40MjY5IDQwLjk1ODFDMjYuMzc3MyA0My4xNzU2IDI3Ljc4MzkgNDQuODg2OSAyOS4xMzA5IDQ2LjQ4ODRDMzAuMTggNDcuNzMzNiAzMS4zMTUxIDQ4Ljk1MjMgMzIuNjU1NiA0OS44ODEyQzMyLjQ4NjggNTEuMzI5NiAzMi40MDA3IDUyLjc3NzkgMzIuNDAwNyA1NC4yMzYzQzMyLjQwMDcgNTYuMDQ0MiAzMi40NTA0IDU3Ljg3NTQgMzIuODQwOSA1OS42NTAxQzMzLjU5NTUgNjMuMDU5NSAzNi4xMTA4IDY2LjEwOTQgMzkuNzQ0NiA2Ni4zNDI1QzQwLjM2MzUgNjYuMzg1OCA0MS4wNDE5IDY1Ljk2NjIgNDEuMzM2NSA2NS40MjM1QzQxLjM2OTYgNjUuMzYzNiA0MS40MTI2IDY1LjMwMzcgNDEuNDQ1NyA2NS4yMzcxQzQxLjY4NCA2NS42Nzk5IDQxLjkzNTUgNjYuMTA2MSA0Mi4yMTY5IDY2LjUxNTZDNDMuMTg5OCA2Ny45NDA3IDQ0LjQxMTEgNjkuMzM1NyA0NS45MzY4IDcwLjE3MTVDNDkuMjY2MiA3MS45ODYgNTMuMTY0OCA3MC42MDc2IDU1LjcxMzIgNjguMDkwNUM1Ni4yODkgNjcuNTI3OCA1Ni44MDU0IDY2LjkwNTIgNTcuMjg4NiA2Ni4yNTkzQzU3LjMzMTYgNjYuNDEyNSA1Ny4zNzQ2IDY2LjU1OSA1Ny40MDc3IDY2LjcxMjFDNTcuNDU3MyA2Ni45MTUyIDU3LjUwMDQgNjcuMTIxNyA1Ny41MzM1IDY3LjMzNDhDNTcuNTMzNSA2Ny4zNDQ3IDU3LjU0MzQgNjcuMzg0NyA1Ny41NSA2Ny40MjhDNTcuNTUgNjcuNDk0NiA1Ny41ODMxIDY3LjcwMSA1Ny41ODMxIDY3LjcwNzdDNTcuNjQyNyA2OC4zMTM2IDU3LjgyMTQgNjguNzgzMSA1OC4zMTEyIDY5LjE2NkM1OC43MzQ4IDY5LjQ5ODkgNTkuMzg2OCA2OS43MDIgNTkuOTE5NiA2OS40OTg5QzYyLjc1OTIgNjguMzkwMiA2NS4xNjUzIDY2LjI1OTMgNjYuNTUyIDYzLjU2NTdDNjcuMzgyNyA2NC4wODUyIDY4LjM0OTEgNjQuMzkxNSA2OS4zNDg2IDY0LjQxODFDNzAuMDg2NiA2NC40MzQ3IDcxIDYzLjgyODggNzEuMTI5MSA2My4wNTNDNzEuOTU5OCA1Ny45MDU1IDcxLjgzMDcgNTIuNjYxOSA3MC42ODg5IDQ3LjU5MDRDNzIuMjU3NyA0Ni45MjQ1IDczLjUwODcgNDUuNjM5MiA3NC40OTE3IDQ0LjE3MUM3NS43Mjk0IDQyLjMxMzEgNzYuNjk1OSA0MC4yNzU0IDc3LjUzMzEgMzguMjE0NEM3Ny41NDMgMzguMTg3OCA3Ny41NDk3IDM4LjE2NDUgNzcuNTY2MiAzOC4xMzc5Qzc3LjU5OTMgMzguMDUxMyA3Ny42MzI0IDM3Ljk2OCA3Ny42Njg4IDM3Ljg4MTVDNzcuODA0NSAzNy41MzE5IDc3Ljc3OCAzNy4xNDkgNzcuNjQyMyAzNi43ODI3Qzc3LjY0MjMgMzYuNzcyNyA3Ny42MzI0IDM2Ljc2NjEgNzcuNjMyNCAzNi43NTYxQzc3LjU5OTMgMzYuNjYyOCA3Ny41NDYzIDM2LjU2OTYgNzcuNDk2NyAzNi40ODMxQzc3LjQ5NjcgMzYuNDczMSA3Ny40OTY3IDM2LjQ2NjQgNzcuNDgwMSAzNi40NTY0Qzc3LjQ3MDIgMzYuNDM5OCA3Ny40NjM2IDM2LjQyOTggNzcuNDUzNyAzNi40MjMxQzc3LjE5ODggMzYuMDIzNiA3Ni44MDE3IDM1LjcwNzMgNzYuMzc4MSAzNS42MDQxQzc2LjE4MjggMzUuNTYwOCA3NS45OTc1IDM1LjU1NDEgNzUuODE4OCAzNS41NjA4Qzc1Ljc1OTIgMzUuNTYwOCA3NS42OTMgMzUuNTYwOCA3NS42MzM0IDM1LjU3MDhINzUuNjA3Qzc1LjM4NTIgMzUuNjA0MSA3NS4xNjY4IDM1LjY3NCA3NC45NTUgMzUuNzkzOEM3NC43MzMyIDM1LjkyMDQgNzQuNTA0OSAzNi4wNDAyIDc0LjI3NjUgMzYuMTUzNEM3NC4xOTMxIDM2LjE5NTQgNzMuOTY5NSAzNi4yOTM4IDczLjkwNzggMzYuMzIwOUw3My45MDI1IDM2LjMyMzJDNzMuNDYyNCAzNi40OTMxIDczLjAyMjIgMzYuNjQ2MiA3Mi41NjU1IDM2Ljc3NjFDNzIuMTI1MyAzNi44OTU5IDcxLjY2ODYgMzYuOTg5MSA3MS4yMTg1IDM3LjA2NTdDNzEuMTkyMSAzNy4wNjU3IDcxLjE3NTUgMzcuMDY1NyA3MS4xNTkgMzcuMDc1N0M3MS4wNjYzIDM3LjA4NTcgNzAuOTYzNyAzNy4xMDIzIDcwLjg3MSAzNy4xMDlDNzAuNzI1NCAzNy4xMjU3IDcwLjU3MzIgMzcuMTI1NyA3MC40MzA5IDM3LjEzNTZDNjguNTc4MyAzNy4yMiA2Ny4xMzg3IDM2LjkxNTQgNjYuNjUwNSAzNi43NTI2QzY2LjQ5ODMgMzYuNzA5MyA2Ni4zNDYgMzYuNjY2IDY2LjE5MzggMzYuNjI2MUM2NS45NjU0IDM2LjU1OTUgNjUuNzQzNyAzNi40Nzk2IDY1LjUxNTMgMzYuMzk2M0M2NS40MzkyIDM2LjM2OTcgNjUuMzY5NyAzNi4zMzY0IDY1LjI5MzYgMzYuMzA5OEM2NS4yNzcxIDM2LjMwOTggNjUuMDIyMiAzNi4xODk5IDY0Ljk3OTIgMzYuMTczMkM2NC4xMDU1IDM1Ljc1NyA2My4yODQ3IDM1LjI1NDMgNjIuMzk0NCAzNC44NjgxQzYxLjMwMjIgMzQuMzkyIDYwLjE4MzYgMzQuMTA5IDU4Ljk3OSAzNC4xNjg5QzU3LjA3MjcgMzQuMjYyMSA1NS4xNTY1IDM0Ljg0MTUgNTMuNTc0NSAzNS45NDAyQzUyLjkyMjUgMzYuMzkzIDUyLjMxMzUgMzYuODk1OCA1MS43Nzc0IDM3LjQ3NTFDNTEuNjkxMyAzNy4zODE5IDUxLjU5ODcgMzcuMjg4NyA1MS41MTU5IDM3LjE5NTRDNTAuNDEzOCAzNi4xMDM0IDQ5LjA5OTkgMzUuMzA0MiA0Ny42NjAzIDM0Ljc2NDlDNDQuNzk3NSAzMy42ODk0IDQxLjQxNTEgMzQuMDU5IDM4Ljc5NzIgMzUuNjI3MkMzOC4xMzU2IDM2LjAyNjYgMzMuOTcwOSAzOC42NDY2IDMzLjQxMTggMzkuMTcyNEwzMi44ODA2IDM5LjUxOTdDMzIuNzk1NyAzOS41MTk3IDMyLjY4ODEgMzkuNTAzNSAzMi42MjE3IDM5LjQ5MzRMMzIuNjE5MiAzOS40OTMxWk00OS42NDU4IDY3LjI5MTNDNDkuNjQ1OCA2Ny4yOTEzIDQ5LjcxMiA2Ny4yOTEzIDQ5Ljc0ODQgNjcuMjgxNEM0OS43MTUzIDY3LjI4MTQgNDkuNjgyMiA2Ny4yODE0IDQ5LjY0NTggNjcuMjkxM1oiIGZpbGw9IndoaXRlIi8+CjxwYXRoIGQ9Ik0yOC40MDE4IDU0LjkzNjJDMjguNDE2NyA1Ni42MjA5IDI4LjUwNDEgNTguNTU1NiAyOC45MzQgNjAuNTA5NUwyOC45MzUgNjAuNTE0M0MyOS4wNzYgNjEuMTUxMSAyOS4yNjk4IDYxLjc5NjIgMjkuNTEzMSA2Mi40MzYyTDE1Ljg2MzcgNzAuMzc3NkMxNC4yOTggNzEuMjg4MSAxMi4yMjkgNzAuNjU4MiAxMS4yNjYxIDY4Ljk3ODJDMTAuMzAzMyA2Ny4yOTc5IDEwLjc5NyA2NS4xNzgyIDEyLjM2MjggNjQuMjY3M0wyOC40MDE4IDU0LjkzNjJaTTkxLjAzNDYgNjQuMjA2N0M5Mi41OTgxIDY1LjExNjYgOTMuMDkwMSA2Ny4yMzU1IDkyLjEyNzQgNjguOTE1N0M5MS4xNjQ1IDcwLjU5NTggODkuMDk2NSA3MS4yMjY2IDg3LjUzMjcgNzAuMzE3MUw3NS4xNjM1IDYzLjEyMThDNzUuNTUxMiA2MC41MTM2IDc1LjcxMzkgNTcuODgxNCA3NS42NDUgNTUuMjUzNkw5MS4wMzQ2IDY0LjIwNjdaTTUxLjc1MDUgNDEuMzU0Mkw2Mi42NzgyIDM0Ljk5NjhMNjIuNzI1MSAzNS4wMTgyQzYzLjQ5MDMgMzUuMzc4OCA2NC4yMTQ4IDM1LjgwOTQgNjQuOTc5IDM2LjE3MzVMNjUuMjkzNCAzNi4zMDkzTDY1LjUxNTEgMzYuMzk2Mkw2NS44NTQgMzYuNTE3M0M2NS45NjY0IDM2LjU1NTkgNjYuMDc5NyAzNi41OTI0IDY2LjE5MzggMzYuNjI1N0M2Ni4zNDU3IDM2LjY2NTUgNjYuNDk3OSAzNi43MDk0IDY2LjY0OTkgMzYuNzUyNkw2Ni44NzY0IDM2LjgxOUM2Ny41MDQyIDM2Ljk4NTIgNjguODA5MiAzNy4yMDkyIDcwLjQzMDEgMzcuMTM1NEw3MC44NzA2IDM3LjEwOTFDNzAuOTYzMSAzNy4xMDI0IDcxLjA2NjEgMzcuMDg1OSA3MS4xNTg3IDM3LjA3NTlDNzEuMTc1MSAzNy4wNjU5IDcxLjE5MiAzNy4wNjUxIDcxLjIxODIgMzcuMDY1MUM3MS41NTU1IDM3LjAwNzcgNzEuODk2OSAzNi45NDEzIDcyLjIzMTkgMzYuODYxTDcyLjU2NDkgMzYuNzc2MUM3My4wMjE0IDM2LjY0NjMgNzMuNDYxOCAzNi40OTI3IDczLjkwMTggMzYuMzIyOUw3My45MDc3IDM2LjMyMUM3My45Njk1IDM2LjI5MzggNzQuMTkyMiAzNi4xOTUxIDc0LjI3NTggMzYuMTUzQzc0LjUwNDEgMzYuMDM5OCA3NC43MzI5IDM1LjkyMDEgNzQuOTU0NiAzNS43OTM2Qzc1LjE2NjIgMzUuNjczOCA3NS4zODUzIDM1LjYwNDMgNzUuNjA2OSAzNS41NzFINzUuNjMzM0w3NS43MDQ2IDM1LjU2NjFMNTguNzUyNCA0NS40Mjc0TDcxLjUwNDQgNTIuODQ1NEM3MS43NDE1IDU1LjUzNDcgNzEuNzA4NiA1OC4yNDUyIDcxLjQxMjYgNjAuOTQwMUw1MS43NDk1IDQ5LjUwMTZMMzMuMDMzNyA2MC4zODg0QzMyLjk2MDMgNjAuMTQ0OCAzMi44OTUzIDU5Ljg5ODQgMzIuODQwMyA1OS42NTAxQzMyLjQ0OTggNTcuODc1NSAzMi4zOTk5IDU2LjA0MzkgMzIuMzk5OSA1NC4yMzZDMzIuMzk5OSA1My42ODYgMzIuNDExNyA1My4xMzczIDMyLjQzNiA1Mi41ODk1TDQ0Ljc0NzUgNDUuNDI4NEwzMy42NTU3IDM4Ljk3NjNDMzQuNzE0NCAzOC4xODAzIDM4LjE5NSAzNS45ODk2IDM4Ljc5NjQgMzUuNjI2NkMzOS4zMzY1IDM1LjMwMzEgMzkuOTA5NCAzNS4wMzA1IDQwLjUwMzQgMzQuODExMkw1MS43NTA1IDQxLjM1NDJaTTg2LjI4NzYgMjEuMjY0M0M5MS41MTY4IDE4LjIyMjYgOTguMzk4MSAyMC4zMTY4IDEwMS42MTQgMjUuOTI4NEMxMDQuODI5IDMxLjU0IDEwMy4xODggMzguNTkxNyA5Ny45NTk0IDQxLjYzMzVMOTUuMTExOCA0My4yODg4QzkzLjU0NjEgNDQuMTk5MyA5MS40NzcxIDQzLjU3MDMgOTAuNTE0MSA0MS44OTAzQzg5LjU1MTIgNDAuMjEgOTAuMDQ1MSAzOC4wODkzIDkxLjYxMDggMzcuMTc4NEw5NC40NTc1IDM1LjUyMjFDOTYuNTU0NiAzNC4zMDIyIDk3LjIwODYgMzEuNDkxNSA5NS45MTk0IDI5LjI0MDlDOTQuNjI5NyAyNi45OTAyIDkxLjg4NTkgMjYuMTU0NyA4OS43ODg1IDI3LjM3NDdMNzkuODg1MiAzMy4xMzQ1Qzc5LjIxODMgMzIuNTAwMyA3OC4zNTg4IDMxLjk2OTUgNzcuMzI0NyAzMS43MTc1TDc3LjI4MzcgMzEuNzA3N0w3Ny4yNDM2IDMxLjY5ODlMNzcuMDA3MyAzMS42NTExQzc2LjU0NDIgMzEuNTY4NSA3Ni4xMzYxIDMxLjU1NTkgNzUuODE4OCAzMS41NjEyVjMxLjU2MDJDNzUuNzk5OSAzMS41NjAyIDc1LjY4OTYgMzEuNTYwMiA3NS41NjY5IDMxLjU2NTFDNzUuNTM5NiAzMS41NjYyIDc1LjUwOCAzMS41Njg5IDc1LjQ3MzEgMzEuNTcxSDc1LjMwODFMNzUuMDEyMiAzMS42MTQ5Qzc0LjM0NjkgMzEuNzE0OSA3My42NTU5IDMxLjkzMjUgNzIuOTg0OCAzMi4zMTIyTDcyLjk3OCAzMi4zMTYxTDcyLjk3MjEgMzIuMzE5QzcyLjgzMTggMzIuMzk5MSA3Mi42NzQ0IDMyLjQ4MjMgNzIuNTAxNCAzMi41NjhDNzIuNDg2OSAzMi41NzQ3IDcyLjQ2OCAzMi41ODM1IDcyLjQ0NTggMzIuNTkzNEM3Mi40Mjg4IDMyLjYwMTEgNzIuNDExMyAzMi42MDg2IDcyLjM5NSAzMi42MTU5QzcyLjA3MDQgMzIuNzM5NSA3MS43NzUyIDMyLjg0MDcgNzEuNDg5NyAzMi45MjI1QzcxLjIzOCAzMi45OSA3MC45NDk1IDMzLjA1MTEgNzAuNjI0NSAzMy4xMDgxQzcwLjU4ODMgMzMuMTEzMiA3MC41NTA4IDMzLjExODMgNzAuNTEzMSAzMy4xMjQ3SDcwLjQ5OTVMNzAuNDY0MyAzMy4xMjk2QzcwLjQ1MzYgMzMuMTMgNzAuNDQxMSAzMy4xMjk4IDcwLjQyNDMgMzMuMTMwNUM3MC40MDY1IDMzLjEzMTMgNzAuMzgyIDMzLjEzMjMgNzAuMzU2OSAzMy4xMzM1QzcwLjMyNzYgMzMuMTM0OCA3MC4yOTA0IDMzLjEzNzkgNzAuMjQ4NSAzMy4xNDAzVjMzLjEzOTNDNjkuNTgzNCAzMy4xNjk2IDY4Ljk5NzEgMzMuMTI5NyA2OC41NTEyIDMzLjA3MUM2OC4wNzI5IDMzLjAwNzkgNjcuODUzNyAzMi45MzcxIDY3LjkxNTUgMzIuOTU3N0w2Ny44MzA1IDMyLjkyOTRMNjcuNzQzNiAzMi45MDVDNjcuNjIyNiAzMi44NzA2IDY3LjQ2OTYgMzIuODI4MyA2Ny4zMDgxIDMyLjc4NDhDNjcuMjI2IDMyLjc2MDcgNjcuMTIyMyAzMi43MjU2IDY2LjkwNjcgMzIuNjQ3MUM2Ni44ODYxIDMyLjYzODcgNjYuODU0NiAzMi42MjQ0IDY2LjgyMDggMzIuNjExQzY2LjgxMjggMzIuNjA3OSA2Ni44MDQ0IDMyLjYwNDQgNjYuNzk1NCAzMi42MDEzTDg2LjI4NzYgMjEuMjY0M1pNMS44ODcxNyAyNS45Mjg0QzUuMTAyODEgMjAuMzE2NyAxMS45Nzg5IDE4LjIxOTQgMTcuMjAxNiAyMS4yNTc1TDM2LjM4NTIgMzIuNDE2N0MzNS44MjkgMzIuNzYxNSAzNC44NTAyIDMzLjM3NTkgMzMuODk2IDMzLjk5MTlDMzMuMjg4MSAzNC4zODQzIDMyLjY2NCAzNC43OTI4IDMyLjE0NjkgMzUuMTQ0MkMzMi4wNzM1IDM1LjE5NDIgMzEuOTg5MyAzNS4yNTA5IDMxLjg5ODkgMzUuMzEzMkMzMS42NzAzIDM1LjI3NTYgMzEuNDQzOSAzNS4yNDA3IDMxLjIyNTEgMzUuMjA4N0wzMS4yMDg1IDM1LjIwNTdMMzEuMTkwOSAzNS4yMDM4QzI5LjkzMjYgMzUuMDMwOCAyOC42NDkzIDM0Ljk3NjEgMjcuMTg0IDM1LjIxMTZMMTMuNjk5NyAyNy4zNjc5QzExLjYwNTEgMjYuMTQ5NyA4Ljg2NDQxIDI2Ljk4NTcgNy41NzQ2NyAyOS4yMzZDNi4yODUxOCAzMS40ODY3IDYuOTM3MDggMzQuMjk2OSA5LjAzMTcgMzUuNTE1M0wxMS44NzQ1IDM3LjE2OTZDMTMuNDM4MiAzOC4wNzk0IDEzLjkzIDQwLjE5ODMgMTIuOTY3MyA0MS44Nzg2QzEyLjAwNDMgNDMuNTU4NyA5LjkzNzMxIDQ0LjE4OTUgOC4zNzM1IDQzLjI4TDUuNTI5NzUgNDEuNjI1N0MwLjMwNzQyNSAzOC41ODc2IC0xLjMyNzk5IDMxLjUzOTkgMS44ODcxNyAyNS45Mjg0WiIgZmlsbD0id2hpdGUiLz4KPHBhdGggZD0iTTMwLjEzNjcgMjcuNjQzNkMzMC4yMjQgMjcuNzg2IDMwLjMyNSAyNy45MjM3IDMwLjQzODUgMjguMDU1N0MzMC40OTUzIDI4LjEyMTggMzAuNTU1NCAyOC4xODY0IDMwLjYxOTEgMjguMjQ5QzMwLjgxIDI4LjQzNjQgMzEuMDMyIDI4LjYwNzIgMzEuMjg5MSAyOC43NTJDMzEuNzc0NyAyOS4wMjU0IDMyLjMwMiAyOS4xNjA5IDMyLjgzMDEgMjkuMjExOUMzMi4zMDE5IDI5LjE2MDkgMzEuNzc0OCAyOS4wMjU0IDMxLjI4OTEgMjguNzUyQzMwLjc3NDcgMjguNDYyMyAzMC4zOTg3IDI4LjA3MTIgMzAuMTM2NyAyNy42NDM2Wk03MC44MjYyIDE5Ljg5MjZDNzIuNTkzNiAxOS44OTI2IDcyLjU5MzggMjEuMjQ1MiA3Mi41OTM4IDIyLjM0MDhWMjQuNzg5MUM3Mi41OTM4IDI2LjE0MTYgNzIuNTkzNSAyNy4yMzczIDcwLjgyNjIgMjcuMjM3M0gzMy4zNTY0TDMzLjE4MjYgMjcuMjMzNEMzMS42NzEgMjcuMTYzNCAzMS41ODMzIDI2LjE2NjMgMzEuNTg1OSAyNS4yMDlMMzEuNTg4OSAyNC43ODkxVjIyLjM0MDhDMzEuNTg4OSAyMS4wNzI5IDMxLjU4OTIgMjAuMDMwOCAzMi4zOTM2IDE5LjkwNTNMMzIuNTY1NCAxOS44OTI2SDcwLjgyNjJaTTI5LjU4ODkgMjQuNzg5MUMyOS41ODg5IDI0Ljg4MSAyOS41ODcgMjUuMDMxNCAyOS41ODY5IDI1LjIwMzFMMjkuNTk4NiAyNS43NDYxQzI5LjU4ODcgMjUuNTY4NSAyOS41ODU5IDI1LjM3NTEgMjkuNTg1OSAyNS4yMDMxTDI5LjU4ODkgMjQuNzg5MVpNMzAuMTQwNiAxOS4yMzU0QzMwLjA3NjggMTkuMzQxIDMwLjAyMDcgMTkuNDQ1NyAyOS45NzM2IDE5LjU0ODhDMzAuMDIwOCAxOS40NDU3IDMwLjA3NjggMTkuMzQxIDMwLjE0MDYgMTkuMjM1NFpNMzAuNDc3NSAxOC43ODEyQzMwLjM5NDMgMTguODcxOSAzMC4zMjIzIDE4Ljk2NjYgMzAuMjU1OSAxOS4wNjA1QzMwLjI3NjcgMTkuMDMxMSAzMC4yOTU5IDE5IDMwLjMxODQgMTguOTcwN0wzMC40Nzc1IDE4Ljc4MTJaTTMxLjYzOTYgMTguMDM2MUMzMS40NTg4IDE4LjA5NDggMzEuMjgwNCAxOC4xNzIxIDMxLjEwODQgMTguMjcyNUMzMS4yODA0IDE4LjE3MjEgMzEuNDU4OCAxOC4wOTQ4IDMxLjYzOTYgMTguMDM2MVpNMzIuMTA0NSAxNy45MjY4QzMyLjA4MDcgMTcuOTMwMyAzMi4wNTcgMTcuOTM0MyAzMi4wMzMyIDE3LjkzODVDMzIuMDU3IDE3LjkzNDMgMzIuMDgwNyAxNy45MzAzIDMyLjEwNDUgMTcuOTI2OFpNNzEuMzQwOCA2LjY1NDNDNzIuMDUzOCA1Ljk0NTk1IDczLjAzMjkgNS41MDg4IDc0LjExMzMgNS41MDg3OUM3Ni4yOTQgNS41MDg4OSA3OC4wNjE1IDcuMjkwMTMgNzguMDYxNSA5LjQ4NzNDNzguMDYxNCAxMS42ODQ0IDc2LjI5MzkgMTMuNDY1NyA3NC4xMTMzIDEzLjQ2NThDNzIuMzY3OSAxMy40NjU4IDcwLjg4OCAxMi4zMjQyIDcwLjM2NjIgMTAuNzQyMkg2NC42OTQzTDY4LjA5MjggMTUuNTA0OUM2OC43MDI0IDE2LjM1OTUgNjguMzM0NiAxNy40NzkgNjcuNDkxMiAxNy44OTI2SDM2LjE1OTJDMzUuMzEyOCAxNy40Nzc2IDM0Ljk0NjIgMTYuMzUxNiAzNS41NjM1IDE1LjQ5NzFMNDAuOTYxOSA4LjAyNDQxQzQ0LjYwMjQgMi45ODUwNiA1MC40NDE0IDAuMDAwMTA1Mzk0IDU2LjY1ODIgMEg1Ny4wMzEzTDcxLjM0MDggNi42NTQzWiIgZmlsbD0id2hpdGUiLz4KPHBhdGggZD0iTTMyNy42NTEgNTkuNjA2NlY1My45NjY2TDMyMi43MzEgNDUuNjA2NkgzMjQuNDcxTDMyOC40MzEgNTIuNDQ2NkwzMzIuMzkxIDQ1LjYwNjZIMzM0LjA5MUwzMjkuMTcxIDUzLjkyNjZWNTkuNjA2NkgzMjcuNjUxWiIgZmlsbD0id2hpdGUiLz4KPHBhdGggZD0iTTMxNi4xOTEgNTkuNjA2NlY0Ny4wMDY2SDMxMi4yNzFWNDUuNjA2NkgzMjEuNjMxVjQ3LjAwNjZIMzE3LjY5MVY1OS42MDY2SDMxNi4xOTFaIiBmaWxsPSJ3aGl0ZSIvPgo8cGF0aCBkPSJNMzA4LjIxMyA1OS42MDY2VjQ1LjYwNjZIMzA5LjcxM1Y1OS42MDY2SDMwOC4yMTNaIiBmaWxsPSJ3aGl0ZSIvPgo8cGF0aCBkPSJNMjk1LjY1MSA1OS42MDY2VjQ1LjYwNjZIMzAwLjQzMUMzMDIuMDMxIDQ1LjYwNjYgMzAzLjMxMSA0Ni4wODY2IDMwNC4xMTEgNDYuOTA2NkMzMDQuODExIDQ3LjYwNjYgMzA1LjIxMSA0OC42MDY2IDMwNS4yMTEgNDkuNzg2NlY0OS44MjY2QzMwNS4yMTEgNTIuMDQ2NiAzMDMuODMxIDUzLjM4NjYgMzAxLjg5MSA1My44NjY2TDMwNS42NTEgNTkuNjA2NkgzMDMuODUxTDMwMC4zMzEgNTQuMTY2NkgyOTcuMTUxVjU5LjYwNjZIMjk1LjY1MVpNMjk3LjE1MSA1Mi44MDY2SDMwMC4xNzFDMzAyLjQ1MSA1Mi44MDY2IDMwMy43MTEgNTEuNjY2NiAzMDMuNzExIDQ5Ljg4NjZWNDkuODQ2NkMzMDMuNzExIDQ4LjAwNjYgMzAyLjQzMSA0Ni45ODY2IDMwMC4zMzEgNDYuOTg2NkgyOTcuMTUxVjUyLjgwNjZaIiBmaWxsPSJ3aGl0ZSIvPgo8cGF0aCBkPSJNMjg3LjQwNiA1OS44MjY2QzI4NC40MjYgNTkuODI2NiAyODIuNDA2IDU3LjkwNjYgMjgyLjQwNiA1NC4zODY2VjQ1LjYwNjZIMjgzLjkwNlY1NC4zNDY2QzI4My45MDYgNTYuOTg2NiAyODUuMjQ2IDU4LjQ0NjYgMjg3LjQ0NiA1OC40NDY2QzI4OS41ODYgNTguNDQ2NiAyOTAuOTQ2IDU3LjA2NjYgMjkwLjk0NiA1NC40MDY2VjQ1LjYwNjZIMjkyLjQ0NlY1NC4zMDY2QzI5Mi40NDYgNTcuOTA2NiAyOTAuNDI2IDU5LjgyNjYgMjg3LjQwNiA1OS44MjY2WiIgZmlsbD0id2hpdGUiLz4KPHBhdGggZD0iTTI3NS43NjEgNTkuODA2NkMyNzIuMzAxIDU5LjgwNjYgMjY5LjcyMSA1Ni45NDY2IDI2OS43MjEgNTIuNjg2NlY1Mi41NjY2QzI2OS43MjEgNDguMzI2NiAyNzIuMzYxIDQ1LjQwNjYgMjc1Ljg2MSA0NS40MDY2QzI3Ny43ODEgNDUuNDA2NiAyNzkuMDIxIDQ2LjEwNjYgMjgwLjEyMSA0Ny4xMjY2TDI3OS4yMDEgNDguMjY2NkMyNzguMzIxIDQ3LjQyNjYgMjc3LjI2MSA0Ni44MDY2IDI3NS44NDEgNDYuODA2NkMyNzMuMjYxIDQ2LjgwNjYgMjcxLjI4MSA0OS4xNjY2IDI3MS4yODEgNTIuNTQ2NlY1Mi42MjY2QzI3MS4yODEgNTYuMDY2NiAyNzMuMjYxIDU4LjQwNjYgMjc1Ljg0MSA1OC40MDY2QzI3Ny4yODEgNTguNDA2NiAyNzguMzAxIDU3LjgwNjYgMjc5LjMwMSA1Ni44NDY2TDI4MC4yMDEgNTcuODg2NkMyNzkuMDIxIDU5LjA0NjYgMjc3LjY4MSA1OS44MDY2IDI3NS43NjEgNTkuODA2NloiIGZpbGw9IndoaXRlIi8+CjxwYXRoIGQ9Ik0yNTguOTkxIDU5LjYwNjZWNDUuNjA2NkgyNjcuNTMxVjQ2Ljk4NjZIMjYwLjQ5MVY1MS44NjY2SDI2Ni44MTFWNTMuMjI2NkgyNjAuNDkxVjU4LjIyNjZIMjY3LjYzMVY1OS42MDY2SDI1OC45OTFaIiBmaWxsPSJ3aGl0ZSIvPgo8cGF0aCBkPSJNMjUxLjk3NCA1OS44MDY2QzI1MC4xNzQgNTkuODA2NiAyNDguNTc0IDU5LjE4NjYgMjQ3LjExNCA1Ny44MjY2TDI0OC4wNTQgNTYuNjg2NkMyNDkuMjE0IDU3Ljc2NjYgMjUwLjQxNCA1OC40MjY2IDI1MS45OTQgNTguNDI2NkMyNTMuNjc0IDU4LjQyNjYgMjU0Ljc5NCA1Ny40MDY2IDI1NC43OTQgNTYuMDY2NlY1Ni4wNDY2QzI1NC43OTQgNTQuODg2NiAyNTQuMjM0IDU0LjE0NjYgMjUxLjY5NCA1My4yNDY2QzI0OC43OTQgNTIuMTY2NiAyNDcuNjU0IDUxLjEyNjYgMjQ3LjY1NCA0OS4xNDY2VjQ5LjEwNjZDMjQ3LjY1NCA0Ny4wMDY2IDI0OS40MTQgNDUuNDA2NiAyNTEuODc0IDQ1LjQwNjZDMjUzLjQ5NCA0NS40MDY2IDI1NC44MzQgNDUuOTA2NiAyNTYuMDc0IDQ2Ljk4NjZMMjU1LjE3NCA0OC4xNDY2QzI1NC4xMzQgNDcuMjQ2NiAyNTMuMDM0IDQ2Ljc4NjYgMjUxLjgxNCA0Ni43ODY2QzI1MC4yMTQgNDYuNzg2NiAyNDkuMTc0IDQ3Ljc2NjYgMjQ5LjE3NCA0OC45NjY2VjQ5LjAwNjZDMjQ5LjE3NCA1MC4yMjY2IDI0OS43OTQgNTAuOTI2NiAyNTIuNDM0IDUxLjg4NjZDMjU1LjI3NCA1Mi45NDY2IDI1Ni4zMTQgNTQuMDg2NiAyNTYuMzE0IDU1Ljk0NjZWNTUuOTg2NkMyNTYuMzE0IDU4LjIyNjYgMjU0LjQ3NCA1OS44MDY2IDI1MS45NzQgNTkuODA2NloiIGZpbGw9IndoaXRlIi8+CjxwYXRoIGQ9Ik0yMzEuNTUgNTkuNjA2NlY0NS42MDY2SDI0MC4wOVY0Ni45ODY2SDIzMy4wNVY1MS44NjY2SDIzOS4zN1Y1My4yMjY2SDIzMy4wNVY1OC4yMjY2SDI0MC4xOVY1OS42MDY2SDIzMS41NVoiIGZpbGw9IndoaXRlIi8+CjxwYXRoIGQ9Ik0yMjEuMTc5IDU5LjYwNjZWNDUuNjA2NkgyMjIuNjc5VjU4LjIyNjZIMjI5LjE3OVY1OS42MDY2SDIyMS4xNzlaIiBmaWxsPSJ3aGl0ZSIvPgo8cGF0aCBkPSJNMjEyLjM0MiA1OS44MjY1QzIwOC43NjIgNTkuODI2NSAyMDYuMzIyIDU2LjgwNjUgMjA2LjMyMiA1Mi43MDY1VjUyLjU0NjVDMjA2LjMyMiA0OC40MjY1IDIwOC44MDIgNDUuMzg2NSAyMTIuMzYyIDQ1LjM4NjVDMjE1LjkyMiA0NS4zODY1IDIxOC4zNjIgNDguNDA2NSAyMTguMzYyIDUyLjUwNjVWNTIuNjY2NUMyMTguMzYyIDU2Ljc4NjUgMjE1LjkwMiA1OS44MjY1IDIxMi4zNDIgNTkuODI2NVpNMjEyLjM2MiA1OC40NDY1QzIxNC45NDIgNTguNDQ2NSAyMTYuODIyIDU2LjA2NjUgMjE2LjgyMiA1Mi42ODY1VjUyLjU0NjVDMjE2LjgyMiA0OS4xNjY1IDIxNC45MjIgNDYuNzY2NSAyMTIuMzQyIDQ2Ljc2NjVDMjA5Ljc2MiA0Ni43NjY1IDIwNy44ODIgNDkuMTQ2NSAyMDcuODgyIDUyLjUyNjVWNTIuNjY2NUMyMDcuODgyIDU2LjA0NjUgMjA5Ljc4MiA1OC40NDY1IDIxMi4zNjIgNTguNDQ2NVoiIGZpbGw9IndoaXRlIi8+CjxwYXRoIGQ9Ik0xOTUuMzE5IDU5LjYwNjZWNDUuNjA2NkgxOTkuNTM5QzIwMi41MTkgNDUuNjA2NiAyMDQuNDU5IDQ3LjI4NjYgMjA0LjQ1OSA1MC4wNDY2VjUwLjA4NjZDMjA0LjQ1OSA1My4wNDY2IDIwMi4yMTkgNTQuNjQ2NiAxOTkuMzU5IDU0LjY2NjZIMTk2LjgxOVY1OS42MDY2SDE5NS4zMTlaTTE5Ni44MTkgNTMuMzA2NkgxOTkuMzk5QzIwMS41NzkgNTMuMzA2NiAyMDIuOTM5IDUyLjA0NjYgMjAyLjkzOSA1MC4xMjY2VjUwLjEwNjZDMjAyLjkzOSA0OC4wNjY2IDIwMS41NzkgNDYuOTg2NiAxOTkuNDU5IDQ2Ljk4NjZIMTk2LjgxOVY1My4zMDY2WiIgZmlsbD0id2hpdGUiLz4KPHBhdGggZD0iTTE3Ny4wMTkgNTkuNjA2NlY0NS42MDY2SDE3OC41MTlWNTEuODY2NkgxODUuMjc5VjQ1LjYwNjZIMTg2Ljc3OVY1OS42MDY2SDE4NS4yNzlWNTMuMjY2NkgxNzguNTE5VjU5LjYwNjZIMTc3LjAxOVoiIGZpbGw9IndoaXRlIi8+CjxwYXRoIGQ9Ik0xNjkuMTQgNTkuNjA2NlY0Ny4wMDY2SDE2NS4yMlY0NS42MDY2SDE3NC41OFY0Ny4wMDY2SDE3MC42NFY1OS42MDY2SDE2OS4xNFoiIGZpbGw9IndoaXRlIi8+CjxwYXRoIGQ9Ik0xNTMuODc0IDU5LjYwNjZWNDUuNjA2NkgxNTguNjU0QzE2MC4yNTQgNDUuNjA2NiAxNjEuNTM0IDQ2LjA4NjYgMTYyLjMzNCA0Ni45MDY2QzE2My4wMzQgNDcuNjA2NiAxNjMuNDM0IDQ4LjYwNjYgMTYzLjQzNCA0OS43ODY2VjQ5LjgyNjZDMTYzLjQzNCA1Mi4wNDY2IDE2Mi4wNTQgNTMuMzg2NiAxNjAuMTE0IDUzLjg2NjZMMTYzLjg3NCA1OS42MDY2SDE2Mi4wNzRMMTU4LjU1NCA1NC4xNjY2SDE1NS4zNzRWNTkuNjA2NkgxNTMuODc0Wk0xNTUuMzc0IDUyLjgwNjZIMTU4LjM5NEMxNjAuNjc0IDUyLjgwNjYgMTYxLjkzNCA1MS42NjY2IDE2MS45MzQgNDkuODg2NlY0OS44NDY2QzE2MS45MzQgNDguMDA2NiAxNjAuNjU0IDQ2Ljk4NjYgMTU4LjU1NCA0Ni45ODY2SDE1NS4zNzRWNTIuODA2NloiIGZpbGw9IndoaXRlIi8+CjxwYXRoIGQ9Ik0xNDUuMDM4IDU5LjgyNjVDMTQxLjQ1OCA1OS44MjY1IDEzOS4wMTggNTYuODA2NSAxMzkuMDE4IDUyLjcwNjVWNTIuNTQ2NUMxMzkuMDE4IDQ4LjQyNjUgMTQxLjQ5OCA0NS4zODY1IDE0NS4wNTggNDUuMzg2NUMxNDguNjE4IDQ1LjM4NjUgMTUxLjA1OCA0OC40MDY1IDE1MS4wNTggNTIuNTA2NVY1Mi42NjY1QzE1MS4wNTggNTYuNzg2NSAxNDguNTk4IDU5LjgyNjUgMTQ1LjAzOCA1OS44MjY1Wk0xNDUuMDU4IDU4LjQ0NjVDMTQ3LjYzOCA1OC40NDY1IDE0OS41MTggNTYuMDY2NSAxNDkuNTE4IDUyLjY4NjVWNTIuNTQ2NUMxNDkuNTE4IDQ5LjE2NjUgMTQ3LjYxOCA0Ni43NjY1IDE0NS4wMzggNDYuNzY2NUMxNDIuNDU4IDQ2Ljc2NjUgMTQwLjU3OCA0OS4xNDY1IDE0MC41NzggNTIuNTI2NVY1Mi42NjY1QzE0MC41NzggNTYuMDQ2NSAxNDIuNDc4IDU4LjQ0NjUgMTQ1LjA1OCA1OC40NDY1WiIgZmlsbD0id2hpdGUiLz4KPHBhdGggZD0iTTEyNS45ODMgNTkuNjA2NlY0NS42MDY2SDEyNy40MDNMMTM0LjcyMyA1Ni42MjY2VjQ1LjYwNjZIMTM2LjIwM1Y1OS42MDY2SDEzNC45NDNMMTI3LjQ0MyA0OC4zMjY2VjU5LjYwNjZIMTI1Ljk4M1oiIGZpbGw9IndoaXRlIi8+CjxwYXRoIGQ9Ik0yMTcuNzU5IDM4LjYwNjVMMjI3LjI4NiAxMS4zNDI1SDIzNC4zMzVMMjQzLjkgMzguNjA2NUgyMzYuNTgxTDIzNC45OTMgMzMuNzI2OUgyMjYuNDczTDIyNC45MjQgMzguNjA2NUgyMTcuNzU5Wk0yMjguMjE2IDI4LjE1MDJIMjMzLjI1TDIzMC43MzMgMjAuMjExMUwyMjguMjE2IDI4LjE1MDJaIiBmaWxsPSJ3aGl0ZSIvPgo8cGF0aCBkPSJNMjA2LjAxOCAzOC42MDY1VjE3Ljc3MTNIMTk5LjMxOFYxMS40OTc0SDIxOS42ODhWMTcuNzcxM0gyMTIuOTg5VjM4LjYwNjVIMjA2LjAxOFoiIGZpbGw9IndoaXRlIi8+CjxwYXRoIGQ9Ik0xNzQuMTU5IDM4LjYwNjVWMTEuNDk3NEgxODAuNzA0TDE4OS43MjcgMjUuMTI5NFYxMS40OTc0SDE5Ni41ODJWMzguNjA2NUgxOTAuMzg2TDE4MS4wMTQgMjQuMzkzNlYzOC42MDY1SDE3NC4xNTlaIiBmaWxsPSJ3aGl0ZSIvPgo8cGF0aCBkPSJNMTQ1LjkwMiAzOC42MDY1TDE1NS40MjkgMTEuMzQyNUgxNjIuNDc3TDE3Mi4wNDMgMzguNjA2NUgxNjQuNzI0TDE2My4xMzYgMzMuNzI2OUgxNTQuNjE2TDE1My4wNjcgMzguNjA2NUgxNDUuOTAyWk0xNTYuMzU4IDI4LjE1MDJIMTYxLjM5M0wxNTguODc2IDIwLjIxMTFMMTU2LjM1OCAyOC4xNTAyWiIgZmlsbD0id2hpdGUiLz4KPHBhdGggZD0iTTEzNS4zNzkgMzguOTkzOEMxMzEuMzUyIDM4Ljk5MzggMTI3LjUxOCAzNy43NTQ1IDEyNC4zNDIgMzUuMDA0OUwxMjguMDYgMjkuOTMxNkMxMzAuMjY3IDMxLjc1MTggMTMyLjc4NSAzMi45OTExIDEzNS40MTggMzIuOTkxMUMxMzcuMjc3IDMyLjk5MTEgMTM4LjI0NSAzMi4xNzc4IDEzOC4yNDUgMzEuMDE2VjMwLjk3NzNDMTM4LjI0NSAyOS44OTI5IDEzNy40MzIgMjkuMjM0NSAxMzQuMjU2IDI4LjExMTRDMTI5LjE0NCAyNi4zNjg3IDEyNS41NDMgMjQuNTA5OCAxMjUuNTQzIDE5LjU5MTRWMTkuNDc1M0MxMjUuNTQzIDE0LjU1NjkgMTI5LjI5OSAxMS4xMTAyIDEzNS4yMjUgMTEuMTEwMkMxMzguODY1IDExLjExMDIgMTQyLjA3OSAxMi4xMTcxIDE0NC45MDYgMTQuNDAyTDE0MS4zODIgMTkuNTkxNEMxMzkuNTIzIDE4LjE1ODUgMTM3LjI3NyAxNy4xMTI5IDEzNS4wNyAxNy4xMTI5QzEzMy40ODIgMTcuMTEyOSAxMzIuNTkxIDE3Ljg4NzQgMTMyLjU5MSAxOC44OTQ0VjE4LjkzMzFDMTMyLjU5MSAyMC4xMzM2IDEzMy40NDMgMjAuNzUzMyAxMzYuODkgMjIuMDMxM0MxNDIuMDQxIDIzLjY5NjUgMTQ1LjI1NSAyNS43ODc4IDE0NS4yNTUgMzAuMzk2NFYzMC40NzM4QzE0NS4yNTUgMzUuNzQwNyAxNDEuMTg5IDM4Ljk5MzggMTM1LjM3OSAzOC45OTM4WiIgZmlsbD0id2hpdGUiLz4KPC9zdmc+Cg=="
            }) {
              Text(verbatim: "Populate").font(Font.subheadline)
            }
            Button(action: { brandingCompanyLogoDark = "" }) { Text("Clear").font(Font.subheadline) }
          }
          HStack {
            Toggle(isOn: $allowNotificationSilence) {
              Text(verbatim: "Allow notification silences")
            }
          }
          HStack {
            Picker(selection: $appearanceMode, label: Text(verbatim: "Appearance")) {
              Text(verbatim: "System").tag(AppearanceMode.system)
              Text(verbatim: "Light").tag(AppearanceMode.light)
              Text(verbatim: "Dark").tag(AppearanceMode.dark)
            }.pickerStyle(.segmented)
          }
        }
      }

      Divider()

      Button("Display") {
        var configMap = [
          "FunFontsOnSpecificDays": true,
          "ClientMode": clientModeOverride.rawValue as NSNumber,
          "EnableStandalonePasswordFallback": true,
          "UnknownBlockMessage": unknownBlockMessage,
          "EnableNotificationSilences": allowNotificationSilence,
        ]
        if !eventDetailURL.isEmpty {
          configMap["EventDetailURL"] = eventDetailURL
        }
        if !brandingCompanyName.isEmpty {
          configMap["BrandingCompanyName"] = brandingCompanyName
        }
        if !brandingCompanyLogo.isEmpty {
          configMap["BrandingCompanyLogo"] = brandingCompanyLogo
        }
        if !brandingCompanyLogoDark.isEmpty {
          configMap["BrandingCompanyLogoDark"] = brandingCompanyLogoDark
        }
        SNTConfigurator.overrideConfig(configMap)

        let event = SNTDebugStoredEvent(staticPublisher: publisher)
        event.decision = .blockUnknown
        event.fileBundleName = application
        event.fileSHA256 = sha256
        event.cdhash = cdhash
        event.teamID = teamID
        event.filePath = path
        event.parentName = parent
        event.pid = 12345
        event.ppid = 2511
        event.executingUser = NSUserName()

        switch dateOverride {
        case .Apr1: Date.overrideDate = Date(timeIntervalSince1970: 1711980915)
        case .May4: Date.overrideDate = Date(timeIntervalSince1970: 1714832115)
        case .Oct31: Date.overrideDate = Date(timeIntervalSince1970: 1730384115)
        case .Nov25: Date.overrideDate = Date(timeIntervalSince1970: 1732544115)
        }

        let window = NSWindow()
        ShowWindow(
          SNTBinaryMessageWindowViewFactory.createWith(
            window: window,
            event: event,
            customMsg: customMsg as NSString?,
            customURL: customURL as NSString?,
            configState: SNTConfigState(config: SNTConfigurator.configurator()),
            bundleProgress: SNTBundleProgress(),
            uiStateCallback: { interval in print("Silence interval was set to \(interval)") },
            replyCallback: { approved in print("Did user approve execution: \(approved)") }
          ),
          window,
          appearance: appearanceMode
        )
      }
    }
  }
}

struct FAAView: View {
  var body: some View {
    VStack {
      Image(systemName: "globe")
        .imageScale(.large)
        .foregroundStyle(.tint)
      Text("Hello, world!")
    }
  }
}

struct DeviceView: View {
  @State private var device: String = "SANDISK CRUZER"
  @State private var remountArgs: String = "rdonly"

  @State private var remountUSBMode: String = "rdonly,noexec"
  @State private var remountUSBBlockMessage: String = ""
  @State private var bannedUSBBlockMessage: String = ""
  @State private var appearanceMode: AppearanceMode = .system

  var body: some View {
    VStack {
      GroupBox(label: Label("Event Properties", systemImage: "")) {
        TextField(text: $device, label: { Text("Device") })
        TextField(text: $remountArgs, label: { Text("Remount Args (comma-separated)") })

      }
      GroupBox(label: Label("Config Overrides", systemImage: "")) {
        TextField(text: $remountUSBMode, label: { Text("RemountUSBMode (comma-separated)") })
        TextField(text: $remountUSBBlockMessage, label: { Text("RemountUSB Block Message") })
        TextField(text: $bannedUSBBlockMessage, label: { Text("Banned Block Message") })
        Picker(selection: $appearanceMode, label: Text(verbatim: "Appearance")) {
          Text(verbatim: "System").tag(AppearanceMode.system)
          Text(verbatim: "Light").tag(AppearanceMode.light)
          Text(verbatim: "Dark").tag(AppearanceMode.dark)
        }.pickerStyle(.segmented)
      }

      Button("Display") {
        let event = SNTDeviceEvent()
        event.mntonname = device
        event.remountArgs = remountArgs.components(separatedBy: ",")

        SNTConfigurator.overrideConfig([
          "RemountUSBBlockMessage": remountUSBBlockMessage,
          "BannedUSBBlockMessage": bannedUSBBlockMessage,
        ])

        let window = NSWindow()
        ShowWindow(
          SNTDeviceMessageWindowViewFactory.createWith(window: window, event: event),
          window,
          appearance: appearanceMode
        )
      }
    }
  }
}

struct AboutView: View {
  @State var dateOverride: SpecialDates = .Nov25
  @State var appearanceMode: AppearanceMode = .system

  var body: some View {
    VStack {
      HStack {
        Picker(selection: $dateOverride, label: Text(verbatim: "Date")) {
          Text(verbatim: "Nov 25").tag(SpecialDates.Nov25)
          Text(verbatim: "Apr 1").tag(SpecialDates.Apr1)
          Text(verbatim: "May 4").tag(SpecialDates.May4)
          Text(verbatim: "Oct 31").tag(SpecialDates.Oct31)
        }.pickerStyle(.segmented)
      }
      HStack {
        Picker(selection: $appearanceMode, label: Text(verbatim: "Appearance")) {
          Text(verbatim: "System").tag(AppearanceMode.system)
          Text(verbatim: "Light").tag(AppearanceMode.light)
          Text(verbatim: "Dark").tag(AppearanceMode.dark)
        }.pickerStyle(.segmented)
      }
      Button("Display") {
        switch dateOverride {
        case .Apr1: Date.overrideDate = Date(timeIntervalSince1970: 1711980915)
        case .May4: Date.overrideDate = Date(timeIntervalSince1970: 1714832115)
        case .Oct31: Date.overrideDate = Date(timeIntervalSince1970: 1730384115)
        case .Nov25: Date.overrideDate = Date(timeIntervalSince1970: 1732544115)
        }

        let window = NSWindow()
        ShowWindow(SNTAboutWindowViewFactory.createWith(window: window), window, appearance: appearanceMode)
      }
    }
  }
}

struct ContentView: View {
  var body: some View {
    TabView {
      BinaryView().padding(15.0).tabItem({ Text("Binary") })
      FAAView().padding(15.0).tabItem({ Text("FAA") })
      DeviceView().padding(15.0).tabItem({ Text("Device") })
      AboutView().padding(15.0).tabItem({ Text("About") })
    }
  }
}

class AppDelegate: NSObject, NSApplicationDelegate {
  func applicationDidFinishLaunching(_ notification: Notification) {
    NSApp.setActivationPolicy(.regular)
    NSApp.activate()
  }
}

@main
struct testApp: App {
  @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate

  var body: some Scene {
    Window("Main Window", id: "main") {
      ContentView().frame(minWidth: 300.0).fixedSize()
    }.windowResizability(.contentSize)
  }
}
