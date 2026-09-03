/// Copyright 2024 North Pole Security, Inc.
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

import santa_common_SNTConfigBundle
import santa_common_SNTConfigState
import santa_common_SNTConfigurator
import santa_common_SNTCommonEnums
import santa_common_SNTDeviceEvent
import santa_common_SNTRuleTimeWindow
import santa_common_SNTStoredExecutionEvent
import santa_common_SNTStoredNetworkFlowEvent
import santa_common_SNTTimedRuleKillDetails
import Source_gui_SNTDeviceMessageWindowView
import Source_gui_SNTBinaryMessageWindowView
import Source_gui_SNTAboutWindowView
import Source_gui_SNTNetworkFlowMessageWindowView
import Source_gui_SNTTimedRuleKillMessageWindowView

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
  case Jul20
  case Oct31
  case Nov25
}

enum AppearanceMode {
  case system
  case light
  case dark
}

struct CommonPropertiesView: View {
  @Binding var brandingCompanyName: String
  @Binding var brandingCompanyLogo: String
  @Binding var brandingCompanyLogoDark: String
  @Binding var appearanceMode: AppearanceMode

  var body: some View {
    Group {
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
            "data:image/png;base64,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"
        }) {
          Text(verbatim: "Populate").font(Font.subheadline)
        }
        Button(action: { brandingCompanyLogoDark = "" }) { Text("Clear").font(Font.subheadline) }
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
}

struct BinaryView: View {
  @State var application: String = "Bad Malware"
  @State var publisher: String = "Developer ID: Cozy Bear (X4P54F4992)"
  @State var sha256: String = "60055b1f6fb276bfacf61f91505a72201987f20ad8b6867cce3058f4c0f0f5e5"
  @State var cdhash: String = "e38e71023d09c2e8e78a0e382669d1338ee8876a"
  @State var teamID: String = "9X9633G7QW"
  @State var path: String = "/Applications/Malware.app/Contents/MacOS"
  @State var parent: String = "launchd"
  @State var executingUser: String = NSUserName()

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
  @State private var eventDetailText: String = ""
  @State private var eventDetailButtonText: String = ""

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
          TextField(text: $executingUser, label: { Text(verbatim: "Executing User") })
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
            TextField(text: $eventDetailText, label: { Text(verbatim: "Event Detail Text") })
            Button(action: { eventDetailText = "Request Access" }) {
              Text("Populate").font(Font.subheadline)
            }
            Button(action: { eventDetailText = "" }) {
              Text(verbatim: "Clear").font(Font.subheadline)
            }
          }
          HStack {
            TextField(
              text: $eventDetailButtonText,
              label: { Text(verbatim: "Event Detail Button Text (per-event)") }
            )
            Button(action: { eventDetailButtonText = "Request Access" }) {
              Text("Populate").font(Font.subheadline)
            }
            Button(action: { eventDetailButtonText = "" }) {
              Text(verbatim: "Clear").font(Font.subheadline)
            }
          }
          HStack {
            Picker(selection: $dateOverride, label: Text(verbatim: "Date")) {
              Text(verbatim: "Nov 25").tag(SpecialDates.Nov25)
              Text(verbatim: "Apr 1").tag(SpecialDates.Apr1)
              Text(verbatim: "May 4").tag(SpecialDates.May4)
              Text(verbatim: "Jul 20").tag(SpecialDates.Jul20)
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
            Toggle(isOn: $allowNotificationSilence) {
              Text(verbatim: "Allow notification silences")
            }
          }
          CommonPropertiesView(
            brandingCompanyName: $brandingCompanyName,
            brandingCompanyLogo: $brandingCompanyLogo,
            brandingCompanyLogoDark: $brandingCompanyLogoDark,
            appearanceMode: $appearanceMode
          )
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
        if !eventDetailText.isEmpty {
          configMap["EventDetailText"] = eventDetailText
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
        event.executingUser = executingUser

        switch dateOverride {
        case .Apr1: Date.overrideDate = Date(timeIntervalSince1970: 1711980915)
        case .May4: Date.overrideDate = Date(timeIntervalSince1970: 1714832115)
        case .Jul20: Date.overrideDate = Date(timeIntervalSince1970: 1721497515)
        case .Oct31: Date.overrideDate = Date(timeIntervalSince1970: 1730384115)
        case .Nov25: Date.overrideDate = Date(timeIntervalSince1970: 1732544115)
        }

        // Mirror SNTExecutionController.mm: customURL falls back to the EventDetailURL
        // config so the Open Event button appears in the harness.
        let effectiveURL = customURL.isEmpty ? eventDetailURL : customURL

        let window = NSWindow()
        ShowWindow(
          SNTBinaryMessageWindowViewFactory.createWith(
            window: window,
            event: event,
            customMsg: customMsg as NSString?,
            customURL: effectiveURL.isEmpty ? nil : (effectiveURL as NSString),
            eventDetailButtonText: eventDetailButtonText.isEmpty ? nil : (eventDetailButtonText as NSString),
            configState: SNTConfigState(config: SNTConfigurator.configurator()),
            bundleProgress: SNTBundleProgress(),
            silenceable: true,
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
  @State var brandingCompanyName: String = ""
  @State var brandingCompanyLogo: String = ""
  @State var brandingCompanyLogoDark: String = ""
  @State var appearanceMode: AppearanceMode = .system

  var body: some View {
    VStack {
      GroupBox(label: Label("Config Overrides", systemImage: "")) {
        Form {
          CommonPropertiesView(
            brandingCompanyName: $brandingCompanyName,
            brandingCompanyLogo: $brandingCompanyLogo,
            brandingCompanyLogoDark: $brandingCompanyLogoDark,
            appearanceMode: $appearanceMode
          )
        }
      }

      Text("FAA View - Display functionality coming soon")
    }
  }
}

struct DeviceView: View {
  @State private var device: String = "SANDISK CRUZER"
  @State private var remountArgs: String = "rdonly"

  @State private var remountUSBMode: String = "rdonly,noexec"
  @State private var remountUSBBlockMessage: String = ""
  @State private var bannedUSBBlockMessage: String = ""
  @State private var allowNotificationSilence: Bool = true
  @State private var brandingCompanyName: String = ""
  @State private var brandingCompanyLogo: String = ""
  @State private var brandingCompanyLogoDark: String = ""
  @State private var appearanceMode: AppearanceMode = .system

  var body: some View {
    VStack {
      GroupBox(label: Label("Event Properties", systemImage: "")) {
        TextField(text: $device, label: { Text("Device") })
        TextField(text: $remountArgs, label: { Text("Remount Args (comma-separated)") })

      }
      GroupBox(label: Label("Config Overrides", systemImage: "")) {
        Form {
          TextField(text: $remountUSBMode, label: { Text("RemountUSBMode (comma-separated)") })
          TextField(text: $remountUSBBlockMessage, label: { Text("RemountUSB Block Message") })
          TextField(text: $bannedUSBBlockMessage, label: { Text("Banned Block Message") })
          HStack {
            Toggle(isOn: $allowNotificationSilence) {
              Text(verbatim: "Allow notification silences")
            }
          }
          CommonPropertiesView(
            brandingCompanyName: $brandingCompanyName,
            brandingCompanyLogo: $brandingCompanyLogo,
            brandingCompanyLogoDark: $brandingCompanyLogoDark,
            appearanceMode: $appearanceMode
          )
        }
      }

      Button("Display") {
        let event = SNTDeviceEvent()
        event.mntonname = device
        event.remountArgs = remountArgs.components(separatedBy: ",")

        var configMap = [
          "RemountUSBBlockMessage": remountUSBBlockMessage,
          "BannedUSBBlockMessage": bannedUSBBlockMessage,
        ]
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

        let bundle = SNTConfigBundle()
        bundle.setValue(NSNumber(value: allowNotificationSilence), forKey: "enableNotificationSilences")

        let window = NSWindow()
        ShowWindow(
          SNTDeviceMessageWindowViewFactory.createWith(
            window: window,
            event: event,
            configBundle: bundle,
            silenceable: true,
            uiStateCallback: { interval in print("Silence interval was set to \(interval)") }
          ),
          window,
          appearance: appearanceMode
        )
      }
    }
  }
}

struct AboutView: View {
  @State var dateOverride: SpecialDates = .Nov25
  @State var brandingCompanyName: String = ""
  @State var brandingCompanyLogo: String = ""
  @State var brandingCompanyLogoDark: String = ""
  @State var appearanceMode: AppearanceMode = .system

  var body: some View {
    VStack {
      GroupBox(label: Label("Config Overrides", systemImage: "")) {
        Form {
          HStack {
            Picker(selection: $dateOverride, label: Text(verbatim: "Date")) {
              Text(verbatim: "Nov 25").tag(SpecialDates.Nov25)
              Text(verbatim: "Apr 1").tag(SpecialDates.Apr1)
              Text(verbatim: "May 4").tag(SpecialDates.May4)
              Text(verbatim: "Jul 20").tag(SpecialDates.Jul20)
              Text(verbatim: "Oct 31").tag(SpecialDates.Oct31)
            }.pickerStyle(.segmented)
          }
          CommonPropertiesView(
            brandingCompanyName: $brandingCompanyName,
            brandingCompanyLogo: $brandingCompanyLogo,
            brandingCompanyLogoDark: $brandingCompanyLogoDark,
            appearanceMode: $appearanceMode
          )
        }
      }
      Button("Display") {
        switch dateOverride {
        case .Apr1: Date.overrideDate = Date(timeIntervalSince1970: 1711980915)
        case .May4: Date.overrideDate = Date(timeIntervalSince1970: 1714832115)
        case .Jul20: Date.overrideDate = Date(timeIntervalSince1970: 1721497515)
        case .Oct31: Date.overrideDate = Date(timeIntervalSince1970: 1730384115)
        case .Nov25: Date.overrideDate = Date(timeIntervalSince1970: 1732544115)
        }

        var configMap: [String: Any] = [:]
        if !brandingCompanyName.isEmpty {
          configMap["BrandingCompanyName"] = brandingCompanyName
        }
        if !brandingCompanyLogo.isEmpty {
          configMap["BrandingCompanyLogo"] = brandingCompanyLogo
        }
        if !brandingCompanyLogoDark.isEmpty {
          configMap["BrandingCompanyLogoDark"] = brandingCompanyLogoDark
        }
        if !configMap.isEmpty {
          SNTConfigurator.overrideConfig(configMap)
        }

        let window = NSWindow()
        ShowWindow(SNTAboutWindowViewFactory.createWith(window: window), window, appearance: appearanceMode)
      }
    }
  }
}

struct NetworkFlowView: View {
  @State private var application: String = "/Applications/Malware.app/Contents/MacOS/Malware"
  @State private var hostname: String = "evil.example.com"
  @State private var remoteAddress: String = "93.184.216.34"
  @State private var remotePort: String = "443"
  @State private var ruleName: String = "block-evil-example"
  @State private var ruleId: String = "42"
  @State private var decisionTier: SNTNetworkFlowTier = .domain
  @State private var sha256: String = "60055b1f6fb276bfacf61f91505a72201987f20ad8b6867cce3058f4c0f0f5e5"
  @State private var cdhash: String = "e38e71023d09c2e8e78a0e382669d1338ee8876a"
  @State private var signingID: String = "com.example.malware"
  @State private var teamID: String = "9X9633G7QW"
  @State private var pid: String = "12345"
  @State private var executingUser: String = NSUserName()
  @State private var customMsg: String = ""
  @State private var customURL: String = ""
  @State private var eventDetailButtonText: String = ""
  @State private var allowNotificationSilence: Bool = true

  @State private var brandingCompanyName: String = ""
  @State private var brandingCompanyLogo: String = ""
  @State private var brandingCompanyLogoDark: String = ""
  @State private var appearanceMode: AppearanceMode = .system

  var body: some View {
    VStack {
      GroupBox(label: Label("Event Properties", systemImage: "")) {
        Form {
          TextField(text: $application, label: { Text(verbatim: "Application") })
          TextField(text: $sha256, label: { Text(verbatim: "SHA-256") })
          TextField(text: $cdhash, label: { Text(verbatim: "CDHash") })
          TextField(text: $signingID, label: { Text(verbatim: "Signing ID") })
          TextField(text: $teamID, label: { Text(verbatim: "Team ID") })
          TextField(text: $pid, label: { Text(verbatim: "PID") })
          TextField(text: $executingUser, label: { Text(verbatim: "Executing User") })
          TextField(text: $hostname, label: { Text(verbatim: "Hostname") })
          TextField(text: $remoteAddress, label: { Text(verbatim: "Remote Address") })
          TextField(text: $remotePort, label: { Text(verbatim: "Remote Port") })
          TextField(text: $ruleName, label: { Text(verbatim: "Rule Name") })
          TextField(text: $ruleId, label: { Text(verbatim: "Rule ID") })
          HStack {
            TextField(text: $customMsg, label: { Text(verbatim: "Custom Message") })
            Button(action: { customMsg = "Contact IT before reaching this host" }) {
              Text(verbatim: "Populate").font(Font.subheadline)
            }
            Button(action: { customMsg = "" }) { Text(verbatim: "Clear").font(Font.subheadline) }
          }
          HStack {
            TextField(text: $customURL, label: { Text(verbatim: "Custom URL") })
            Button(action: {
              customURL =
                "http://sync-server-hostname/netflow?rule=%rule_name%&host=%remote_hostname%&port=%remote_port%"
            }) {
              Text(verbatim: "Populate").font(Font.subheadline)
            }
            Button(action: { customURL = "" }) { Text(verbatim: "Clear").font(Font.subheadline) }
          }
          HStack {
            TextField(
              text: $eventDetailButtonText,
              label: { Text(verbatim: "Event Detail Button Text") }
            )
            Button(action: { eventDetailButtonText = "Request Access" }) {
              Text("Populate").font(Font.subheadline)
            }
            Button(action: { eventDetailButtonText = "" }) {
              Text(verbatim: "Clear").font(Font.subheadline)
            }
          }
          HStack {
            Picker(selection: $decisionTier, label: Text(verbatim: "Match (decisionTier)")) {
              Text(verbatim: "Exact IP").tag(SNTNetworkFlowTier.exactIP)
              Text(verbatim: "CIDR").tag(SNTNetworkFlowTier.CIDR)
              Text(verbatim: "Hostname").tag(SNTNetworkFlowTier.hostname)
              Text(verbatim: "Domain").tag(SNTNetworkFlowTier.domain)
              Text(verbatim: "Any Remote").tag(SNTNetworkFlowTier.anyRemote)
            }.pickerStyle(.segmented)
          }
        }
      }

      GroupBox(label: Label("Config Overrides", systemImage: "")) {
        Form {
          HStack {
            Toggle(isOn: $allowNotificationSilence) {
              Text(verbatim: "Allow notification silences")
            }
          }
          CommonPropertiesView(
            brandingCompanyName: $brandingCompanyName,
            brandingCompanyLogo: $brandingCompanyLogo,
            brandingCompanyLogoDark: $brandingCompanyLogoDark,
            appearanceMode: $appearanceMode
          )
        }
      }

      Button("Display") {
        var configMap: [String: Any] = [:]
        if !brandingCompanyName.isEmpty {
          configMap["BrandingCompanyName"] = brandingCompanyName
        }
        if !brandingCompanyLogo.isEmpty {
          configMap["BrandingCompanyLogo"] = brandingCompanyLogo
        }
        if !brandingCompanyLogoDark.isEmpty {
          configMap["BrandingCompanyLogoDark"] = brandingCompanyLogoDark
        }
        if !configMap.isEmpty {
          SNTConfigurator.overrideConfig(configMap)
        }

        let event = SNTStoredNetworkFlowEvent()
        event.decision = .block
        event.process?.filePath = application
        event.process?.fileSHA256 = sha256
        event.process?.cdhash = cdhash
        event.process?.signingID = signingID
        event.process?.teamID = teamID
        event.process?.pid = NSNumber(value: Int(pid) ?? 0)
        event.process?.executingUser = executingUser
        event.hostname = hostname
        event.remoteAddress = remoteAddress
        event.remotePort = UInt16(remotePort) ?? 0
        event.direction = .outgoing
        event.`protocol` = 6
        event.ruleName = ruleName
        event.ruleId = Int64(ruleId) ?? 0
        event.decisionTier = decisionTier
        event.customMsg = customMsg.isEmpty ? nil : customMsg
        event.customURL = customURL.isEmpty ? nil : customURL
        event.eventDetailButtonText = eventDetailButtonText.isEmpty ? nil : eventDetailButtonText

        let bundle = SNTConfigBundle()
        bundle.setValue(NSNumber(value: allowNotificationSilence), forKey: "enableNotificationSilences")

        let window = NSWindow()
        ShowWindow(
          SNTNetworkFlowMessageWindowViewFactory.createWith(
            window: window,
            event: event,
            configBundle: bundle,
            silenceable: true,
            uiStateCallback: { interval in print("Silence interval was set to \(interval)") }
          ),
          window,
          appearance: appearanceMode
        )
      }
    }
  }
}

enum RuleWindowDays {
  case everyDay
  case weekdays
  case monWedFri
  case unset
}

struct TimedRuleKillView: View {
  @State private var application: String = "Calculator"
  @State private var publisher: String = "Apple Inc. - Software Signing"
  @State private var user: String = NSUserName()
  @State private var path: String = "/System/Applications/Calculator.app/Contents/MacOS/Calculator"
  @State private var signingID: String = "platform:com.apple.calculator"
  @State private var cdhash: String = "3143f4402b417986ad4df24ce68127f0716b7898"
  @State private var parent: String = "launchd"
  @State private var ppid: String = "1"
  @State private var ruleType: SNTRuleType = .signingID
  // Minutes, so a value past midnight also exercises the dated form of the sentence.
  @State private var minutesUntilDeadline: String = "45"

  @State private var includeTimeWindow: Bool = true
  @State private var startOfDay: String = "09:00"
  @State private var endOfDay: String = "17:00"
  @State private var zoneName: String = "local"
  @State private var windowDays: RuleWindowDays = .weekdays

  @State private var brandingCompanyName: String = ""
  @State private var brandingCompanyLogo: String = ""
  @State private var brandingCompanyLogoDark: String = ""
  @State private var appearanceMode: AppearanceMode = .system

  var body: some View {
    VStack {
      GroupBox(label: Label("Warning Properties", systemImage: "")) {
        Form {
          TextField(text: $application, label: { Text(verbatim: "Application") })
          TextField(text: $publisher, label: { Text(verbatim: "Publisher") })
          TextField(text: $user, label: { Text(verbatim: "User") })
          TextField(text: $path, label: { Text(verbatim: "Path") })
          TextField(text: $signingID, label: { Text(verbatim: "Signing ID") })
          TextField(text: $cdhash, label: { Text(verbatim: "CDHash") })
          TextField(text: $parent, label: { Text(verbatim: "Parent") })
          TextField(text: $ppid, label: { Text(verbatim: "PPID") })
          TextField(text: $minutesUntilDeadline, label: { Text(verbatim: "Minutes Until Deadline") })
          HStack {
            Picker(selection: $ruleType, label: Text(verbatim: "Rule Type")) {
              Text(verbatim: "Signing ID").tag(SNTRuleType.signingID)
              Text(verbatim: "Team ID").tag(SNTRuleType.teamID)
              Text(verbatim: "CDHash").tag(SNTRuleType.cdHash)
              Text(verbatim: "Unknown").tag(SNTRuleType.unknown)
            }.pickerStyle(.segmented)
          }
        }
      }

      GroupBox(label: Label("Time Window", systemImage: "")) {
        Form {
          HStack {
            Toggle(isOn: $includeTimeWindow) { Text(verbatim: "Include a time window") }
          }
          TextField(text: $startOfDay, label: { Text(verbatim: "Start (HH:MM)") })
          TextField(text: $endOfDay, label: { Text(verbatim: "End (HH:MM)") })
          TextField(text: $zoneName, label: { Text(verbatim: "Zone") })
          HStack {
            Picker(selection: $windowDays, label: Text(verbatim: "Days")) {
              Text(verbatim: "Every day").tag(RuleWindowDays.everyDay)
              Text(verbatim: "Mon to Fri").tag(RuleWindowDays.weekdays)
              Text(verbatim: "Mon, Wed, Fri").tag(RuleWindowDays.monWedFri)
              Text(verbatim: "None").tag(RuleWindowDays.unset)
            }.pickerStyle(.segmented)
          }
        }
      }

      GroupBox(label: Label("Config Overrides", systemImage: "")) {
        Form {
          CommonPropertiesView(
            brandingCompanyName: $brandingCompanyName,
            brandingCompanyLogo: $brandingCompanyLogo,
            brandingCompanyLogoDark: $brandingCompanyLogoDark,
            appearanceMode: $appearanceMode
          )
        }
      }

      Button("Display") {
        var configMap: [String: Any] = [:]
        if !brandingCompanyName.isEmpty {
          configMap["BrandingCompanyName"] = brandingCompanyName
        }
        if !brandingCompanyLogo.isEmpty {
          configMap["BrandingCompanyLogo"] = brandingCompanyLogo
        }
        if !brandingCompanyLogoDark.isEmpty {
          configMap["BrandingCompanyLogoDark"] = brandingCompanyLogoDark
        }
        if !configMap.isEmpty {
          SNTConfigurator.overrideConfig(configMap)
        }

        let details = SNTTimedRuleKillDetails()
        details.application = application
        details.deadline = Date(
          timeIntervalSinceNow: (Double(minutesUntilDeadline) ?? 45.0) * 60.0
        )
        details.ruleType = ruleType
        details.publisher = publisher.isEmpty ? nil : publisher
        details.user = user.isEmpty ? nil : user
        details.path = path.isEmpty ? nil : path
        details.signingID = signingID.isEmpty ? nil : signingID
        details.cdhash = cdhash.isEmpty ? nil : cdhash
        details.parentName = parent.isEmpty ? nil : parent
        details.ppid = ppid.isEmpty ? nil : NSNumber(value: Int(ppid) ?? 0)

        if includeTimeWindow {
          let timeWindow = SNTRuleTimeWindow()
          timeWindow.startOfDay = startOfDay
          timeWindow.endOfDay = endOfDay
          timeWindow.zoneName = zoneName.isEmpty ? nil : zoneName
          switch windowDays {
          case .everyDay: timeWindow.days = [0, 1, 2, 3, 4, 5, 6].map { NSNumber(value: $0) }
          case .weekdays: timeWindow.days = [1, 2, 3, 4, 5].map { NSNumber(value: $0) }
          case .monWedFri: timeWindow.days = [1, 3, 5].map { NSNumber(value: $0) }
          case .unset: timeWindow.days = nil
          }
          details.timeWindow = timeWindow
        }

        let window = NSWindow()
        ShowWindow(
          SNTTimedRuleKillMessageWindowViewFactory.createWith(window: window, details: details),
          window,
          appearance: appearanceMode
        )
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
      NetworkFlowView().padding(15.0).tabItem({ Text("Network Flow") })
      TimedRuleKillView().padding(15.0).tabItem({ Text("Timed Rule Kill") })
      AboutView().padding(15.0).tabItem({ Text("About") })
    }
  }
}

// Renders the binary block dialog with the given config overrides, writes it to
// a PNG and exits. Used to regenerate the dialog screenshots in
// docs/static/img. Example:
//
//   SantaTestGUI.app/Contents/MacOS/SantaTestGUI --screenshot /tmp/dialog.png \
//       --dark --config '{"BrandingCompanyName": "Acme, Inc."}'
func CaptureScreenshot(path: String, appearance: AppearanceMode, config: [String: Any]) {
  var configMap: [String: Any] = ["ClientMode": SNTClientMode.lockdown.rawValue as NSNumber]
  configMap.merge(config) { _, new in new }
  SNTConfigurator.overrideConfig(configMap)

  let event = SNTDebugStoredEvent(staticPublisher: "Developer ID: Cozy Bear (X4P54F4992)")
  event.decision = .blockUnknown
  event.fileBundleName = "Bad Malware"
  event.fileSHA256 = "60055b1f6fb276bfacf61f91505a72201987f20ad8b6867cce3058f4c0f0f5e5"
  event.cdhash = "e38e71023d09c2e8e78a0e382669d1338ee8876a"
  event.teamID = "9X9633G7QW"
  event.filePath = "/Applications/Malware.app/Contents/MacOS"
  event.parentName = "launchd"
  event.pid = 12345
  event.ppid = 2511
  event.executingUser = "sasha"

  let window = NSWindow()
  ShowWindow(
    SNTBinaryMessageWindowViewFactory.createWith(
      window: window,
      event: event,
      customMsg: nil,
      customURL: nil,
      eventDetailButtonText: nil,
      configState: SNTConfigState(config: SNTConfigurator.configurator()),
      bundleProgress: SNTBundleProgress(),
      silenceable: true,
      uiStateCallback: nil,
      replyCallback: nil
    ),
    window,
    appearance: appearance
  )

  // Let SwiftUI lay out and draw before capturing.
  RunLoop.main.run(until: Date().addingTimeInterval(2.0))

  guard let frameView = window.contentView?.superview,
    let rep = frameView.bitmapImageRepForCachingDisplay(in: frameView.bounds)
  else {
    print("Failed to snapshot window")
    exit(1)
  }
  frameView.cacheDisplay(in: frameView.bounds, to: rep)

  guard let data = ShadowedWindowImage(rep).representation(using: .png, properties: [:]) else {
    print("Failed to encode PNG")
    exit(1)
  }
  do {
    try data.write(to: URL(fileURLWithPath: path))
  } catch {
    print("Failed to write \(path): \(error)")
    exit(1)
  }
  exit(0)
}

// cacheDisplay(_:to:) captures the window's own drawing only: no rounded corners
// and no drop shadow, both of which the window server composites. Re-add them so
// the output matches an interactive screencapture(1) window grab.
func ShadowedWindowImage(_ window: NSBitmapImageRep) -> NSBitmapImageRep {
  let cornerRadius = 10.0
  // Just enough room for the shadow below to fade out without being clipped.
  let margin = 36.0
  let scale = Double(window.pixelsWide) / window.size.width
  let windowRect = NSMakeRect(margin, margin, window.size.width, window.size.height)
  let canvas = NSMakeRect(0, 0, window.size.width + margin * 2, window.size.height + margin * 2)

  let out = NSBitmapImageRep(
    bitmapDataPlanes: nil,
    pixelsWide: Int(canvas.width * scale),
    pixelsHigh: Int(canvas.height * scale),
    bitsPerSample: 8,
    samplesPerPixel: 4,
    hasAlpha: true,
    isPlanar: false,
    colorSpaceName: .deviceRGB,
    bytesPerRow: 0,
    bitsPerPixel: 0
  )!
  out.size = canvas.size

  NSGraphicsContext.saveGraphicsState()
  NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: out)
  let shadow = NSShadow()
  shadow.shadowBlurRadius = 26.0
  shadow.shadowOffset = NSMakeSize(0, -9)
  shadow.shadowColor = NSColor.black.withAlphaComponent(0.55)
  shadow.set()
  let clip = NSBezierPath(roundedRect: windowRect, xRadius: cornerRadius, yRadius: cornerRadius)
  // Draw the rounded rect once to cast the shadow, then clip the capture to it.
  NSColor.black.setFill()
  clip.fill()
  NSGraphicsContext.saveGraphicsState()
  clip.addClip()
  window.draw(in: windowRect)
  NSGraphicsContext.restoreGraphicsState()
  NSGraphicsContext.restoreGraphicsState()

  return out
}

class AppDelegate: NSObject, NSApplicationDelegate {
  func applicationDidFinishLaunching(_ notification: Notification) {
    NSApp.setActivationPolicy(.regular)
    NSApp.activate()

    let args = ProcessInfo.processInfo.arguments
    guard let flag = args.firstIndex(of: "--screenshot") else { return }
    guard flag + 1 < args.count, !args[flag + 1].hasPrefix("--") else {
      print("--screenshot requires an output path")
      exit(1)
    }

    var config: [String: Any] = [:]
    if let i = args.firstIndex(of: "--config"), i + 1 < args.count {
      guard let json = try? JSONSerialization.jsonObject(with: Data(args[i + 1].utf8)),
        let dict = json as? [String: Any]
      else {
        print("--config must be a JSON object of config keys")
        exit(1)
      }
      config = dict
    }

    CaptureScreenshot(
      path: args[flag + 1],
      appearance: args.contains("--dark") ? .dark : .light,
      config: config
    )
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
