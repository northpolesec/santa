import SwiftUI

import santa_common_SNTConfigState
import santa_common_SNTConfigurator
import santa_common_SNTCommonEnums
import santa_common_SNTDeviceEvent
import santa_common_SNTStoredEvent
import Source_gui_SNTDeviceMessageWindowView
import Source_gui_SNTBinaryMessageWindowView
import Source_gui_SNTAboutWindowView

func ShowWindow(_ vc: NSViewController, _ window: NSWindow) {
  window.contentRect(forFrameRect: NSMakeRect(0, 0, 0, 0))
  window.styleMask = [.closable, .resizable, .titled]
  window.backingType = .buffered
  window.titlebarAppearsTransparent = true
  window.isMovableByWindowBackground = true
  window.standardWindowButton(.zoomButton)?.isHidden = true
  window.standardWindowButton(.closeButton)?.isHidden = true
  window.standardWindowButton(.miniaturizeButton)?.isHidden = true
  window.contentViewController = vc
  window.makeKeyAndOrderFront(nil)
  window.setFrame(window.frame, display: true)
  window.center()
}

class SNTDebugStoredEvent: SNTStoredEvent {
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
            Toggle(isOn: $allowNotificationSilence) {
              Text(verbatim: "Allow notification silences")
            }
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
          window
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
        ShowWindow(SNTDeviceMessageWindowViewFactory.createWith(window: window, event: event), window)
      }
    }
  }
}

struct AboutView: View {
  @State var dateOverride: SpecialDates = .Nov25

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
      Button("Display") {
        switch dateOverride {
        case .Apr1: Date.overrideDate = Date(timeIntervalSince1970: 1711980915)
        case .May4: Date.overrideDate = Date(timeIntervalSince1970: 1714832115)
        case .Oct31: Date.overrideDate = Date(timeIntervalSince1970: 1730384115)
        case .Nov25: Date.overrideDate = Date(timeIntervalSince1970: 1732544115)
        }

        let window = NSWindow()
        ShowWindow(SNTAboutWindowViewFactory.createWith(window: window), window)
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
