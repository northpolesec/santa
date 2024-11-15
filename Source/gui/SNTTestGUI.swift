import SwiftUI

import santa_common_SNTConfigurator
import santa_common_SNTDeviceEvent
import santa_common_SNTStoredEvent
import Source_gui_SNTDeviceMessageWindowView
import Source_gui_SNTBinaryMessageWindowView

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

  @State var bannedBlockMessage: String = ""
  @State var eventDetailURL: String = "http://sync-server-hostname/blockables/%bundle_or_file_identifier%"
  @State var dateOverride: SpecialDates = .Nov25

  @State var customMsg: String = ""
  @State var customURL: String = ""

  var body: some View {
    VStack(spacing: 15.0) {
      GroupBox(label: Label("Event Properties", systemImage: "")) {
        Form {
          TextField(text: $application, label: { Text("Application") })
          TextField(text: $publisher, label: { Text("Publisher") })
          TextField(text: $sha256, label: { Text("SHA-256") })
          TextField(text: $cdhash, label: { Text("CDHash") })
          TextField(text: $teamID, label: { Text("TeamID") })
          TextField(text: $path, label: { Text("Path") })
          TextField(text: $parent, label: { Text("Parent") })
        }
      }

      GroupBox(label: Label("Config Overrides", systemImage: "")) {
        Form {
          HStack {
            TextField(text: $bannedBlockMessage, label: { Text("Banned Block Message") }).frame(width: 550.0)
            Button(action: {
              bannedBlockMessage =
                "<img src='https://static.wikia.nocookie.net/villains/images/8/8a/Robot_Santa.png/revision/latest?cb=20200520230856' /><br /><br />Isn't Santa fun?"
            }) {
              Text("Populate (With Image)").font(Font.subheadline)
            }
            Button(action: { bannedBlockMessage = "You may not run this thing" }) {
              Text("Populate (1-line)").font(Font.subheadline)
            }
            Button(action: { bannedBlockMessage = "" }) { Text("Clear").font(Font.subheadline) }
          }

          HStack {
            TextField(text: $eventDetailURL, label: { Text("Event Detail URL") })
            Button(action: { eventDetailURL = "http://sync-server-hostname/blockables/%bundle_or_file_identifier%" }) {
              Text("Populate").font(Font.subheadline)
            }
            Button(action: { eventDetailURL = "" }) { Text("Clear").font(Font.subheadline) }
          }
          HStack {
            Picker(selection: $dateOverride, label: Text("Date :")) {
              Text("Nov 25").tag(SpecialDates.Nov25)
              Text("Apr 1").tag(SpecialDates.Apr1)
              Text("May 4").tag(SpecialDates.May4)
              Text("Oct 31").tag(SpecialDates.Oct31)
            }.pickerStyle(.segmented)
          }
        }
      }

      Divider()

      Button("Display") {
        SNTConfigurator.overrideConfig([
          "BannedBlockMessage": bannedBlockMessage,
          "EventDetailURL": eventDetailURL,
          "FunFontsOnSpecificDays": true,
        ])

        let event = SNTDebugStoredEvent(staticPublisher: publisher)
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
            bundleProgress: SNTBundleProgress(),
            uiStateCallback: { interval in print("Silence interval was set to \(interval)") }
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

struct ContentView: View {
  var body: some View {
    TabView {
      BinaryView().padding(15.0).tabItem({ Text("Binary") })
      FAAView().padding(15.0).tabItem({ Text("FAA") })
      DeviceView().padding(15.0).tabItem({ Text("Device") })
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
