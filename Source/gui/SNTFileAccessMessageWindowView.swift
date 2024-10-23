/// Copyright 2023 Google LLC
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

import SecurityInterface
import SwiftUI

import santa_common_SNTFileAccessEvent

@available(macOS 13, *)
@objc public class SNTFileAccessMessageWindowViewFactory : NSObject {
  @objc public static func createWith(window: NSWindow,
                                      event: SNTFileAccessEvent,
                                      customMessage: NSAttributedString?,
                                      customURL: NSString?,
                                      customText: NSString?,
                                      uiStateCallback: ((TimeInterval) -> Void)?) -> NSViewController {
    return NSHostingController(rootView:SNTFileAccessMessageWindowView(window:window,
                                                                       event:event,
                                                                       customMessage:customMessage,
                                                                       customURL:customURL as String?,
                                                                       customText:customText as String?,
                                                                       uiStateCallback:uiStateCallback)
      .frame(width:800, height:600))
  }
}

@available(macOS 13, *)
struct Property : View {
  var lbl: String
  var val: String
  var propertyAction: (() -> Void)? = nil

  var body: some View {
    let width: CGFloat? = 150

    HStack(spacing: 5) {
      HStack {
        if let block = propertyAction {
          Button(action: {
            block()
          }) {
            Image(systemName: "info.circle.fill")
          }.buttonStyle(BorderlessButtonStyle())
        }
        Text(lbl + ":")
          .frame(alignment: .trailing)
          .lineLimit(1)
          .font(.system(size: 12, weight: .bold))
          .padding(Edge.Set.horizontal, 10)
      }.frame(width: width, alignment: .trailing)

      Text(val)
        .fixedSize(horizontal: false, vertical: true)
        .frame(minWidth: 0, maxWidth: .infinity, alignment: .leading)
    }

  }
}

@available(macOS 13, *)
struct Event: View {
  let e: SNTFileAccessEvent
  let window: NSWindow?

  var body: some View {
    VStack(spacing:10) {
      Property(lbl: "Path Accessed", val: e.accessedPath)
      Property(lbl: "Rule Name", val: e.ruleName)
      Property(lbl: "Rule Version", val: e.ruleVersion)

      Divider()
        .frame(width: 700)

      if let app = e.application {
        Property(lbl: "Application", val: app)
      }

      if let pub = e.publisherInfo {
        Property(lbl: "Publisher", val: pub) {
          SFCertificatePanel.shared()
                .beginSheet(for: window,
                            modalDelegate: nil,
                            didEnd: nil,
                            contextInfo: nil,
                            certificates: e.signingChainCertRefs,
                            showGroup: true)
        }
      }

      Property(lbl: "Name", val: (e.filePath as NSString).lastPathComponent)
      Property(lbl: "Path", val: e.filePath)
      Property(lbl: "Identifier", val: e.fileSHA256)
      Property(lbl: "Parent", val: e.parentName + " (" + e.ppid.stringValue + ")")
    }
  }
}

@available(macOS 13, *)
struct SNTFileAccessMessageWindowView: View {
  let window: NSWindow?
  let event: SNTFileAccessEvent?
  let customMessage: NSAttributedString?
  let customURL: String?
  let customText: String?
  let uiStateCallback: ((TimeInterval) -> Void)?

  @Environment(\.openURL) var openURL

  let preventNotificationPeriods: [TimeInterval] = [86400, 604800, 2678400]
  @State public var preventFutureNotifications = false
  @State public var preventFutureNotificationPeriod: TimeInterval = 86400

  let dateFormatter : DateComponentsFormatter = {
    let df = DateComponentsFormatter()
    df.unitsStyle = .spellOut
    df.allowedUnits = [.day, .month, .weekOfMonth]
    return df
  }()

  var body: some View {
    VStack(spacing:20.0) {
      Spacer()
      Text("Santa").font(Font.custom("HelveticaNeue-UltraLight", size: 34.0))

      if let msg = customMessage {
        Text(AttributedString(msg)).multilineTextAlignment(.center).padding(15.0)
      } else {
        Text("Access to a protected resource was denied.").multilineTextAlignment(.center).padding(15.0)
      }

      Event(e: event!, window: window)

      // TODO: Make a shared view component for this "prevent notifications" checkbox and picker, as it's
      // useful in multiple views.
      // Create a wrapper binding around $preventFutureNotificationsPeriod so that we can automatically
      // check the checkbox if the user has selected a new period.
      let pi = Binding<TimeInterval>(get: { return self.preventFutureNotificationPeriod }, set: {
        self.preventFutureNotifications = true
        self.preventFutureNotificationPeriod = $0
      })

      Toggle(isOn: $preventFutureNotifications) {
        HStack(spacing:0.0) {
          Text("Prevent future notifications for this application for ").font(Font.system(size: 11.0));
          Picker("", selection: pi) {
            ForEach(preventNotificationPeriods, id: \.self) { period in
              let text = dateFormatter.string(from: period) ?? "unknown"
              Text(text).font(Font.system(size: 11.0))
            }
          }.fixedSize()
        }
      }.padding(10.0)

      VStack(spacing:15) {
          if customURL != nil {
            Button(action: openButton, label: {

              Text(customText ?? "Open Event...").frame(maxWidth:.infinity)
            })
            .buttonStyle(.borderedProminent)
            .keyboardShortcut(.defaultAction)
          }
          Button(action: dismissButton, label: {
            Text("Dismiss").frame(maxWidth:.infinity)
          })
          .keyboardShortcut(.return)
      }.frame(width: 220)

      Spacer()

    }.frame(maxWidth:800.0).fixedSize()
  }

  func openButton() {
    guard let urlString = customURL else {
      print("No URL available")
      return
    }

    guard let url = URL(string: urlString) else {
      print("Failed to create URL")
      return
    }

    openURL(url)
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

@available(macOS 13, *)
func testFileAccessEvent() -> SNTFileAccessEvent {
  let faaEvent = SNTFileAccessEvent()

  faaEvent.accessedPath = "/accessed/path"
  faaEvent.ruleVersion = "watched_path.v1"
  faaEvent.ruleName = "watched_path"
  faaEvent.fileSHA256 = "b7c1e3fd640c5f211c89b02c2c6122f78ce322aa5c56eb0bb54bc422a8f8b670"
  faaEvent.filePath = "/Applications/gShoe.app/Contents/MacOS/gShoe"
  faaEvent.application = "gShoe"
  faaEvent.teamID = "ZMCG7MLDV9"
  faaEvent.signingID = "com.northpolesec.gShoe"
  faaEvent.executingUser = "nobody"
  faaEvent.pid = 456
  faaEvent.ppid = 123
  faaEvent.parentName = "gLauncher"

  return faaEvent
}

// Enable previews in Xcode.
@available(macOS 13, *)
struct SNTFileAccessMessageWindowView_Previews: PreviewProvider {
  static var previews: some View {
    SNTFileAccessMessageWindowView(window: nil,
                                    event: testFileAccessEvent(),
                            customMessage: nil,
                                customURL: nil,
                               customText: nil,
                          uiStateCallback: nil)
  }
}
