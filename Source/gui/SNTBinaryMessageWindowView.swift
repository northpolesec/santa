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

import santa_common_CertificateHelpers
import santa_common_SNTBlockMessage
import santa_common_SNTConfigurator
import santa_common_SNTStoredEvent

let MAX_OUTER_VIEW_WIDTH = 560.0
let MAX_OUTER_VIEW_HEIGHT = 340.0
let MAX_BUTTON_AREA_WIDTH = 300.0

@objc public class SNTBinaryMessageWindowViewFactory : NSObject {
  @objc public static func createWith(window: NSWindow,
                                      event: SNTStoredEvent,
                                      customMsg: NSString?,
                                      customURL: NSString?,
                                      uiStateCallback: ((TimeInterval) -> Void)?) -> NSViewController {
    return NSHostingController(rootView:SNTBinaryMessageWindowView(
      window:window,
      event:event,
      customMsg:customMsg,
      customURL:customURL,
      uiStateCallback:uiStateCallback).frame(
        minWidth:MAX_OUTER_VIEW_WIDTH,
        minHeight:MAX_OUTER_VIEW_HEIGHT).fixedSize())
  }
}

struct ScalingButtonStyle: ButtonStyle {
  func makeBody(configuration: Self.Configuration) -> some View {
      configuration.label
          .foregroundColor(.white)
          .cornerRadius(40)
          .scaleEffect(configuration.isPressed ? 0.8 : 0.9)
  }
}

func copyDetailsToClipboard(e: SNTStoredEvent?, customURL: String?) {
  var s = "Santa blocked \(e?.fileBundleName ?? "an application:")"
  if let publisher = Publisher(e?.signingChain, e?.teamID) {
    s += "\nPublisher: \(publisher)"
  }
  s += "\nUser     : \(e?.executingUser ?? "unknown")"
  s += "\nPath     : \(e?.filePath ?? "unknown")"

  if let signingID = e?.signingID {
    s += "\nSigningID: \(signingID)"
  }
  if let cdhash = e?.cdhash {
    s += "\nCDHash   : \(cdhash)"
  }
  s += "\nSHA-256  : \(e?.fileSHA256 ?? "unknown")"
  s += "\nParent   : \(e?.parentName ?? "") (\(String(format: "%d", e?.ppid.intValue ?? 0)))"

  let url = SNTBlockMessage.eventDetailURL(for:e, customURL:customURL as String?)
  s += "\nURL      : \(url?.absoluteString ?? "unknown")"
  s += "\n"

  let pasteboard = NSPasteboard.general
  pasteboard.clearContents()
  pasteboard.setString(s, forType: .string)
}

struct SNTBinaryMessageEventExpandedView: View {
  let e: SNTStoredEvent?
  let customURL: NSString?

  @Environment(\.presentationMode) var presentationMode

  func addLabel(@ViewBuilder closure: () -> some View) -> some View {
    HStack(spacing:5.0) {
      VStack(alignment:.leading, spacing:2.0) {
        closure()
      }.frame(alignment:.leading)
      Spacer()
    }.frame(width:MAX_OUTER_VIEW_WIDTH - 60).fixedSize()
  }

  var body: some View {
    HStack(spacing: 20.0) {
      VStack(spacing: 20.0) {
        Spacer()

        addLabel {
          Text("Path").bold().font(Font.system(size:12.0))
          Text(e?.filePath ?? "unknown").textSelection(.enabled)
        }

        Divider()

        if let signingID = e?.signingID {
          addLabel {
            Text("Signing ID").bold().font(Font.system(size:12.0))
            Text(signingID).font(Font.system(size:12.0).monospaced()).textSelection(.enabled)
          }
          Divider()
        }


        if let cdHash = e?.cdhash {
          addLabel {
            Text("CDHash").bold().font(Font.system(size:12.0))
            Text(cdHash).font(Font.system(size:12.0).monospaced()).textSelection(.enabled)
          }
          Divider()
        }

        addLabel {
          Text("SHA-256").bold().font(Font.system(size:12.0))
          // Fix the max width of this to 240px so that the SHA-256 splits across 2 lines evenly.
          Text(e?.fileSHA256 ?? "unknown").font(Font.system(size:12.0).monospaced()).frame(width:240).textSelection(.enabled)
        }

        Divider()

        addLabel {
            Text("Parent").bold().font(Font.system(size:12.0))
            Text(verbatim: "\(e?.parentName ?? "") (\(String(format: "%d", e?.ppid.intValue ?? 0)))").textSelection(.enabled)
        }

        Spacer()


      HStack {
        Button(action: { copyDetailsToClipboard(e:e, customURL:customURL as String?) }) {
          HStack(spacing:2.0) {
            Text("Copy Details", comment:"Copy Details button in more details dialog").foregroundColor(.blue)
            Image(systemName:"pencil.and.list.clipboard").foregroundColor(.blue)
          }
        }
        .buttonStyle(ScalingButtonStyle())
        .keyboardShortcut("d", modifiers: .command)
        .help("⌘ d")


        Button(action: { presentationMode.wrappedValue.dismiss() }) {
          HStack(spacing:2.0) {
            Text("Dismiss", comment:"Dismiss button in more details dialog").foregroundColor(.blue)
            Image(systemName:"xmark.circle").foregroundColor(.blue)
          }
        }
        .buttonStyle(ScalingButtonStyle())
        .keyboardShortcut(.escape, modifiers: .command)
        .help("⌘ Esc")
      }

        Spacer()
      }.frame(maxWidth:MAX_OUTER_VIEW_WIDTH - 20).fixedSize()
    }.frame(width:MAX_OUTER_VIEW_WIDTH - 20).fixedSize().background(Color.gray.opacity(0.2))
  }
}

struct SNTBinaryMessageEventView: View {
  let e: SNTStoredEvent? 
  let customURL: NSString?

  @State private var isShowingDetails = false

  var body: some View {
    Spacer()

    HStack(spacing: 20.0) {
      VStack(alignment:.trailing, spacing:10.0) {
        /*
        if e?.needsBundleHash ?? false {
          Text("Bundle Hash")
        }
        */

        if e?.fileBundleName != "" {
          Text("Application").bold().font(Font.system(size:12.0))
        } else if e?.filePath != "" {
          Text("Filename").bold().font(Font.system(size:12.0))
        }

        if Publisher(e?.signingChain, e?.teamID) != nil {
          Text("Publisher").bold().font(Font.system(size:12.0))
        }

        Text("User").bold().font(Font.system(size:12.0))
      }

      Divider()

      VStack(alignment:.leading, spacing:10.0) {
        /*
        if e?.needsBundleHash ?? false {
          // TODO: Implement bundle hashing
          ProgressView()

          /*
            To be implemented in the near future...

            if (!self.event.needsBundleHash) {
              [self.bundleHashLabel removeFromSuperview];
              [self.hashingIndicator removeFromSuperview];
              [self.foundFileCountLabel removeFromSuperview];
            } else {
              self.openEventButton.enabled = NO;
              self.hashingIndicator.indeterminate = YES;
              [self.hashingIndicator startAnimation:self];
              self.bundleHashLabel.hidden = YES;
              self.foundFileCountLabel.stringValue = @"";
            }
          */
        }
        */

        if let bundleName = e?.fileBundleName {
          Text(bundleName).textSelection(.enabled)
        } else if let filePath = e?.filePath {
          Text((filePath as NSString).lastPathComponent).textSelection(.enabled)
        }

        if let publisher = Publisher(e?.signingChain, e?.teamID) {
          Text(publisher).textSelection(.enabled)
        }

        Text(e?.executingUser ?? "").textSelection(.enabled)
      }
    }.sheet(isPresented: $isShowingDetails) {
      SNTBinaryMessageEventExpandedView(e: e, customURL:customURL)
    }

    ZStack {
      Button(action: { isShowingDetails = true }) {
        HStack(spacing:2.0) {
          Text("More Details", comment:"More Details button in binary block dialog").foregroundColor(.blue)
          Image(systemName:"info.circle").foregroundColor(.blue)
        }
      }
      .buttonStyle(ScalingButtonStyle())
      .keyboardShortcut("m", modifiers: .command)
      .help("⌘ m")

      // This button is hidden and exists only to allow using the Cmd+D keyboard shortcut
      // to copy the event details to the clipboard even if the "More Details" button hasn't been pressed.
      Button(action: { copyDetailsToClipboard(e:e, customURL:customURL as String?) }) { Text(verbatim:"Copy Details") }
      .buttonStyle(ScalingButtonStyle())
      .opacity(0.0) // Invisible!
      .keyboardShortcut("d", modifiers: .command)
      .help("⌘ d")
    }
  }

}

struct SNTBinaryMessageWindowView: View {
  let window: NSWindow?
  let event: SNTStoredEvent?
  let customMsg: NSString?
  let customURL: NSString?
  let uiStateCallback: ((TimeInterval) -> Void)?

  let c = SNTConfigurator()

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
    VStack(spacing:15.0) {
      HStack {
        ZStack {
          Image(nsImage: NSImage(named: "AppIcon") ?? NSImage())
              .resizable()
              .frame(maxWidth:32, maxHeight:32)
              .offset(x:-75)
              .saturation(0.5)
          Text(verbatim: "Santa").font(Font.custom("HelveticaNeue-UltraLight", size: 34.0))
        }
      }

      Spacer()

      let blockMessage = SNTBlockMessage.attributedBlockMessage(for:event, customMessage:customMsg as String?)
      Text(AttributedString(blockMessage)).multilineTextAlignment(.center).frame(maxWidth:MAX_OUTER_VIEW_WIDTH - 60).fixedSize()

      SNTBinaryMessageEventView(e: event!, customURL: customURL)

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

      HStack(spacing:15.0) {
        if c.eventDetailURL != nil {
          Button(action: openButton, label: {
            if let edt = c.eventDetailText {
              Text(edt).frame(maxWidth:MAX_BUTTON_AREA_WIDTH / 2)
            } else {
              Text("Open...").frame(maxWidth:MAX_BUTTON_AREA_WIDTH / 2)
            }
          })
          .buttonStyle(.borderedProminent)
          .keyboardShortcut("\r", modifiers:.command)
          .help("⌘ ⏎")
        }

        Button(action: dismissButton, label: {
          if let dmt = c.dismissText {
            Text(dmt).frame(maxWidth:MAX_BUTTON_AREA_WIDTH / 2)
          } else {
            if self.preventFutureNotifications {
              Text("Dismiss & Silence").frame(maxWidth:MAX_BUTTON_AREA_WIDTH / 2)
            } else {
              Text("Dismiss").frame(maxWidth:MAX_BUTTON_AREA_WIDTH / 2)
            }
          }
        })
        .keyboardShortcut(.escape, modifiers:.command)
        .help("⌘ Esc")
      }.frame(maxWidth:MAX_BUTTON_AREA_WIDTH)

      Spacer()
    }.frame(maxWidth:MAX_OUTER_VIEW_WIDTH, minHeight:MAX_OUTER_VIEW_HEIGHT).fixedSize()
  }

  func openButton() {
    if let callback = uiStateCallback {
      if self.preventFutureNotifications {
        callback(self.preventFutureNotificationPeriod)
      } else {
        callback(0)
      }
    }

    let url = SNTBlockMessage.eventDetailURL(for:event, customURL:customURL as String?)
    window?.close()
    if let url = url {
      NSWorkspace.shared.open(url)
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
