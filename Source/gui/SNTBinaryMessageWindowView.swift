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

@objc public class SNTBinaryMessageWindowViewFactory : NSObject {
  @objc public static func createWith(window: NSWindow,
                                      event: SNTStoredEvent,
                                      customMsg: NSString?,
                                      customURL: NSString?,
                                      uiStateCallback: ((Bool) -> Void)?) -> NSViewController {
    return NSHostingController(rootView:SNTBinaryMessageWindowView(
      window:window, event:event, customMsg:customMsg, customURL:customURL, uiStateCallback:uiStateCallback).frame(minWidth:520, minHeight:540).fixedSize())
  }
}

struct SNTBinaryMessageEventView: View {
  let e: SNTStoredEvent? 

  func addLabel(@ViewBuilder closure: () -> some View) -> some View {
    HStack(spacing:5.0) {
      VStack(alignment:.leading, spacing:2.0) {
        closure()
      }.frame(alignment:.leading)
      Spacer()
    }.frame(width:400).fixedSize()
  }

  var body: some View {
    VStack(spacing: 20.0) {
      Spacer()

      if e!.needsBundleHash {
        addLabel() {
          Text("Bundle Hash").bold().font(Font.system(size:12.0))
          ProgressView()
        }
      }

      if let bundleName = e?.fileBundleName {
        addLabel() {
          Text("Application").bold().font(Font.system(size:12.0))
          Text(bundleName)
        }
      }

      addLabel() {
        Text("Filename").bold().font(Font.system(size:12.0))
        Text(e?.filePath ?? "unknown")
      }

      if let publisher = Publisher(e?.signingChain, e?.teamID) {
        addLabel() {
          Text("Publisher").bold().font(Font.system(size:12.0))
          Text(publisher)
        }
      }

      addLabel {
        if let signingID = e?.signingID {
          Text("Signing ID").bold().font(Font.system(size:12.0))
          Text(signingID).font(Font.system(size:12.0).monospaced())
        } else if let sha256 = e?.fileSHA256 {
          Text("SHA-256").bold().font(Font.system(size:12.0))
          Text(sha256).font(Font.system(size:12.0).monospaced()).frame(width:240)
        }
      }

      addLabel {
          Text("Parent").bold().font(Font.system(size:12.0))
          Text("\(e?.parentName ?? "") (\(String(format: "%d", e?.ppid.intValue ?? 0)))")
      }

      addLabel {
        Text("User").bold().font(Font.system(size:12.0))
        Text(e?.executingUser ?? "")
      }

      Spacer()
    }
  }
}

struct SNTBinaryMessageWindowView: View {
  let window: NSWindow?
  let event: SNTStoredEvent?
  let customMsg: NSString?
  let customURL: NSString?
  let uiStateCallback: ((Bool) -> Void)?

  let c = SNTConfigurator()

  @State public var checked = false

  var body: some View {
    VStack(spacing:15.0) {
      Spacer()

      Text("Santa").font(Font.custom("HelveticaNeue-UltraLight", size: 34.0))

      Text(AttributedString(SNTBlockMessage.attributedBlockMessage(for:event, customMessage:customMsg as String?)))

      SNTBinaryMessageEventView(e: event!)

      Toggle(isOn: $checked) {
        Text("Prevent future notifications for this application for a day").font(Font.system(size: 11.0));
      }

      HStack(spacing:15) {
        if c.eventDetailURL != nil {
          Button(action: openButton, label: {
            if let edt = c.eventDetailText {
              Text(edt).frame(maxWidth:150.0)
            } else {
              Text("Open...")
            }
          })
          .buttonStyle(.borderedProminent)
          .keyboardShortcut(KeyboardShortcut("\r", modifiers:.command))
        }
        Button(action: dismissButton, label: {
          if let dmt = c.dismissText {
            Text(dmt).frame(maxWidth:150.0)
          } else {
            Text("Dismiss").frame(maxWidth:150.0)
          }
        })
      }.frame(maxWidth:300.0)

      Spacer()
      Spacer()
    }.frame(maxWidth:600.0, minHeight:400.0).fixedSize()
  }

  func openButton() {
    if let callback = uiStateCallback {
      callback(self.checked)
    }

    let url = SNTBlockMessage.eventDetailURL(for:event, customURL:customURL as String?)
    window?.close()
    if let url = url {
      NSWorkspace.shared.open(url)
    }
  }

  func dismissButton() {
    if let callback = uiStateCallback {
      callback(self.checked)
    }
    window?.close()
  }
}
