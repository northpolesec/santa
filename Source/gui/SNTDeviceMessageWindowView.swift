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

import SwiftUI

import santa_common_SNTBlockMessage
import santa_common_SNTConfigurator
import santa_common_SNTDeviceEvent
import santa_gui_SNTMessageView

@objc public class SNTDeviceMessageWindowViewFactory : NSObject {
  @objc public static func createWith(window: NSWindow, event: SNTDeviceEvent) -> NSViewController {
    return NSHostingController(rootView:SNTDeviceMessageWindowView(window:window, event:event).fixedSize())
  }
}

struct SNTDeviceMessageWindowView: View {
  let window: NSWindow?
  let event: SNTDeviceEvent?

  var body: some View {
    SNTMessageView(SNTBlockMessage.attributedBlockMessage(for:event)) {
      HStack(spacing: 20.0) {
        VStack(alignment:.trailing, spacing:10.0) {
          Text("Device Name").bold().font(Font.system(size:12.0))
          Text("Device BSD Path").bold().font(Font.system(size:12.0))

          if event!.remountArgs?.count ?? 0 > 0 {
            Text("Remount Mode").bold().font(Font.system(size:12.0))
          }
        }

        Divider()

        VStack(alignment:.leading, spacing:10.0) {
          Text(event!.mntonname)
          Text(event!.mntfromname)

          if event!.remountArgs?.count ?? 0 > 0 {
            Text(event!.readableRemountArgs())
          }
        }
      }

      Spacer()

      HStack(spacing:15.0) {
        DismissButton(customText: nil, silence: nil, action: dismissButton)
      }

      Spacer()
    }.fixedSize()
  }

  func dismissButton() {
    window?.close()
  }
}
