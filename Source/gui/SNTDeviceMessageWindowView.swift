/// Copyright 2023 Google LLC
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

import santa_common_SNTBlockMessage
import santa_common_SNTConfigBundle
import santa_common_SNTDeviceEvent
import santa_gui_SNTMessageView

@objc public class SNTDeviceMessageWindowViewFactory: NSObject {
  @objc public static func createWith(
    window: NSWindow,
    event: SNTDeviceEvent,
    configBundle: SNTConfigBundle,
    silenceable: Bool,
    uiStateCallback: ((TimeInterval) -> Void)?
  ) -> NSViewController {
    return NSHostingController(
      rootView: SNTDeviceMessageWindowView(
        window: window,
        event: event,
        configBundle: configBundle,
        silenceable: silenceable,
        uiStateCallback: uiStateCallback
      ).fixedSize()
    )
  }
}

struct SNTDeviceMessageWindowView: View {
  let window: NSWindow?
  let event: SNTDeviceEvent
  let configBundle: SNTConfigBundle
  let silenceable: Bool
  let uiStateCallback: ((TimeInterval) -> Void)?

  @State public var preventFutureNotifications = false
  @State public var preventFutureNotificationPeriod: TimeInterval = NotificationSilencePeriods[0]

  var body: some View {
    SNTMessageView(SNTBlockMessage.attributedBlockMessage(for: event)) {
      HStack(spacing: 20.0) {
        VStack(alignment: .trailing, spacing: 10.0) {
          Text("Path").bold().font(Font.system(size: 12.0))

          if event.remountArgs?.count ?? 0 > 0 {
            Text("Remount Mode").bold().font(Font.system(size: 12.0))
          }
        }

        Divider()

        VStack(alignment: .leading, spacing: 10.0) {
          TextWithLimit(event.mntonname)

          if event.remountArgs?.count ?? 0 > 0 {
            TextWithLimit(event.readableRemountArgs())
          }
        }
      }

      if configBundle.notificationSilencesEnabled() && silenceable {
        SNTNotificationSilenceView(
          silence: $preventFutureNotifications,
          period: $preventFutureNotificationPeriod,
          labelBefore: Text("Label before time period picker (mount)"),
          labelAfter: Text("Label after time period picker (mount)")
        )
      }

      Spacer()

      HStack(spacing: 15.0) {
        DismissButton(customText: nil, silence: preventFutureNotifications, action: dismissButton)
      }

      Spacer()
    }.fixedSize()
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
