/// Copyright 2026 North Pole Security, Inc.
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

struct Fido2PromptContent: View {
  let detail: String
  let offerTouchID: Bool
  let onCancel: () -> Void
  let onTouchID: () -> Void

  var body: some View {
    SNTMessageView {
      VStack(spacing: 12) {
        HStack(spacing: 16) {
          Image(systemName: "key.fill")
            .font(.system(size: 32, weight: .medium))
            .foregroundStyle(.secondary)
            .frame(width: 48, height: 48)

          VStack(alignment: .leading, spacing: 6) {
            Text(
              NSLocalizedString("Touch your security key", comment: "Security key prompt title")
            )
            .font(.system(size: 16, weight: .bold))

            Text(detail)
              .font(.system(size: 13))
              .foregroundStyle(.secondary)
          }
        }

        ProgressView()
          .controlSize(.small)
          .padding(.bottom, 8)

        HStack(spacing: 15.0) {
          Button(action: onCancel) {
            Text(NSLocalizedString("Cancel", comment: "Cancel button")).frame(maxWidth: 120)
          }
          .keyboardShortcut(.escape, modifiers: [])

          if offerTouchID {
            Button(action: onTouchID) {
              Text(
                NSLocalizedString(
                  "Use Touch ID Instead",
                  comment: "Switch from security key to Touch ID"
                )
              ).frame(maxWidth: 160)
            }
          }
        }
      }
      .padding(.vertical, 20)
      .padding(.horizontal, 40)
    }
  }
}

/// Factory callable from Objective-C to create the SwiftUI prompt as an NSViewController.
@objc public class SNTFido2PromptViewFactory: NSObject {
  @objc public static func makePromptViewController(
    detail: String,
    offerTouchID: Bool,
    onCancel: @escaping () -> Void,
    onTouchID: @escaping () -> Void
  ) -> NSViewController {
    return NSHostingController(
      rootView: Fido2PromptContent(
        detail: detail,
        offerTouchID: offerTouchID,
        onCancel: onCancel,
        onTouchID: onTouchID
      )
    )
  }
}
