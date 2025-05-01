import SwiftUI

import santa_common_SNTConfigurator
import santa_gui_SNTMessageView

@objc public class SNTAboutWindowViewFactory: NSObject {
  @objc public static func createWith(window: NSWindow) -> NSViewController {
    return NSHostingController(
      rootView: SNTAboutWindowView(w: window).fixedSize()
    )
  }
}

struct SNTAboutWindowView: View {
  let w: NSWindow?
  let c = SNTConfigurator.configurator()
  let v = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "unknown"

  var body: some View {
    SNTMessageView() {
      if let t = c.aboutText {
        Text(t).multilineTextAlignment(.center)
      } else {
        Text(
          """
          Santa is a security system providing application,
          device, and file-access controls.
          """,
          comment: "Explanation in About view"
        ).multilineTextAlignment(.center)
      }

      // Calling .init explicitly to get Markdown rendering
      let versionString = NSLocalizedString("Version **%@**", comment: "Version in About view")
      Text(.init(String(format: versionString, v))).padding(10.0)

      HStack {
        if c.moreInfoURL?.absoluteString.isEmpty == false {
          Button(action: moreInfoButton) {
            Text("More Info...").frame(width: 90.0)
          }
        }

        Button(action: dismissButton) {
          Text("Dismiss").frame(width: 90.0)
        }
        .keyboardShortcut(.defaultAction)

      }.padding(10.0)

      Text(
        """
        Santa is made with ❤️ by the elves at [North Pole Security](https://northpole.security)
        along with contributions from our wonderful community
        """
      )
      .font(.system(size: 10.0, weight: .regular))
      .padding([.bottom], 10.0)
      .foregroundColor(.secondary)
      .multilineTextAlignment(.center)
      .padding(10.0)
    }
  }

  func dismissButton() {
    w?.close()
  }

  func moreInfoButton() {
    if let u = c.moreInfoURL {
      NSWorkspace.shared.open(u)
    }
    w?.close()
  }
}

// Enable previews in Xcode.
struct SNTAboutWindow_Previews: PreviewProvider {
  static var previews: some View {
    SNTAboutWindowView(w: nil)
  }
}
