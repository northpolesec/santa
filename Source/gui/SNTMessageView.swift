import SwiftUI

import santa_common_SNTConfigurator

public let MAX_OUTER_VIEW_WIDTH = 560.0
public let MAX_OUTER_VIEW_HEIGHT = 340.0

extension Date {
  public static var overrideDate: Date = Date()

  public static func now() -> Date {
    return overrideDate
  }
}

public struct SNTMessageView<Content: View>: View {
  let blockMessage: NSAttributedString
  @ViewBuilder let content: Content

  let enableFunFonts: Bool = SNTConfigurator.configurator().funFontsOnSpecificDays

  public init(_ blockMessage: NSAttributedString, @ViewBuilder content: () -> Content) {
    self.content = content()
    self.blockMessage = blockMessage
  }

  func SpecialDateIs(month: Int, day: Int) -> Bool {
    return enableFunFonts
      && Calendar.current.dateComponents([.month, .day], from: Date.now()) == DateComponents(month: month, day: day)
  }

  public var body: some View {
    VStack {
      HStack {
        let image = Image(nsImage: NSImage(named: "MessageIcon") ?? NSImage())
          .resizable()
          .scaledToFill()
          .frame(width: 32, height: 32)
          .saturation(0.9)

        if SpecialDateIs(month: 4, day: 1) {
          image
          Text(verbatim: " Santa ").font(Font.custom("ComicSansMS", size: 34.0))
          image.hidden()
        } else if SpecialDateIs(month: 5, day: 4) {
          // $ is the Rebel Alliance logo in the StarJedi font.
          Text(verbatim: "$  Santa   ").font(Font.custom("StarJedi", size: 34.0))
        } else if SpecialDateIs(month: 10, day: 31) {
          Text(verbatim: "🎃 Santa   ").font(Font.custom("HelveticaNeue-UltraLight", size: 34.0))
        } else {
          image
          Text(verbatim: " Santa ").font(Font.custom("HelveticaNeue-UltraLight", size: 34.0))
          image.hidden()
        }
      }
    }.fixedSize()

    VStack(spacing: 10.0) {
      AttributedText(blockMessage)
        .multilineTextAlignment(.center)
        .padding([.leading, .trailing], 15.0)
        .fixedSize()

      Spacer()

      content
    }
    .padding([.leading, .trailing], 40.0)
    .padding([.bottom], 10.0)
    .frame(maxWidth: MAX_OUTER_VIEW_WIDTH)
  }
}

public let NotificationSilencePeriods: [TimeInterval] = [86400, 604800, 2_678_400]

public struct SNTNotificationSilenceView: View {
  @Binding var silence: Bool
  @Binding var period: TimeInterval

  let dateFormatter: DateComponentsFormatter = {
    let df = DateComponentsFormatter()
    df.unitsStyle = .spellOut
    df.allowedUnits = [.day, .month, .weekOfMonth]
    return df
  }()

  public init(silence: Binding<Bool>, period: Binding<TimeInterval>) {
    _silence = silence
    _period = period
  }

  public var body: some View {
    // Create a wrapper binding around $preventFutureNotificationsPeriod so that we can automatically
    // check the checkbox if the user has selected a new period.
    let pi = Binding<TimeInterval>(
      get: { return period },
      set: {
        silence = true
        period = $0
      }
    )

    Toggle(isOn: $silence) {
      HStack(spacing: 0.0) {
        Text("Prevent future notifications for this application for ").font(Font.system(size: 11.0))
        Picker("", selection: pi) {
          ForEach(NotificationSilencePeriods, id: \.self) { period in
            let text = dateFormatter.string(from: period) ?? "unknown"
            Text(text).font(Font.system(size: 11.0))
          }
        }.fixedSize()
      }
    }
  }
}

public struct ScalingButtonStyle: ButtonStyle {
  public init() {}

  public func makeBody(configuration: Self.Configuration) -> some View {
    configuration.label
      .foregroundColor(.white)
      .cornerRadius(40)
      .scaleEffect(configuration.isPressed ? 0.8 : 0.9)
  }
}

public func MoreDetailsButton(_ showDetails: Binding<Bool>) -> some View {
  Button(action: { showDetails.wrappedValue = true }) {
    HStack(spacing: 2.0) {
      Text("More Details", comment: "More Details button").foregroundColor(.blue)
      Image(systemName: "info.circle").foregroundColor(.blue)
    }
  }
  .buttonStyle(ScalingButtonStyle())
  .keyboardShortcut("m", modifiers: .command)
  .help("⌘ m")
}

public func OpenEventButton(customText: String? = nil, action: @escaping () -> Void) -> some View {
  Button(
    action: action,
    label: {
      let t = customText ?? NSLocalizedString("Open...", comment: "Default text for Open button")
      Text(t).frame(maxWidth: 200.0)
    }
  )
  .keyboardShortcut(.return, modifiers: .command)
  .help("⌘ Return")
}

public func DismissButton(
  customText: String? = nil,
  silence: Bool?,
  action: @escaping () -> Void
)
  -> some View
{
  Button(
    action: action,
    label: {
      let t =
        customText
        ?? (silence ?? false
          ? NSLocalizedString("Dismiss & Silence", comment: "")
          : NSLocalizedString("Dismiss", comment: ""))
      Text(t).frame(maxWidth: 200.0)
    }
  )
  .keyboardShortcut(.escape, modifiers: .command)
  .help("⌘ Esc")
}

// TextWithLimit is like Text() but it supports a limit on the number of characters in the
// string before truncating with an ellipsis. Text() technically handles this by setting
// lineLimit(1) and a maxWidth on frame but if the text is selectable, when selected it
// will expand out of the limits of the frame right up to the edge of the window.
public struct TextWithLimit: View {
  private var text: String
  private var limit: Int

  public init(_ text: String, _ limit: Int = 50) {
    self.text = text
    self.limit = limit
  }

  public var body: some View {
    if self.text.count > self.limit {
      Text(verbatim: self.text.prefix(self.limit) + "…").help(self.text)
    } else {
      Text(self.text)
    }
  }
}

// AttributedText is like Text() but it supports all the features of NSAttributedString()
// by using NSTextField under the hood.
struct AttributedText: NSViewRepresentable {
  private let attributedString: NSAttributedString

  init(_ attributedString: NSAttributedString) {
    self.attributedString = attributedString
  }

  func makeNSView(context: Context) -> NSTextField {
    NSTextField(labelWithAttributedString: self.attributedString)
  }

  func updateNSView(_ textField: NSTextField, context: Context) {}
}
