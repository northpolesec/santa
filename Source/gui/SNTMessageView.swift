import SwiftUI

public let MAX_OUTER_VIEW_WIDTH = 560.0
public let MAX_OUTER_VIEW_HEIGHT = 340.0

public struct SNTMessageView<Content: View>: View {
  let blockMessage: NSAttributedString
  @ViewBuilder let content: Content

  public init(_ blockMessage: NSAttributedString, @ViewBuilder content: () -> Content) {
    self.content = content()
    self.blockMessage = blockMessage
  }

  public var body: some View {
    VStack(spacing: 10.0) {
      HStack {
        ZStack {
          Image(nsImage: NSImage(named: "AppIcon") ?? NSImage())
            .resizable()
            .frame(maxWidth: 32, maxHeight: 32)
            .offset(x: -75)
          Text(verbatim: "Santa").font(Font.custom("HelveticaNeue-UltraLight", size: 34.0))
        }
      }

      Spacer()

      Text(AttributedString(blockMessage))
        .multilineTextAlignment(.center)
        .padding([.leading, .trailing], 15.0)
        .fixedSize()

      Spacer()

      content
    }
    .padding([.leading, .trailing], 40.0)
    .padding([.top, .bottom], 10.0)
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
      let t = customText ?? String(localized: "Open...")
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
