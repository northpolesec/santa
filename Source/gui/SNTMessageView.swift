import SwiftUI
import LocalAuthentication

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
  let blockMessage: NSAttributedString?
  @ViewBuilder let content: Content

  let enableFunFonts: Bool = SNTConfigurator.configurator().funFontsOnSpecificDays

  public init(_ blockMessage: NSAttributedString? = nil, @ViewBuilder content: () -> Content) {
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
      if let blockMessage = blockMessage {
        AttributedText(blockMessage)
          .multilineTextAlignment(.center)
          .padding([.leading, .trailing], 15.0)
          .fixedSize(horizontal: false, vertical: true)

      }

      Spacer()
      content
    }
    .padding([.leading, .trailing], 40.0)
    .frame(maxWidth: MAX_OUTER_VIEW_WIDTH)

    SNTBrandingView()
      .frame(maxWidth: MAX_OUTER_VIEW_WIDTH)
  }
}

// Special struct to help ensure an image is appropriately sized and
// the bounding box is appropriately limited to the final image size.
struct ConstrainedImage: View {
  let image: NSImage
  let maxWidth: CGFloat
  let maxHeight: CGFloat

  private var constrainedSize: (width: CGFloat, height: CGFloat) {
    let size = image.size
    let aspectRatio = size.width / size.height

    if size.width / maxWidth > size.height / maxHeight {
      // Width is the limiting factor
      let width = min(size.width, maxWidth)
      let height = width / aspectRatio
      return (width, height)
    } else {
      // Height is the limiting factor
      let height = min(size.height, maxHeight)
      let width = height * aspectRatio
      return (width, height)
    }
  }

  var body: some View {
    Image(nsImage: image)
      .resizable()
      .frame(width: constrainedSize.width, height: constrainedSize.height)
  }
}

public struct SNTBrandingView: View {
  let c = SNTConfigurator.configurator()
  @Environment(\.colorScheme) var colorScheme

  @ViewBuilder
  private var brandingContent: some View {
    // Select the appropriate logo based on color scheme
    let logoImage: NSImage? = {
      if colorScheme == .dark, let url = c.brandingCompanyLogoDark {
        return NSImage(contentsOf: url)
      } else if let url = c.brandingCompanyLogo {
        return NSImage(contentsOf: url)
      }
      return nil
    }()

    if let nsi = logoImage {
      ConstrainedImage(image: nsi, maxWidth: 84.0, maxHeight: 28.0)
    } else if let companyName = c.brandingCompanyName {
      TextWithLimit(companyName).font(.footnote).fontWeight(.bold).fixedSize()
    }
  }

  public var body: some View {
    if c.brandingCompanyLogoDark != nil || c.brandingCompanyLogo != nil || c.brandingCompanyName != nil {
      HStack {
        Spacer()
        VStack(spacing: 4.0) {
          Text("Managed by:", comment: "Label shown before company branding").font(.footnote).fixedSize()
          brandingContent
        }
        Spacer()
      }
      .padding(.top, 10.0)
      .padding(.bottom, 28.0)
    } else {
      Spacer()
        .frame(height: 28.0)
    }
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
      HStack(spacing: 5.0) {
        Text("Label before time period picker").font(Font.system(size: 11.0))
        Picker("", selection: pi) {
          ForEach(NotificationSilencePeriods, id: \.self) { period in
            let text = dateFormatter.string(from: period) ?? "unknown"
            Text(text).font(Font.system(size: 11.0))
          }
        }.fixedSize()
        Text("Label after time period picker").font(Font.system(size: 11.0))
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

public func OpenEventButton(
  customText: String? = nil,
  disabled: Bool? = false,
  action: @escaping () -> Void
) -> some View {
  Button(
    action: action,
    label: {
      let t = customText ?? NSLocalizedString("Open...", comment: "Default text for Open button")
      Text(t).frame(maxWidth: 200.0)
    }
  )
  .disabled(disabled ?? false)
  .keyboardShortcut(.return, modifiers: .command)
  .help("⌘ Return")
}

public struct CopyDetailsButton: View {
  let action: () -> Void

  @State private var showCopyConfirmation = false

  public init(action: @escaping () -> Void) {
    self.action = action
  }

  public var body: some View {
    Button(action: {
      action()
      withAnimation {
        showCopyConfirmation = true
      }

      // Hide after 1 second
      DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
        withAnimation {
          showCopyConfirmation = false
        }
      }
    }) {
      HStack(spacing: 2.0) {
        Text("Copy Details", comment: "Copy Details")
          .foregroundColor(.blue)

        Image(systemName: "pencil.and.list.clipboard")
          .foregroundColor(.blue)

        // Reserve space for the checkmark to maintain consistent width
        ZStack {
          // Invisible placeholder with the same size as the checkmark
          Image(systemName: "checkmark.circle.fill")
            .foregroundColor(.clear)

          // Actual checkmark that appears and fades
          if showCopyConfirmation {
            Image(systemName: "checkmark.circle.fill")
              .foregroundColor(.blue)
              .transition(.opacity)
          }
        }
      }
    }
    .buttonStyle(ScalingButtonStyle())
    .keyboardShortcut("c", modifiers: [.command, .shift])
    .help("⇧ ⌘  c")
  }
}

@objc public class SNTAuthorizationHelper: NSObject {
  @objc public static func authorizeTemporaryMonitorMode(replyBlock: @escaping (Bool) -> Void) {
    let format = NSLocalizedString(
      "authorize temporary Monitor Mode",
      comment: "Authorize temporary Monitor Mode exception"
    )

    AuthorizeViaTouchID(reason: format, replyBlock: replyBlock)
  }
}

public func AuthorizeViaTouchID(reason: String, replyBlock: @escaping (Bool) -> Void) {
  let policy: LAPolicy =
    SNTConfigurator.configurator().enableStandalonePasswordFallback
    ? .deviceOwnerAuthentication : .deviceOwnerAuthenticationWithBiometrics

  LAContext().evaluatePolicy(policy, localizedReason: reason) { success, error in
    if error != nil {
      replyBlock(false)
    } else {
      replyBlock(success)
    }
  }
}

// CanAuthorizeWithTouchID checks if TouchID is available on the current device
// and returns an error if it is not.
public func CanAuthorizeWithTouchID() -> (Bool, NSError?) {
  let context = LAContext()
  var error: NSError?

  let policy: LAPolicy =
    SNTConfigurator.configurator().enableStandalonePasswordFallback
    ? .deviceOwnerAuthentication : .deviceOwnerAuthenticationWithBiometrics

  if context.canEvaluatePolicy(policy, error: &error) {
    return (true, nil)
  } else {
    return (false, error)
  }
}

// StandaloneButton is only used in Standalone mode. It's a replacement for the
// Open event button.
//
// It is intended to be used for all approvals in the future if in standalone
// mode.
public func StandaloneButton(action: @escaping () -> Void) -> some View {
  Button(
    action: action,
    label: {
      Text(NSLocalizedString("Approve", comment: "Default text for Approve")).frame(maxWidth: 200.0)
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
      let truncatedText = "\(self.text.prefix(self.limit/2))…\(self.text.suffix(self.limit/2))"
      Text(verbatim: truncatedText).help(self.text)
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

  func makeNSView(context: Context) -> TextFieldWithCursors {
    TextFieldWithCursors(labelWithAttributedString: self.attributedString)
  }

  func updateNSView(_ textView: TextFieldWithCursors, context: Context) {
    textView.maximumNumberOfLines = 15
    textView.translatesAutoresizingMaskIntoConstraints = false
    textView.allowsEditingTextAttributes = true
    textView.isSelectable = true
    textView.isEditable = false
  }
}

class TextFieldWithCursors: NSTextField {
  override func resetCursorRects() {
    super.resetCursorRects()

    let attributedString = self.attributedStringValue
    attributedString.enumerateAttribute(
      .link,
      in: NSRange(location: 0, length: attributedString.length),
      options: [],
      using: { value, range, stop in
        if value != nil {
          let textStorage = NSTextStorage(attributedString: attributedString)
          let layoutManager = NSLayoutManager()

          textStorage.addLayoutManager(layoutManager)

          let textContainer = NSTextContainer(size: bounds.size)
          textContainer.lineFragmentPadding = 0.0
          layoutManager.addTextContainer(textContainer)

          var glyphRange = NSRange()

          // Convert the range for glyphs.
          layoutManager.characterRange(forGlyphRange: range, actualGlyphRange: &glyphRange)

          let rect = layoutManager.boundingRect(forGlyphRange: glyphRange, in: textContainer)

          // Set the cursor to a pointing hand where this link is.
          addCursorRect(rect, cursor: NSCursor.pointingHand)
        }
      }
    )
  }
}
