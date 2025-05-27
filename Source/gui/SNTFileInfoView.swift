import SwiftUI

import santa_common_SigningIDHelpers
import santa_common_MOLCodesignChecker
import santa_common_SNTFileInfo
import santa_gui_SNTMessageView

@objc public class SNTFileInfoViewFactory: NSObject {
  @objc public static func createWith(fileInfo: SNTFileInfo) -> NSViewController {
    return NSHostingController(
      rootView: FileInfoView(fileInfo: fileInfo).fixedSize()
    )
  }
}

public struct FileInfoView: View {
  let fileInfo: SNTFileInfo
  let csc: MOLCodesignChecker?
  let cscError: NSError?

  public init(fileInfo: SNTFileInfo) {
    self.fileInfo = fileInfo
    do {
      self.csc = try fileInfo.codesignChecker()
      self.cscError = nil
    } catch let error as NSError {
      self.csc = nil
      self.cscError = error
    }
  }

  func copyDetailsToClipboard() {
    var s = "File info for \(self.fileInfo.bundleName() ?? "an application:")"
    s += "\nSHA-256  : \(fileInfo.sha256() ?? "Unknown")"
    s += "\nSHA-1    : \(fileInfo.sha1() ?? "Unknown")"
    if let csc = csc {
      s += "\nSigningID: \(FormatSigningID(csc) ?? "Unknown")"

      if let cdhash = csc.cdhash {
        s += "\nCDHash   : \(cdhash)"
      }

      if let teamID = csc.teamID {
        s += "\nTeam ID  : \(teamID)"
      }
    }
    s += "\nSigned   : \(fileInfo.codesignStatus() ?? "Unknown")"

    let pasteboard = NSPasteboard.general
    pasteboard.clearContents()
    pasteboard.setString(s, forType: .string)
  }

  public var body: some View {
    VStack(spacing: 10.0) {
      VStack(alignment: .leading, spacing: 5.0) {
        Text("Path").bold().padding(.top, 15.0)
        TextWithLimit(fileInfo.path()).font(Font.system(size: 12.0).monospaced()).textSelection(.enabled)

        Text(verbatim: "SHA-256").bold().padding(.top, 15.0)
        Text(fileInfo.sha256()).font(Font.system(size: 12.0).monospaced()).textSelection(.enabled)

        Text(verbatim: "SHA-1").bold().padding(.top, 15.0)
        Text(fileInfo.sha1()).font(Font.system(size: 12.0).monospaced()).textSelection(.enabled)

        if let csc = csc {
          Text("Signing ID").bold().padding(.top, 15.0)
          Text(FormatSigningID(csc) ?? "Unknown").font(Font.system(size: 12.0).monospaced()).textSelection(.enabled)

          if let cdhash = csc.cdhash {
            Text("CDHash").bold().padding(.top, 15.0)
            Text(cdhash).font(Font.system(size: 12.0).monospaced()).textSelection(.enabled)
          }

          if let teamID = csc.teamID {
            Text("Team ID").bold().padding(.top, 15.0)
            Text(teamID).font(Font.system(size: 12.0).monospaced()).textSelection(.enabled)
          }
        }

        Text("Signed").bold().padding(.top, 15.0)
        Text(fileInfo.codesignStatus()).font(Font.system(size: 12.0).monospaced()).textSelection(.enabled)
      }

      CopyDetailsButton(action: copyDetailsToClipboard)

      DismissButton(
        customText: nil,
        silence: false,
        action: {
          NSApp.keyWindow?.close()
        }
      )
    }.padding(15.0)
  }
}
