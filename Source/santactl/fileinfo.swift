import ArgumentParser
import Foundation

import santa_common_CertificateHelpers
import santa_common_MOLCertificate
import santa_common_MOLCodesignChecker
import santa_common_SNTFileInfo
import santa_common_SNTRule
import santa_common_SigningIDHelpers
import santa_common_SNTRuleIdentifiers

extension Santactl {
  struct Fileinfo: ParsableCommand {
    static let configuration = CommandConfiguration(
      abstract: "Prints information about a file."
    )

    @Argument(help: "The path to the file to get information about.")
    var path: String?

    @Flag(help: "Show entitlements")
    var entitlements: Bool = false

    @Flag(help: "Show JSON output")
    var json: Bool = false

    func validate() throws {
    }

    mutating func run() {
      // TODO: Implement JSON output, filtering, other flags.

      guard let fileInfo = try? SNTFileInfo(path: path, error: ()) else {
        print("Failed to get file info")
        return
      }

      let dateFormatter = DateFormatter()
      dateFormatter.timeZone = TimeZone(secondsFromGMT: 0)
      dateFormatter.dateFormat = "yyyy/MM/dd HH:mm:ss Z"

      let proxy = daemonConn()

      var csc: MOLCodesignChecker?
      var cscError: Error?
      do {
        csc = try fileInfo.codesignChecker()
      } catch {
        cscError = error
      }

      let signingStatus = SigningStatus(csc, cscError)

      print("Path                : \(fileInfo.path()!)")
      print("SHA-256             : \(fileInfo.sha256()!)")
      print("SHA-1               : \(fileInfo.sha1()!)")

      // Bundle Info
      if fileInfo.bundleName() != nil {
        print("Bundle Name         : \(fileInfo.bundleName()!)")
        print("Bundle Version      : \(fileInfo.bundleVersion()!)")
        print("Bundle Short Version: \(fileInfo.bundleShortVersionString()!)")
      }

      // Identifiers from code signature
      print("Team ID             : \(csc?.teamID ?? "None")")
      print("Signing ID          : \(FormatSigningID(csc) ?? "None")")
      if csc?.cdhash.isEmpty ?? true {
        print("CDHash              : None")
      } else {
        print("CDHash              : \(csc?.cdhash ?? "None")")
      }

      // Type
      let archs = fileInfo.architectures()!
      if archs.count > 0 {
        print("Type                : \(fileInfo.humanReadableFileType()!) (\(archs.joined(separator: ", ")))")
      } else {
        print("Type                : \(fileInfo.humanReadableFileType()!)")
      }

      if fileInfo.isMissingPageZero() {
        print("Page Zero           : Yes")
      }

      // Code-signed
      print("Code-signed         : \(fileInfo.codesignStatus()!)")

      print(
        "Secure Signing Time : \(csc?.secureSigningTime != nil ? dateFormatter.string(from:csc!.secureSigningTime!) : "None")"
      )
      print("Signing Time        : \(csc?.signingTime != nil ? dateFormatter.string(from:csc!.signingTime!) : "None")")

      if proxy != nil {
        let ruleIdentifiers = SNTRuleIdentifiers(
          binarySHA256: fileInfo.sha256(),
          certificateSHA256: csc?.leafCertificate?.sha256,
          cdhash: csc?.cdhash,
          signingID: FormatSigningID(csc),
          teamID: csc?.teamID,
          signingStatus: signingStatus,
        )

        proxy?.databaseRule(for: ruleIdentifiers) { rule in
          print("Rule                : \(rule?.stringify(withColor:isatty(STDOUT_FILENO) == 1) ?? "None")")
        }
      }

      if entitlements {
        if let entitlements = csc?.entitlements {
          printEntitlements(entitlements)
        } else {
          print("Entitlements        : None")
        }
      }

      if let csc = csc {
        print("Signing Chain:")
        for (index, cert) in csc.certificates.enumerated() {
          printCertificate(cert: cert as! MOLCertificate, index: index + 1)
        }
      }
    }

    private func printCertificate(cert: MOLCertificate, index: Int) {
      print("    \(index). SHA-256             : \(cert.sha256!)")
      print("       SHA-1               : \(cert.sha1!)")
      print("       Common Name         : \(cert.commonName!)")
      print("       Organization        : \(cert.orgName!)")
      print("       Organizational Unit : \(cert.orgUnit!)")
      print("       Valid From          : \(cert.validFrom!)")
      print("       Valid Until         : \(cert.validUntil!)")
      print("")
    }

    private func printEntitlements(_ entitlements: [String: Any]) {
      print("Entitlements        :")

      var index = 0
      for (key, value) in entitlements.sorted(by: { $0.0 < $1.0 }) {
        index += 1

        let indexStr = String(format: " %2d", index)

        if let value = value as? Bool {
          if value {
            print("  \(indexStr). \(key)")
          }
        } else {
          print("  \(indexStr). \(key): \(value)")
        }
      }
    }
  }
}
