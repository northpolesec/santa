import ArgumentParser
import Foundation

import santa_common_MOLXPCConnection
import santa_common_SNTXPCControlInterface
import santa_common_SNTCommonEnums
import santa_common_SNTFileInfo
import santa_common_SigningIDHelpers

extension Santactl {
  struct Rule: ParsableCommand {

    private enum IdentifierType: String, EnumerableFlag {
      case binary
      case certificate
      case cdhash
      case signingid
      case teamid
    }

    private enum Policy: String, EnumerableFlag {
      case allow
      case block
      case silentBlock
      case compiler
      case remove
      case check
      case `import`
      case export
    }

    static let configuration = CommandConfiguration(
      abstract: "Manually add/remove/check rules."
    )

    /// Options

    @Flag(help: "The type of identifier to use for the rule.")
    private var identifierType: IdentifierType = .binary

    // One of these is required
    @Flag(help: "The policy to apply to the rule.")
    private var policy: Policy = .allow
    @Option(help: "A CEL expression to evaluate for this rule.")
    var cel: String?

    // One of these is required
    @Option var identifier: String?
    @Option var path: String?

    #if DEBUG
    @Flag var force: Bool = false
    #endif

    /// State

    var fileInfo: SNTFileInfo?

    var rulePolicy: SNTRuleState = .allow

    private enum CodingKeys: String, CodingKey {
      case identifierType, policy, cel, identifier, path
    }

    mutating func validate() throws {
      if identifier?.isEmpty ?? true && path?.isEmpty ?? true {
        throw ValidationError("One of --identifier or --path is required")
      }
      if !(identifier?.isEmpty ?? true) && !(path?.isEmpty ?? true) {
        throw ValidationError("Only one of --identifier or --path can be provided")
      }

      if path != nil {
        fileInfo = try SNTFileInfo(path: path!, error: ())
        if fileInfo?.path()?.isEmpty ?? true {
          throw ValidationError("Path is not a regular file: \(path!)")
        }

        let csc = try fileInfo?.codesignChecker()

        switch identifierType {
        case .binary:
          identifier = fileInfo?.sha256()
        case .certificate:
          identifier = csc?.leafCertificate?.sha256
        case .cdhash:
          identifier = csc?.cdhash
        case .signingid:
          identifier = FormatSigningID(csc)
        case .teamid:
          identifier = csc?.teamID
        }
      }

      switch policy {
      case .allow:
        rulePolicy = .allow
      case .block:
        rulePolicy = .block
      case .silentBlock:
        rulePolicy = .silentBlock
      case .compiler:
        rulePolicy = .allowCompiler
      case .remove:
        rulePolicy = .remove
      case .check:
        break
      case .import:
        break
      case .export:
        break
      }
      if cel != nil {
        rulePolicy = .CEL
      }
    }

    mutating func run() {
      print("identifierType: \(identifierType)")
      print("policy: \(policy)")
      print("cel: \(cel ?? "None")")
      print("identifier: \(identifier ?? "None")")
      print("path: \(path ?? "None")")

      print("rulePolicy: \(rulePolicy)")
    }
  }
}
