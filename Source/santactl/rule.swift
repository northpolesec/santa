/// Copyright 2025 North Pole Security, Inc.
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
///
import ArgumentParser
import Foundation

import santa_common_MOLXPCConnection
import santa_common_SNTCommonEnums
import santa_common_SNTConfigurator
import santa_common_SNTFileInfo
import santa_common_SNTRule
import santa_common_SNTRuleIdentifiers
import santa_common_SNTXPCControlInterface
import santa_common_SigningIDHelpers

extension Santactl {
  struct Rule: ParsableCommand {
    static let configuration = CommandConfiguration(
      abstract: "Manually add/remove/check rules.",
      discussion: """
        This command requires root privileges and cannot be used if Santa is
        configured to use a sync server.

        Notes:
          The format of `identifier` when adding/checking a SigningID rules is:

              TeamID:SigningID`

          Because signing IDs are controlled by the binary author, this ensures that
          the signing ID is properly scoped to the developer. For the special case of
          platform binaries, `TeamID` should be replaced with the string "platform"
          (e.g. `platform:SigningID`). This allows for rules targeting Apple-signed
          binaries that do not have a TeamID.

        Import / Export:
          If Santa is not configured to use a sync server, one can export & import
          rules to and from JSON files using the --export and --import flags.
          The format of these files is:

          {
            "rules": [
              {
                "identifier": "...",
                "message": "...",
                "policy": "...",
              }
            ]
          }

          Fields that are not populated will not be included in the output.

          By default, existing rules are not cleared when importing. To clear the
          database you must use either --clean or --clean-all as appropriate.
        """
    )

    enum IdentifierType: String, EnumerableFlag {
      case binary = "Binary SHA-256"
      case certificate = "Certificate SHA-256"
      case cdhash = "CDHash"
      case signingid = "SigningID"
      case teamid = "TeamID"
    }
    @Flag(help: "The type of identifier to use for the rule.")
    var identifierType: IdentifierType = .binary

    enum Policy: String, EnumerableFlag {
      case allow
      case block
      case silentBlock
      case compiler
      case remove
      case check
    }
    @Flag(help: "The policy to apply to the rule.")
    var policy: Policy?

    @Option(help: "A CEL expression to evaluate for this rule. Overrides the specified policy.")
    var cel: String?

    // One of these is required
    @Option var identifier: String?

    @Option(completion: .file()) var path: String?

    @Option(help: "A custom message to show when the binary is blocked.")
    var message: String?

    @Option(help: "A comment to add to the rule.")
    var comment: String?

    @Option(
      name: .customLong("import"),
      help: "The path to the rule file to import. Use '-' for stdin.",
      completion: .file()
    )
    var importPath: String?

    @Option(
      name: .customLong("export"),
      help: "The path to the rule file to export. Use '-' for stdout.",
      completion: .file()
    )
    var exportPath: String?

    @Flag(help: "Clear all existing non-transitive rules before importing.")
    var clean: Bool = false

    @Flag(help: "Clear all existing rules before importing.")
    var cleanAll: Bool = false

    #if DEBUG
    @Flag var force: Bool = false
    #endif

    var proxy: SNTDaemonControlXPC? {
      get {
        return privilegedDaemonConn()
      }
    }

    mutating func validate() throws {
      if !isRunningTests() {
        try requireRoot()
        try requireNotManaged()

        if proxy == nil {
          throw ValidationError("Failed to get privileged daemon connection")
        }
      }

      if identifier?.isEmpty ?? true && path?.isEmpty ?? true && importPath?.isEmpty ?? true
        && exportPath?.isEmpty ?? true
      {
        throw ValidationError("One of --identifier, --path, --import, or --export is required")
      }

      if !(identifier?.isEmpty ?? true) && !(path?.isEmpty ?? true) && !(importPath?.isEmpty ?? true)
        && !(exportPath?.isEmpty ?? true)
      {
        throw ValidationError("Only one of --identifier, --path, --import, or --export can be provided")
      }

      if clean && cleanAll {
        throw ValidationError("Only one of --clean or --cleanAll can be provided")
      }

      if (clean || cleanAll) && importPath == "" {
        throw ValidationError("The --clean and --cleanAll flags only work with --import")
      }

      if path != nil {
        let fileInfo = try SNTFileInfo(path: path!, error: ())
        if fileInfo.path()?.isEmpty ?? true {
          throw ValidationError("Path is not a regular file: \(path!)")
        }
        try processFromFileInfo(fi: fileInfo)
      }

      if importPath == nil && exportPath == nil && policy != .check && rulePolicy() == .unknown {
        throw ValidationError("No policy or CEL expression specified")
      }
    }

    func requireNotManaged() throws {
      if SNTConfigurator().syncBaseURL?.absoluteString.isEmpty ?? true {
        return
      }
      #if DEBUG
      if force {
        return
      }
      #endif
      throw ValidationError("SyncBaseURL/StaticRules is set, rules are managed centrally.")
    }

    func ruleType() -> SNTRuleType {
      switch identifierType {
      case .binary:
        return .binary
      case .certificate:
        return .certificate
      case .cdhash:
        return .cdHash
      case .signingid:
        return .signingID
      case .teamid:
        return .teamID
      }
    }

    func rulePolicy() -> SNTRuleState {
      if cel != nil {
        return .CEL
      }
      switch policy {
      case .allow:
        return .allow
      case .block:
        return .block
      case .silentBlock:
        return .silentBlock
      case .compiler:
        return .allowCompiler
      case .remove:
        return .remove
      default:
        return .unknown
      }
    }

    mutating func processFromFileInfo(fi: SNTFileInfo) throws {
      let csc = try fi.codesignChecker()

      switch identifierType {
      case .binary:
        identifier = fi.sha256()
      case .certificate:
        identifier = csc.leafCertificate?.sha256
      case .cdhash:
        identifier = csc.cdhash
      case .signingid:
        identifier = FormatSigningID(csc)
      case .teamid:
        identifier = csc.teamID

      }

      if identifier == nil {
        throw ValidationError("Failed to get \(identifierType.rawValue) identifier from file")
      }
    }

    func run() throws {
      switch true {
      case importPath != nil:
        try importRules(importPath!)
      case exportPath != nil:
        try exportRules(exportPath!)
      case policy == .check:
        try checkRule()
      default:
        try addRule()
      }
    }

    func addRule() throws {
      let rule = try SNTRule(
        identifier: identifier,
        state: rulePolicy(),
        type: ruleType(),
        customMsg: message,
        customURL: nil,
        timestamp: 0,
        comment: comment,
        celExpr: cel,
      )

      var error: Error?
      proxy!.databaseRuleAddRules([rule], ruleCleanup: .none, source: .santactl) { outError in
        error = outError
      }
      if let error = error {
        throw ValidationError("Failed to add rule: \(error)")
      }
      print("Added rule for \(identifierType.rawValue): \(rule.identifier ?? "")")
    }

    func checkRule() throws {
      let ruleIdentifiers = SNTRuleIdentifiers(
        binarySHA256: identifierType == .binary ? identifier : nil,
        certificateSHA256: identifierType == .certificate ? identifier : nil,
        cdhash: identifierType == .cdhash ? identifier : nil,
        signingID: identifierType == .signingid ? identifier : nil,
        teamID: identifierType == .teamid ? identifier : nil,
        signingStatus: .production,
      )

      proxy!.databaseRule(for: ruleIdentifiers) { rule in
        if let rule = rule {
          print(rule.stringify(withColor: isatty(STDOUT_FILENO) == 1) ?? "None")
        } else {
          print("No rule found for \(identifierType.rawValue): \(identifier ?? "")")
        }
      }
    }

    func importRules(_ importPath: String) throws {
      let data = try Data(contentsOf: URL(fileURLWithPath: importPath))

      guard
        let json = try JSONSerialization.jsonObject(
          with: data,
          options: []
        ) as? [String: [[AnyHashable: Any]]]
      else {
        throw ValidationError("Failed to parse JSON")
      }

      let parsedRules = try json["rules"]?.map { rule in
        try SNTRule(dictionary: rule)
      }
      guard let parsedRules = parsedRules else {
        throw ValidationError("Failed to parse rules")
      }

      let cleanup: SNTRuleCleanup =
        switch (clean, cleanAll) {
        case (true, false):
          .nonTransitive
        case (false, true):
          .all
        case (true, true):
          .all
        default:
          .none
        }

      var error: Error?
      proxy!.databaseRuleAddRules(parsedRules, ruleCleanup: cleanup, source: .santactl) { outError in
        error = outError
      }
      if let error = error {
        throw ValidationError("Failed to add rules: \(error)")
      }
      print("Imported \(parsedRules.count) rules")
    }

    func exportRules(_ exportPath: String) throws {
      var rules: [SNTRule]?
      var error: Error?

      proxy!.retrieveAllRules() { outRules, outError in
        rules = outRules
        error = outError
      }

      if let error = error {
        throw ValidationError("Failed to retrieve rules: \(error)")
      }

      if rules?.count ?? 0 == 0 {
        print("No rules to export.")
        return
      }

      // Create an output stream to the specified path.
      // If the path is "-", use stdout.
      func outputStream() throws -> OutputStream {
        let path = exportPath == "-" ? "/dev/stdout" : exportPath
        guard let stream = OutputStream(toFileAtPath: path, append: false) else {
          throw ValidationError("Failed to create output stream")
        }
        stream.open()
        return stream
      }

      // Filter out irrelevant rules and convert each rule to its dictionary representation.
      let rulesArray = rules!.filter { $0.state != .allowTransitive }.map { return $0.dictionaryRepresentation() }

      var nsError: NSError?
      JSONSerialization.writeJSONObject(
        ["rules": rulesArray],
        to: try outputStream(),
        options: [.prettyPrinted, .sortedKeys],
        error: &nsError
      )
      if let error = nsError {
        throw error
      }

      if exportPath != "-" {
        print("Exported \(rulesArray.count) rules to \(exportPath)")
      }
    }
  }
}
