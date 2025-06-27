import XCTest

@testable import santactl

import santa_common_SNTRule

final class RuleTests: XCTestCase {
  func testAddBinaryRule() throws {
    let c = try XCTUnwrap(
      Santactl.parseAsRoot(["rule", "--identifier", "1234567890", "--allow", "--binary"])
        as? Santactl.Rule
    )
    XCTAssertEqual(c.identifier, "1234567890")
    XCTAssertEqual(c.identifierType, .binary)
    XCTAssertEqual(c.rulePolicy(), .allow)
  }

  func testAddCertificateRule() throws {
    let c = try XCTUnwrap(
      Santactl.parseAsRoot(["rule", "--identifier", "1234567890", "--block", "--certificate"])
        as? Santactl.Rule
    )
    XCTAssertEqual(c.identifier, "1234567890")
    XCTAssertEqual(c.identifierType, .certificate)
    XCTAssertEqual(c.rulePolicy(), .block)
  }

  func testAddCDHashRuleWithCEL() throws {
    let c = try XCTUnwrap(
      Santactl.parseAsRoot(["rule", "--identifier", "1234567890", "--cdhash", "--cel", "true"])
        as? Santactl.Rule
    )
    XCTAssertEqual(c.identifier, "1234567890")
    XCTAssertEqual(c.identifierType, .cdhash)
    XCTAssertEqual(c.rulePolicy(), .CEL)
    XCTAssertEqual(c.cel, "true")
  }

  func testAddDuplicateTypes() throws {
    XCTAssertThrowsError(
      try Santactl.parseAsRoot(["rule", "--identifier", "1234567890", "--block", "--binary", "--certificate"])
    )
  }

  func testAddDuplicatePolicies() throws {
    XCTAssertThrowsError(
      try Santactl.parseAsRoot(["rule", "--identifier", "1234567890", "--binary", "--allow", "--block"])
    )
  }

  func testAddPathAndIdentifier() throws {
    XCTAssertThrowsError(
      try Santactl.parseAsRoot(["rule", "--identifier", "1234567890", "--path", "/bin/ls", "--binary"])
    )
  }

  func testMissingIdentifierPathImportExport() throws {
    XCTAssertThrowsError(
      try Santactl.parseAsRoot(["rule", "--allow", "--binary"])
    )
  }

  func testCleanWithoutImport() throws {
    XCTAssertThrowsError(
      try Santactl.parseAsRoot(["rule", "--clean"])
    )
  }

  func testCleanAndCleanAll() throws {
    XCTAssertThrowsError(
      try Santactl.parseAsRoot(["rule", "--import", "test.json", "--clean", "--cleanAll"])
    )
  }
}
