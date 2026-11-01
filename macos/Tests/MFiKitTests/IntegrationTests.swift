import XCTest
import CryptoKit
@testable import MFiKit

/// Optional run against a real identity directory:
///
///     MFI_IDENTITY_DIR=/path/to/mfi DEVELOPER_DIR=... swift test
///
/// Skipped when the variable is unset, so the hermetic tests stay the default.
final class IntegrationTests: XCTestCase {
    func testRealIdentitySignsAndCompletesHandshake() throws {
        guard let path = ProcessInfo.processInfo.environment["MFI_IDENTITY_DIR"] else {
            throw XCTSkip("MFI_IDENTITY_DIR not set")
        }
        let identity = try MFiIdentity(directory: URL(fileURLWithPath: path))
        XCTAssertEqual(identity.protocolMajor, 3)

        let signature = try identity.selfTest()
        XCTAssertEqual(signature.count, 64)

        let events = try SimulatedPhone.run(identity: identity)
        XCTAssertTrue(events.contains { $0.text.contains("verifies") })

        // The identity recovered from DiPlay 0.2.22 (spec/01). If this folder holds
        // that container, its hash must match the one recorded here.
        if identity.certificate.count == 607 {
            let hex = SHA256.hash(data: identity.certificate).map { String(format: "%02x", $0) }.joined()
            XCTAssertEqual(String(hex.prefix(8)), "634a93dd", "certificate container hash drifted")
        }
    }
}
