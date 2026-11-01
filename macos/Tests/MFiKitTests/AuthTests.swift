import XCTest
import CryptoKit
@testable import MFiKit

final class AuthTests: XCTestCase {
    // MARK: - Fixture

    /// Writes a throw-away P-256 PKCS#8 identity into a temporary directory.
    static func makeIdentity() throws -> (MFiIdentity, URL) {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("mfikit-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        let key = P256.Signing.PrivateKey()
        try key.derRepresentation.write(to: directory.appendingPathComponent(MFiIdentity.identityFile))
        // The certificate is opaque to this layer; a marker blob is enough to prove
        // it is returned byte for byte.
        let certificate = Data((0..<97).map { UInt8($0 & 0xFF) })
        try certificate.write(to: directory.appendingPathComponent(MFiIdentity.certificateFile))

        return (try MFiIdentity(directory: directory), directory)
    }

    func testIdentityLoadsAndSelfTests() throws {
        let (identity, directory) = try Self.makeIdentity()
        defer { try? FileManager.default.removeItem(at: directory) }

        XCTAssertEqual(identity.protocolMajor, 3)
        let signature = try identity.selfTest()
        XCTAssertEqual(signature.count, 64)

        let digest = Data(repeating: 0x11, count: 32)
        let signed = try identity.sign(digest: digest)
        XCTAssertTrue(identity.verify(digest: digest, signature: signed))
        XCTAssertFalse(identity.verify(digest: Data(repeating: 0x12, count: 32), signature: signed))
    }

    func testSignatureIsRawRSAndRoundTripsThroughDER() throws {
        let (identity, directory) = try Self.makeIdentity()
        defer { try? FileManager.default.removeItem(at: directory) }

        let digest = Data(repeating: 0x5A, count: 32)
        let raw = try identity.sign(digest: digest)
        XCTAssertEqual(raw.count, 64)

        let der = MFiIdentity.derSignature(fromRaw: raw)
        XCTAssertNotNil(der)
        XCTAssertEqual(MFiIdentity.rawSignature(fromDER: der!), raw)
    }

    func testMissingIdentityFilesAreReported() throws {
        let empty = FileManager.default.temporaryDirectory
            .appendingPathComponent("mfikit-empty-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: empty, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: empty) }

        XCTAssertThrowsError(try MFiIdentity(directory: empty)) { error in
            guard case MFiIdentityError.missingFile = error as! MFiIdentityError else {
                return XCTFail("unexpected error \(error)")
            }
        }
    }

    // MARK: - Responder

    func testResponderAnswersCertificateAndChallenge() throws {
        let (identity, directory) = try Self.makeIdentity()
        defer { try? FileManager.default.removeItem(at: directory) }

        let responder = IAP2AuthResponder(identity: identity)

        let certificateReply = try XCTUnwrap(responder.handle(CSMFrame(messageID: AccAuth.requestCertificate)))
        let certificateFrame = try Self.singleFrame(certificateReply)
        XCTAssertEqual(certificateFrame.messageID, AccAuth.certificate)
        XCTAssertEqual(certificateFrame.parameter(0), identity.certificate)

        let digest = Data(repeating: 0x33, count: 32)
        let challenge = try CSM.frame(
            messageID: AccAuth.requestChallenge,
            parameters: [CSMParameter(id: 0, payload: digest)]
        )
        let signatureReply = try XCTUnwrap(responder.handle(try Self.singleFrame(challenge)))
        let signatureFrame = try Self.singleFrame(signatureReply)
        XCTAssertEqual(signatureFrame.messageID, AccAuth.response)
        let signature = try XCTUnwrap(signatureFrame.parameter(0))
        XCTAssertEqual(signature.count, 64)
        XCTAssertTrue(identity.verify(digest: digest, signature: signature))
    }

    func testResponderReportsFailureAndSuccess() throws {
        let (identity, directory) = try Self.makeIdentity()
        defer { try? FileManager.default.removeItem(at: directory) }

        let responder = IAP2AuthResponder(identity: identity)
        XCTAssertThrowsError(try responder.handle(CSMFrame(messageID: AccAuth.failed))) { error in
            XCTAssertEqual("\(error)", IAP2AuthError.authenticationFailed.description)
        }
        XCTAssertNil(try responder.handle(CSMFrame(messageID: AccAuth.succeeded)))
        XCTAssertTrue(responder.isComplete)
    }

    func testResponderRejectsOversizedChallenge() throws {
        let (identity, directory) = try Self.makeIdentity()
        defer { try? FileManager.default.removeItem(at: directory) }

        let responder = IAP2AuthResponder(identity: identity)
        let challenge = try CSM.frame(
            messageID: AccAuth.requestChallenge,
            parameters: [CSMParameter(id: 0, payload: Data(repeating: 0xAB, count: 129))]
        )
        XCTAssertThrowsError(try responder.handle(try Self.singleFrame(challenge)))
    }

    func testResponderRejectsUnknownMessage() throws {
        let (identity, directory) = try Self.makeIdentity()
        defer { try? FileManager.default.removeItem(at: directory) }

        let responder = IAP2AuthResponder(identity: identity)
        XCTAssertThrowsError(try responder.handle(CSMFrame(messageID: 0xAA06)))
    }

    // MARK: - Simulated phone

    func testSimulatedHandshakeCompletes() throws {
        let (identity, directory) = try Self.makeIdentity()
        defer { try? FileManager.default.removeItem(at: directory) }

        let events = try SimulatedPhone.run(identity: identity)
        XCTAssertFalse(events.isEmpty)
        XCTAssertTrue(events.contains { $0.text.contains("certificate returned byte for byte") })
        XCTAssertTrue(events.contains { $0.text.contains("verifies") })
        XCTAssertTrue(events.contains { $0.text.contains("complete:") })
    }

    // MARK: - Helpers

    static func singleFrame(_ data: Data) throws -> CSMFrame {
        var decoder = CSMDecoder()
        let frames = decoder.push(data)
        return try XCTUnwrap(frames.first)
    }
}
