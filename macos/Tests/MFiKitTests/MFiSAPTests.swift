import XCTest
import CryptoKit
@testable import MFiKit

final class MFiSAPTests: XCTestCase {
    func testAuthSetupAnswersAPeerAndProvesTheKey() throws {
        let (identity, directory) = try AuthTests.makeIdentity()
        defer { try? FileManager.default.removeItem(at: directory) }

        let peer = Curve25519.KeyAgreement.PrivateKey()
        let request = Data([1]) + peer.publicKey.rawRepresentation

        let result = try XCTUnwrap(try MFiSAP.authSetup(identity: identity, request: request))
        let response = result.response

        // public (32) + u32 + cert + u32 + enc
        XCTAssertEqual(response.count, 32 + 4 + identity.certificate.count + 4 + 64)
        XCTAssertEqual(Data(response.prefix(32)), result.publicKey)

        // Reproduce the accessory side from the peer's view and check the signature.
        let shared = try peer.sharedSecretFromKeyAgreement(
            with: Curve25519.KeyAgreement.PublicKey(rawRepresentation: result.publicKey)
        )
        let sharedBytes = shared.withUnsafeBytes { Data($0) }
        let key = Data(Insecure.SHA1.hash(data: Data("AES-KEY".utf8) + sharedBytes).prefix(16))
        let iv = Data(Insecure.SHA1.hash(data: Data("AES-IV".utf8) + sharedBytes).prefix(16))

        let decrypted = try MFiSAP.aesCTR(key: key, iv: iv, input: result.encryptedSignature)
        XCTAssertEqual(decrypted.count, 64)

        let digest = Data(SHA256.hash(data: result.publicKey + peer.publicKey.rawRepresentation))
        // AES-CTR is symmetric, so re-encrypting the plaintext reproduces the ciphertext.
        XCTAssertTrue(identity.verify(digest: digest, signature: decrypted))
    }

    func testAuthSetupRejectsShortAndWrongVersionRequests() throws {
        let (identity, directory) = try AuthTests.makeIdentity()
        defer { try? FileManager.default.removeItem(at: directory) }

        XCTAssertNil(try MFiSAP.authSetup(identity: identity, request: Data([1, 2, 3])))
        let peer = Curve25519.KeyAgreement.PrivateKey()
        XCTAssertNil(try MFiSAP.authSetup(identity: identity, request: Data([9]) + peer.publicKey.rawRepresentation))
    }
}
