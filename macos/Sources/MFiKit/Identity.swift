import Foundation
import CryptoKit
import Security

/// Errors raised while loading or using an MFi identity.
public enum MFiIdentityError: Error, CustomStringConvertible {
    case missingFile(String)
    case unsupportedKey(String)
    case signing(String)

    public var description: String {
        switch self {
        case .missingFile(let name):
            return "missing \(name)"
        case .unsupportedKey(let reason):
            return "unsupported key: \(reason)"
        case .signing(let reason):
            return "signing failed: \(reason)"
        }
    }
}

/// The accessory identity: `identity.pk8` (unencrypted PKCS#8) and
/// `certificate.p7b` (the PKCS#7 container presented to the phone byte for byte).
///
/// This is the same contract the C library and LIVI implement: P-256 keys sign a
/// 32-byte digest with raw `r||s` output and report protocol major 3.
public struct MFiIdentity {
    public static let identityFile = "identity.pk8"
    public static let certificateFile = "certificate.p7b"
    public static let protocolMajorEC: UInt8 = 3

    public let directory: URL
    /// Opaque PKCS#7 bytes, sent as parameter 0 of `0xAA01`.
    public let certificate: Data
    public let protocolMajor: UInt8

    private let p256: P256.Signing.PrivateKey
    private let secKey: SecKey

    public init(directory: URL) throws {
        self.directory = directory

        let certURL = directory.appendingPathComponent(Self.certificateFile)
        let keyURL = directory.appendingPathComponent(Self.identityFile)
        guard let certificate = try? Data(contentsOf: certURL) else {
            throw MFiIdentityError.missingFile(certURL.path)
        }
        guard let der = try? Data(contentsOf: keyURL) else {
            throw MFiIdentityError.missingFile(keyURL.path)
        }

        // CryptoKit parses the unencrypted PKCS#8 wrapper directly. A key it cannot
        // parse is an RSA or encrypted identity, which this build does not sign with.
        let key: P256.Signing.PrivateKey
        do {
            key = try P256.Signing.PrivateKey(derRepresentation: der)
        } catch {
            throw MFiIdentityError.unsupportedKey("not an unencrypted P-256 PKCS#8 key (\(error))")
        }

        // Security.framework is the only raw-digest signer on the system: CryptoKit's
        // signature API hashes its input, and both MFi paths sign a digest that is
        // already final. x9.63 private = 0x04 || X || Y || K.
        let x963 = key.publicKey.x963Representation + key.rawRepresentation
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
        ]
        var error: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateWithData(x963 as CFData, attributes as CFDictionary, &error) else {
            let reason = error?.takeRetainedValue().localizedDescription ?? "SecKeyCreateWithData"
            throw MFiIdentityError.unsupportedKey(reason)
        }

        self.certificate = certificate
        self.protocolMajor = Self.protocolMajorEC
        self.p256 = key
        self.secKey = secKey
    }

    /// Convenience for the default staging directory.
    public static var defaultDirectory: URL {
        FileManager.default
            .homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/CarPlayDesk/mfi", isDirectory: true)
    }

    public var publicKey: SecKey? { SecKeyCopyPublicKey(secKey) }

    /// Sign a final digest. MFi signs the challenge as-is: no re-hash, raw `r||s`.
    public func sign(digest: Data) throws -> Data {
        guard digest.count == 32 else {
            throw MFiIdentityError.signing("P-256 signs a 32-byte digest, got \(digest.count)")
        }
        var error: Unmanaged<CFError>?
        guard let der = SecKeyCreateSignature(
            secKey,
            .ecdsaSignatureDigestX962SHA256,
            digest as CFData,
            &error
        ) as Data? else {
            let reason = error?.takeRetainedValue().localizedDescription ?? "SecKeyCreateSignature"
            throw MFiIdentityError.signing(reason)
        }
        guard let raw = Self.rawSignature(fromDER: der) else {
            throw MFiIdentityError.signing("cannot unwrap the DER signature")
        }
        return raw
    }

    /// Verify a raw `r||s` signature over a final digest (used by the self-test and
    /// by the simulated phone).
    public func verify(digest: Data, signature: Data) -> Bool {
        guard let publicKey, let der = Self.derSignature(fromRaw: signature) else { return false }
        var error: Unmanaged<CFError>?
        return SecKeyVerifySignature(
            publicKey,
            .ecdsaSignatureDigestX962SHA256,
            digest as CFData,
            der as CFData,
            &error
        )
    }

    /// Sign and verify a fixed digest: an identity that fails this cannot answer a
    /// real phone either.
    @discardableResult
    public func selfTest() throws -> Data {
        let digest = Data(repeating: 0x5A, count: 32)
        let signature = try sign(digest: digest)
        guard verify(digest: digest, signature: signature) else {
            throw MFiIdentityError.signing("signature did not verify against its own key")
        }
        return signature
    }

    /// Stable AirPlay device identifier, derived from the certificate so it needs no
    /// hardware access (macOS redacts interface MACs from `getifaddrs` in this
    /// process: every address reads back as 02:00:…).
    public var airPlayDeviceID: String {
        let digest = SHA256.hash(data: certificate)
        var bytes = Array(digest.prefix(6))
        bytes[0] = (bytes[0] & 0xFC) | 0x02   // locally administered, unicast
        return bytes.map { String(format: "%02x", $0) }.joined(separator: ":")
    }

    /// Human-readable facts for the UI and the logs.
    public func summary() -> String {
        let hash = SHA256.hash(data: certificate)
        let hex = hash.map { String(format: "%02x", $0) }.joined()
        // Hash of the PKCS#7 container as shipped; spec/01 records the hash of the
        // DER certificate inside it, which is a different object.
        return "certificate container \(certificate.count) bytes, sha256 \(hex.prefix(16))…, protocol major \(protocolMajor)"
    }

    // MARK: - DER <-> raw

    /// ECDSA signatures on the wire are DER (0x30 …); MFi wants 64 bytes `r||s`.
    public static func rawSignature(fromDER der: Data) -> Data? {
        let bytes = [UInt8](der)
        guard bytes.count >= 8, bytes[0] == 0x30 else { return nil }

        var index = 1
        guard let bodyLength = derLength(bytes, &index), index + bodyLength <= bytes.count else { return nil }

        guard let r = derInteger(bytes, &index), let s = derInteger(bytes, &index) else { return nil }
        guard r.count <= 32, s.count <= 32 else { return nil }
        return Data(leftPad(r, 32) + leftPad(s, 32))
    }

    public static func derSignature(fromRaw raw: Data) -> Data? {
        guard raw.count == 64 else { return nil }
        let r = derIntegerBody(Array(raw.prefix(32)))
        let s = derIntegerBody(Array(raw.suffix(32)))
        let body = r + s
        return Data([0x30, UInt8(body.count)] + body)
    }

    private static func derLength(_ bytes: [UInt8], _ index: inout Int) -> Int? {
        guard index < bytes.count else { return nil }
        var length = Int(bytes[index])
        index += 1
        if length & 0x80 != 0 {
            let count = length & 0x7F
            guard count > 0, count <= 4, index + count <= bytes.count else { return nil }
            length = 0
            for _ in 0..<count {
                length = (length << 8) | Int(bytes[index])
                index += 1
            }
        }
        return length
    }

    private static func derInteger(_ bytes: [UInt8], _ index: inout Int) -> [UInt8]? {
        guard index + 2 <= bytes.count, bytes[index] == 0x02 else { return nil }
        index += 1
        guard let length = derLength(bytes, &index) else { return nil }
        guard index + length <= bytes.count else { return nil }
        var value = Array(bytes[index..<index + length])
        index += length
        while value.count > 1, value.first == 0 { value.removeFirst() }
        return value
    }

    private static func derIntegerBody(_ value: [UInt8]) -> [UInt8] {
        var body = value
        while body.count > 1, body.first == 0 { body.removeFirst() }
        if let first = body.first, first & 0x80 != 0 { body.insert(0, at: 0) }
        return [0x02, UInt8(body.count)] + body
    }

    private static func leftPad(_ value: [UInt8], _ width: Int) -> [UInt8] {
        Array(repeating: 0, count: max(0, width - value.count)) + value
    }
}
