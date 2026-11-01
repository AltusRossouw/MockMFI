import Foundation
import CryptoKit
import CommonCrypto

/// AirPlay `/auth-setup`, MFiSAP v1: the accessory half of the MFi exchange that
/// AirPlay (screen mirroring) uses, as documented in spec/02 §4.
///
/// Request  : `01 || X25519 peer public key (32)`
/// Response : `our public (32) || u32 certLen || cert || u32 encLen || enc`
public enum MFiSAP {
    public static let version: UInt8 = 1
    public static let peerKeyLength = 32

    public struct Result {
        public let response: Data
        public let sharedSecret: Data
        public let publicKey: Data
        public let encryptedSignature: Data
    }

    public static func authSetup(identity: MFiIdentity, request: Data) throws -> Result? {
        guard request.count == 1 + peerKeyLength, request.first == version else { return nil }
        let peerBytes = request.dropFirst()
        let peerKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerBytes)

        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let shared = try privateKey.sharedSecretFromKeyAgreement(with: peerKey)
        let sharedBytes = shared.withUnsafeBytes { Data($0) }
        guard sharedBytes.contains(where: { $0 != 0 }) else { return nil }

        let publicKey = privateKey.publicKey.rawRepresentation
        let aesKey = try sha1(Data("AES-KEY".utf8) + sharedBytes).prefix(16)
        let aesIV = try sha1(Data("AES-IV".utf8) + sharedBytes).prefix(16)

        // Protocol major 3 signs SHA-256(public || peer); major 2 would sign SHA-1.
        let digest: Data
        switch identity.protocolMajor {
        case 3: digest = Data(SHA256.hash(data: publicKey + peerBytes))
        default: digest = try sha1(publicKey + peerBytes)
        }

        let signature = try identity.sign(digest: digest)
        let encrypted = try aesCTR(key: Data(aesKey), iv: Data(aesIV), input: signature)

        var response = Data()
        response.append(publicKey)
        response.append(bigEndian: UInt32(identity.certificate.count))
        response.append(identity.certificate)
        response.append(bigEndian: UInt32(encrypted.count))
        response.append(encrypted)

        return Result(
            response: response,
            sharedSecret: sharedBytes,
            publicKey: publicKey,
            encryptedSignature: encrypted
        )
    }

    /// The BAA `baIC` object form is not produced here; the identity is a plain MFi
    /// certificate (spec/02 §4).
    static func sha1(_ data: Data) -> Data {
        Data(Insecure.SHA1.hash(data: data))
    }

    /// AES-128-CTR, the same construction the AirPlay handshake uses.
    static func aesCTR(key: Data, iv: Data, input: Data) throws -> Data {
        var cryptor: CCCryptorRef?
        let status = key.withUnsafeBytes { keyBytes in
            iv.withUnsafeBytes { ivBytes in
                CCCryptorCreateWithMode(
                    CCOperation(kCCEncrypt),
                    CCMode(kCCModeCTR),
                    CCAlgorithm(kCCAlgorithmAES),
                    CCPadding(ccNoPadding),
                    ivBytes.baseAddress,
                    keyBytes.baseAddress,
                    key.count,
                    nil, 0, 0,
                    CCModeOptions(kCCModeOptionCTR_BE),
                    &cryptor
                )
            }
        }
        guard status == kCCSuccess, let cryptor else {
            throw MFiIdentityError.signing("AES-CTR setup failed (\(status))")
        }
        defer { CCCryptorRelease(cryptor) }

        var output = Data(count: input.count + kCCBlockSizeAES128)
        var moved = 0
        let result = output.withUnsafeMutableBytes { outBytes in
            input.withUnsafeBytes { inBytes in
                CCCryptorUpdate(
                    cryptor,
                    inBytes.baseAddress, input.count,
                    outBytes.baseAddress, outBytes.count,
                    &moved
                )
            }
        }
        guard result == kCCSuccess else {
            throw MFiIdentityError.signing("AES-CTR update failed (\(result))")
        }
        output.removeSubrange(moved..<output.count)
        return output
    }
}
