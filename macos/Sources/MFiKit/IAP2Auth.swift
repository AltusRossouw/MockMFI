import Foundation

/// iAP2 AccAuthentication message IDs (accessory side).
public enum AccAuth {
    public static let requestCertificate: UInt16 = 0xAA00
    public static let certificate: UInt16 = 0xAA01
    public static let requestChallenge: UInt16 = 0xAA02
    public static let response: UInt16 = 0xAA03
    public static let failed: UInt16 = 0xAA04
    public static let succeeded: UInt16 = 0xAA05
    public static let certificateSerial: UInt16 = 0xAA06

    public static let maxCertificateBytes = 65_525
    public static let maxChallengeBytes = 128
}

public enum IAP2AuthError: Error, CustomStringConvertible {
    case challengeLength(Int)
    case unexpectedMessage(UInt16)
    case authenticationFailed
    case missingParameter(UInt16)

    public var description: String {
        switch self {
        case .challengeLength(let length):
            return "challenge must be 1...\(AccAuth.maxChallengeBytes) bytes, got \(length)"
        case .unexpectedMessage(let id):
            return String(format: "unexpected AccAuthentication message 0x%04X", id)
        case .authenticationFailed:
            return "the phone reported AuthenticationFailed"
        case .missingParameter(let id):
            return "missing parameter \(id)"
        }
    }
}

/// The accessory half of iAP2 AccAuthentication: answer the certificate request,
/// sign the challenge, and stop when the phone reports success.
///
/// Exactly one certificate is read and one signature computed per challenge; the
/// phone drives the exchange.
public final class IAP2AuthResponder {
    public let identity: MFiIdentity
    public private(set) var isComplete = false
    public private(set) var certificatesSent = 0
    public private(set) var challengesSigned = 0

    public init(identity: MFiIdentity) {
        self.identity = identity
    }

    /// Handle one frame. Returns the reply to send, or `nil` once the phone has
    /// reported `AuthenticationSucceeded`.
    public func handle(_ frame: CSMFrame) throws -> Data? {
        switch frame.messageID {
        case AccAuth.requestCertificate:
            certificatesSent += 1
            return try CSM.frame(
                messageID: AccAuth.certificate,
                parameters: [CSMParameter(id: 0, payload: identity.certificate)]
            )

        case AccAuth.requestChallenge:
            guard let challenge = frame.parameter(0) else {
                throw IAP2AuthError.missingParameter(0)
            }
            guard (1...AccAuth.maxChallengeBytes).contains(challenge.count) else {
                throw IAP2AuthError.challengeLength(challenge.count)
            }
            // P-256 signs a 32-byte digest. A shorter or longer challenge would be
            // signed as-is by a coprocessor, which is exactly the failure we want to
            // see here rather than on the phone.
            let signature = try identity.sign(digest: challenge)
            challengesSigned += 1
            return try CSM.frame(
                messageID: AccAuth.response,
                parameters: [CSMParameter(id: 0, payload: signature)]
            )

        case AccAuth.failed:
            throw IAP2AuthError.authenticationFailed

        case AccAuth.succeeded:
            isComplete = true
            return nil

        default:
            throw IAP2AuthError.unexpectedMessage(frame.messageID)
        }
    }
}
