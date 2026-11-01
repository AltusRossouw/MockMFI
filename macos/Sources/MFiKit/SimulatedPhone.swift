import Foundation
import CryptoKit
import Security

public struct SimulationEvent: Identifiable {
    public let id = UUID()
    public let direction: String   // "phone -> accessory" / "accessory -> phone" / "note"
    public let text: String

    public init(direction: String, text: String) {
        self.direction = direction
        self.text = text
    }
}

public enum SimulationError: Error, CustomStringConvertible {
    case unexpected(String)

    public var description: String {
        switch self {
        case .unexpected(let message):
            return message
        }
    }
}

/// A phone stand-in that drives the responder over the same frames a real iPhone
/// sends. It proves the identity, the framing and the responder together, without
/// a cable: certificate returned byte for byte, signature verified against the
/// key, success reported.
public enum SimulatedPhone {
    public static func run(identity: MFiIdentity, challenge: Data? = nil) throws -> [SimulationEvent] {
        var events: [SimulationEvent] = []
        let responder = IAP2AuthResponder(identity: identity)
        let decoder = CSMDecoderBox()

        func exchange(_ frame: Data, label: String) throws -> [CSMFrame] {
            events.append(SimulationEvent(direction: "phone → accessory", text: label))
            guard let reply = try responder.handle(try Self.decodeSingle(frame, label: label)) else {
                return []
            }
            events.append(SimulationEvent(
                direction: "accessory → phone",
                text: String(format: "0x%04X, %d bytes", try Self.messageID(of: reply), reply.count)
            ))
            return decoder.push(reply)
        }

        // 1. Certificate request.
        let certReply = try exchange(try CSM.frame(messageID: AccAuth.requestCertificate), label: "0xAA00 RequestAuthenticationCertificate")
        guard let certFrame = certReply.first else {
            throw SimulationError.unexpected("no reply to 0xAA00")
        }
        guard certFrame.messageID == AccAuth.certificate else {
            throw SimulationError.unexpected(String(format: "expected 0xAA01, got 0x%04X", certFrame.messageID))
        }
        guard certFrame.parameter(0) == identity.certificate else {
            throw SimulationError.unexpected("certificate in 0xAA01 differs from certificate.p7b")
        }
        events.append(SimulationEvent(direction: "note", text: "certificate returned byte for byte (\(identity.certificate.count) bytes)"))

        // 2. Challenge.
        let digest = challenge ?? Self.randomDigest()
        let challengeFrame = try CSM.frame(
            messageID: AccAuth.requestChallenge,
            parameters: [CSMParameter(id: 0, payload: digest)]
        )
        let sigReply = try exchange(challengeFrame, label: "0xAA02 challenge (\(digest.count) bytes)")
        guard let sigFrame = sigReply.first, sigFrame.messageID == AccAuth.response else {
            throw SimulationError.unexpected("no 0xAA03 response")
        }
        guard let signature = sigFrame.parameter(0) else {
            throw SimulationError.unexpected("0xAA03 has no parameter 0")
        }
        guard signature.count == 64 else {
            throw SimulationError.unexpected("signature is \(signature.count) bytes, expected 64 (raw r||s)")
        }
        guard identity.verify(digest: digest, signature: signature) else {
            throw SimulationError.unexpected("signature does not verify against the identity")
        }
        events.append(SimulationEvent(direction: "note", text: "signature 64 bytes raw r||s, verifies"))

        // 3. Success.
        let success = try CSM.frame(messageID: AccAuth.succeeded)
        events.append(SimulationEvent(direction: "phone → accessory", text: "0xAA05 AuthenticationSucceeded"))
        let reply = try responder.handle(try Self.decodeSingle(success, label: "0xAA05"))
        guard reply == nil, responder.isComplete else {
            throw SimulationError.unexpected("responder did not complete on 0xAA05")
        }
        events.append(SimulationEvent(
            direction: "note",
            text: "complete: \(responder.certificatesSent) certificate, \(responder.challengesSigned) signature"
        ))
        return events
    }

    public static func randomDigest() -> Data {
        var bytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return Data(bytes)
    }

    private static func messageID(of frame: Data) throws -> UInt16 {
        let decoded = try decodeSingle(frame, label: "reply")
        return decoded.messageID
    }

    private static func decodeSingle(_ frame: Data, label: String) throws -> CSMFrame {
        var decoder = CSMDecoder()
        let frames = decoder.push(frame)
        guard let first = frames.first else {
            throw SimulationError.unexpected("\(label): frame did not decode")
        }
        return first
    }
}

/// Reference-type wrapper so the exchange helper can mutate one decoder.
private final class CSMDecoderBox {
    private var decoder = CSMDecoder()

    func push(_ data: Data) -> [CSMFrame] {
        decoder.push(data)
    }
}
