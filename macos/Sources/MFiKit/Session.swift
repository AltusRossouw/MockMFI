import Foundation

public enum SessionOutcome: Equatable {
    case authSucceeded
    case identificationRejected([UInt16])
    case timedOut
}

public struct SessionRun {
    public let outcome: SessionOutcome
    public let log: [String]
    public let sent: [Data]
}

/// Drives one wired attempt over an open carkit stream.
///
/// Observed order on a real iPhone: link negotiation, then the phone immediately
/// asks for the MFi certificate (`0xAA00`). Identification comes after the phone has
/// authenticated the accessory, not before — so the auth exchange is handled in
/// every phase, not just after `0x1D01`.
public final class MFISession {
    private let identity: MFiIdentity
    private var responder: IAP2AuthResponder

    public init(identity: MFiIdentity) {
        self.identity = identity
        self.responder = IAP2AuthResponder(identity: identity)
    }

    static func messageID(of frame: Data) -> UInt16 {
        var decoder = CSMDecoder()
        return decoder.push(frame).first?.messageID ?? 0
    }

    public func run(
        link: CarKitLink,
        identification: AccessoryIdentification = AccessoryIdentification(),
        startSession: CarPlayStartSession? = nil,
        timeout: TimeInterval = 25
    ) throws -> SessionRun {
        var log: [String] = []
        var sent: [Data] = []
        var decoder = CSMDecoder()
        let engine = IAP2Link(link: link)
        let deadline = Date().addingTimeInterval(timeout)
        var identified = false
        var accepted = false

        func send(_ frame: Data, label: String) throws {
            try engine.send(frame)
            sent.append(frame)
            log.append("→ \(label) (\(frame.count) bytes)")
        }

        /// Returns true when the phone reported authentication success.
        func handle(_ frame: CSMFrame) throws -> Bool {
            switch frame.messageID {
            case AccAuth.requestCertificate:
                log.append("← 0xAA00 RequestAuthenticationCertificate")
                if let reply = try responder.handle(frame) {
                    try send(reply, label: "0xAA01 certificate (\(identity.certificate.count) bytes)")
                }

            case AccAuth.requestChallenge:
                log.append("← 0xAA02 challenge (\(frame.parameter(0)?.count ?? 0) bytes)")
                if let reply = try responder.handle(frame) {
                    try send(reply, label: "0xAA03 signature (64 bytes)")
                }

            case AccAuth.succeeded:
                log.append("← 0xAA05 AuthenticationSucceeded")
                return true

            case AccAuth.failed:
                log.append("← 0xAA04 AuthenticationFailed")
                throw IAP2AuthError.authenticationFailed

            case 0x1D00:
                // The phone announces identification; the accessory answers with its
                // own 0x1D00 + 0x1D01. LIVI's order, and the one this phone expects.
                log.append("← 0x1D00 StartIdentification from the phone")
                if !identified {
                    identified = true
                    try send(identification.startFrame, label: "0x1D00 StartIdentification")
                    try send(try identification.informationFrame(), label: "0x1D01 IdentificationInformation")
                }

            case 0x1D02:
                accepted = true
                log.append("← 0x1D02 IdentificationAccepted")
                let announce = ProcessInfo.processInfo.environment["CPD_ANNOUNCE_AVAILABILITY"] == "1"
                for subscription in AccessorySubscriptions.frames(announceAvailability: announce) {
                    try send(subscription, label: String(format: "0x%04X subscription", Self.messageID(of: subscription)))
                }
                if ProcessInfo.processInfo.environment["CPD_SEND_START"] == "1", let startSession {
                    let frame = try startSession.frame()
                    try send(frame, label: "0x4301 CarPlayStartSession ip=\(startSession.ipAddresses.joined(separator: ",")) port=\(startSession.port)")
                }

            case 0x4300:
                log.append("← 0x4300 CarPlayAvailability")
                if let startSession {
                    let frame = try startSession.frame()
                    try send(frame, label: "0x4301 CarPlayStartSession ip=\(startSession.ipAddresses.joined(separator: ",")) port=\(startSession.port)")
                }

            case 0x1D03:
                let failed = frame.parameters.map(\.id)
                let hex = frame.payload.prefix(24).map { String(format: "%02x", $0) }.joined(separator: " ")
                log.append("← 0x1D03 IdentificationRejected, fields \(failed) [\(hex)]")

            default:
                log.append(String(format: "← 0x%04X, %d bytes (ignored)", frame.messageID, frame.payload.count))
            }
            return false
        }

        log.append("→ iAP2 marker + SYN (link negotiation)")
        try engine.start()

        while Date() < deadline {
            for event in try engine.poll(timeoutMs: 400) {
                switch event {
                case .negotiated:
                    log.append("← link negotiated")

                case .control:
                    log.append("← SYN from the phone, ACK sent")

                case .reset:
                    log.append("← link reset")
                    return SessionRun(outcome: .timedOut, log: log, sent: sent)

                case .data(_, _, let payload):
                    for frame in decoder.push(payload) {
                        _ = try handle(frame)
                    }
                }
            }

        }

        log.append("timed out after \(Int(timeout)) s")
        if responder.isComplete {
            log.append("MFi authentication completed on the wire")
            return SessionRun(outcome: .authSucceeded, log: log, sent: sent)
        }
        if accepted {
            return SessionRun(outcome: .authSucceeded, log: log, sent: sent)
        }
        return SessionRun(outcome: .timedOut, log: log, sent: sent)
    }
}
