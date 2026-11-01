import Foundation

/// iAP2 link layer: the 9-byte packet header, SYN/ACK negotiation, and sequenced
/// data packets that carry CSM frames.
///
/// The phone does not accept bare CSM frames on the carkit stream. It first sends a
/// six-byte iAP2 marker, then negotiates link parameters, and only after an ACK
/// exchange does it accept data packets. This is the minimum of that protocol needed
/// to talk: marker, SYN/ACK, DATA with sequence numbers.
public final class IAP2Link {
    public enum Event {
        case negotiated
        case control(payload: Data)
        case data(session: UInt8, sequence: UInt8, payload: Data)
        case reset
    }

    public static let marker: [UInt8] = [0xFF, 0x55, 0x02, 0x00, 0xEE, 0x10]
    static let start: UInt16 = 0xFF5A
    static let controlSession: UInt8 = 10

    static let syn: UInt8 = 0x80
    static let ack: UInt8 = 0x40
    static let eak: UInt8 = 0x20
    static let rst: UInt8 = 0x10

    private let link: CarKitLink
    private var buffer: [UInt8] = []
    private var sentSequence: UInt8 = 99
    private var lastPeerSequence: UInt8 = 0
    public private(set) var isNormal = false
    public private(set) var peerParameters: Data?

    public init(link: CarKitLink) {
        self.link = link
    }

    // MARK: - Outbound

    /// Sends the marker and our link synchronization packet.
    public func start() throws {
        try link.write(Data(Self.marker))
        try sendSyn()
    }

    private func sendSyn() throws {
        try writePacket(payload: Self.negotiationPayload, control: Self.syn, session: 0)
    }

    /// One CSM frame on the control session. Data packets carry the next sequence
    /// number; ACKs do not consume one.
    public func send(_ frame: Data) throws {
        sentSequence = sentSequence &+ 1
        try writePacket(payload: frame, control: Self.ack, session: Self.controlSession)
    }

    private func sendAck() throws {
        try writePacket(payload: nil, control: Self.ack, session: 0)
    }

    private func writePacket(payload: Data?, control: UInt8, session: UInt8) throws {
        var header = Data()
        header.append(contentsOf: [0xFF, 0x5A])
        let length = 9 + (payload?.count ?? 0) + (payload == nil ? 0 : 1)
        header.append(bigEndian: UInt16(length))
        header.append(control)
        header.append(sentSequence)
        header.append(lastPeerSequence)
        header.append(session)
        header.append(Self.checksum(header))

        var packet = header
        if let payload {
            packet.append(payload)
            packet.append(Self.checksum(payload))
        }
        try link.write(packet)
    }

    // MARK: - Inbound

    /// Reads whatever the phone sent and returns the decoded events.
    public func poll(timeoutMs: UInt32 = 400) throws -> [Event] {
        let chunk = try link.read(max: 64 * 1024, timeoutMs: timeoutMs)
        guard !chunk.isEmpty else { return [] }
        buffer.append(contentsOf: chunk)

        var events: [Event] = []
        while true {
            // Marker: drop it wherever it appears at the head of the buffer.
            if buffer.count >= Self.marker.count {
                if Array(buffer.prefix(Self.marker.count)) == Self.marker {
                    buffer.removeFirst(Self.marker.count)
                    continue
                }
            } else if buffer == Array(Self.marker.prefix(buffer.count)) {
                break  // still receiving a marker
            }

            // Re-sync on the packet start word.
            while buffer.count >= 2 {
                if buffer[0] == 0xFF && buffer[1] == 0x5A { break }
                buffer.removeFirst()
            }
            guard buffer.count >= 9 else { break }

            let headerBytes = Array(buffer.prefix(9))
            guard Self.checksum(Data(headerBytes)) == 0 else {
                buffer.removeFirst()
                continue
            }
            let length = Int(headerBytes[2]) << 8 | Int(headerBytes[3])
            guard length >= 9, buffer.count >= length else { break }

            let control = headerBytes[4]
            let sequence = headerBytes[5]
            let session = headerBytes[7]
            var payload: Data?
            if length > 9 {
                let body = Data(buffer[9..<length])
                guard Self.checksum(body) == 0 else {
                    buffer.removeFirst(length)
                    continue
                }
                payload = body.dropLast()  // strip the payload checksum
            }
            buffer.removeFirst(length)

            if control & Self.rst != 0 {
                events.append(.reset)
            }
            if control & Self.syn != 0, let payload {
                lastPeerSequence = sequence
                peerParameters = payload
                try sendAck()
                events.append(.control(payload: payload))
            } else if control & Self.ack != 0 {
                // Any packet carrying the ACK bit completes negotiation: the phone
                // may acknowledge our SYN in the same packet that carries data.
                if !isNormal {
                    isNormal = true
                    events.append(.negotiated)
                }
                if let payload {
                    lastPeerSequence = sequence
                    try sendAck()
                    events.append(.data(session: session, sequence: sequence, payload: payload))
                }
            }
        }
        return events
    }

    // MARK: - Wire helpers

    static func checksum(_ data: Data) -> UInt8 {
        var sum: UInt8 = 0
        for byte in data { sum = sum &+ byte }
        return 0 &- sum
    }

    /// LinkSynchronizationPayload: version 1, 30 outstanding, 64 KiB frames,
    /// 4 s retransmit, 500 ms ack, 4 retries, 3 acks, control/EA/file sessions.
    static let negotiationPayload: Data = {
        var out = Data([0x01, 0x1E])
        out.append(bigEndian: UInt16(0xFFFF))
        out.append(bigEndian: UInt16(4000))
        out.append(bigEndian: UInt16(500))
        out.append(contentsOf: [4, 3])
        out.append(contentsOf: [10, 0, 1])
        out.append(contentsOf: [11, 2, 1])
        out.append(contentsOf: [12, 1, 2])
        return out
    }()
}
