import Foundation

/// One decoded iAP2 CSM frame.
///
/// Wire shape (big-endian, no checksum):
///
///     frame     0x4040 | u16 length | u16 messageID | body
///     body      parameter*
///     parameter u16 length | u16 parameterID | payload
///
/// `length` includes the 6-byte header; the minimum is 6.
public struct CSMFrame: Equatable {
    public let messageID: UInt16
    public let payload: Data

    public init(messageID: UInt16, payload: Data = Data()) {
        self.messageID = messageID
        self.payload = payload
    }

    public var parameters: [CSMParameter] {
        (try? CSM.parseParameters(payload)) ?? []
    }

    public func parameter(_ id: UInt16) -> Data? {
        parameters.first { $0.id == id }?.payload
    }
}

public struct CSMParameter: Equatable {
    public let id: UInt16
    public let payload: Data

    public init(id: UInt16, payload: Data) {
        self.id = id
        self.payload = payload
    }
}

public enum CSMError: Error, CustomStringConvertible {
    case truncatedParameter
    case invalidParameterLength(UInt16)
    case frameTooLarge(Int)
    case parameterTooLarge(Int)

    public var description: String {
        switch self {
        case .truncatedParameter:
            return "truncated parameter header"
        case .invalidParameterLength(let length):
            return "invalid parameter length \(length)"
        case .frameTooLarge(let length):
            return "frame too large: \(length) bytes"
        case .parameterTooLarge(let length):
            return "parameter too large: \(length) bytes"
        }
    }
}

public enum CSM {
    public static let start: UInt16 = 0x4040
    public static let headerBytes = 6
    public static let maxFrameBytes = 0xFFFF
    public static let maxParameterBytes = 0xFFFF

    public static func parameter(id: UInt16, payload: Data = Data()) throws -> Data {
        let length = 4 + payload.count
        guard length <= maxParameterBytes else { throw CSMError.parameterTooLarge(length) }
        var out = Data()
        out.append(bigEndian: UInt16(length))
        out.append(bigEndian: id)
        out.append(payload)
        return out
    }

    public static func frame(messageID: UInt16, body: Data = Data()) throws -> Data {
        let length = headerBytes + body.count
        guard length <= maxFrameBytes else { throw CSMError.frameTooLarge(length) }
        var out = Data()
        out.append(bigEndian: start)
        out.append(bigEndian: UInt16(length))
        out.append(bigEndian: messageID)
        out.append(body)
        return out
    }

    public static func frame(messageID: UInt16, parameters: [CSMParameter]) throws -> Data {
        var body = Data()
        for parameter in parameters {
            body.append(try self.parameter(id: parameter.id, payload: parameter.payload))
        }
        return try frame(messageID: messageID, body: body)
    }

    public static func parseParameters(_ payload: Data) throws -> [CSMParameter] {
        var parameters: [CSMParameter] = []
        var offset = payload.startIndex
        while offset < payload.endIndex {
            guard payload.distance(from: offset, to: payload.endIndex) >= 4 else {
                throw CSMError.truncatedParameter
            }
            let length = Int(payload.readBigEndian(at: offset))
            guard length >= 4,
                  payload.distance(from: offset, to: payload.endIndex) >= length else {
                throw CSMError.invalidParameterLength(UInt16(clamping: length))
            }
            let id = payload.readBigEndian(at: payload.index(offset, offsetBy: 2))
            let start = payload.index(offset, offsetBy: 4)
            parameters.append(CSMParameter(id: id, payload: Data(payload[start..<payload.index(offset, offsetBy: length)])))
            offset = payload.index(offset, offsetBy: length)
        }
        return parameters
    }
}

/// Incremental decoder. Tolerates arbitrary chunking, concatenated frames and
/// garbage before a `0x4040` marker, matching the reference implementation.
public struct CSMDecoder {
    private var buffer = Data()

    public init() {}

    public mutating func push(_ chunk: Data) -> [CSMFrame] {
        guard !chunk.isEmpty else { return [] }
        buffer.append(chunk)
        var frames: [CSMFrame] = []

        while true {
            guard buffer.count >= 2 else { break }

            guard let start = Self.startMarker(in: buffer) else {
                // Keep a trailing 0x40: it may be the first half of the next marker.
                if buffer.last == 0x40 {
                    buffer = Data([0x40])
                } else {
                    buffer.removeAll(keepingCapacity: true)
                }
                break
            }

            if start > 0 {
                buffer.removeFirst(start)
                continue
            }

            guard buffer.count >= CSM.headerBytes else { break }

            let length = Int(buffer.readBigEndian(at: buffer.startIndex.advanced(by: 2)))
            guard length >= CSM.headerBytes else {
                buffer.removeFirst()
                continue
            }
            guard buffer.count >= length else { break }

            let messageID: UInt16 = buffer.readBigEndian(at: buffer.startIndex.advanced(by: 4))
            let body = Data(buffer[buffer.startIndex.advanced(by: CSM.headerBytes)..<buffer.startIndex.advanced(by: length)])
            frames.append(CSMFrame(messageID: messageID, payload: body))
            buffer.removeFirst(length)
        }

        return frames
    }

    private static func startMarker(in data: Data) -> Int? {
        let bytes = [UInt8](data.prefix(while: { _ in true }))
        guard bytes.count >= 2 else { return nil }
        for index in 0..<(bytes.count - 1) where bytes[index] == 0x40 && bytes[index + 1] == 0x40 {
            return index
        }
        return nil
    }
}

extension Data {
    mutating func append(bigEndian value: UInt16) {
        append(UInt8(truncatingIfNeeded: value >> 8))
        append(UInt8(truncatingIfNeeded: value))
    }

    mutating func append(bigEndian value: UInt32) {
        append(UInt8(truncatingIfNeeded: value >> 24))
        append(UInt8(truncatingIfNeeded: value >> 16))
        append(UInt8(truncatingIfNeeded: value >> 8))
        append(UInt8(truncatingIfNeeded: value))
    }

    func readBigEndian(at index: Data.Index) -> UInt16 {
        guard index < endIndex, self.index(after: index) < endIndex else { return 0 }
        let high = UInt16(self[index])
        let low = UInt16(self[self.index(after: index)])
        return (high << 8) | low
    }
}
