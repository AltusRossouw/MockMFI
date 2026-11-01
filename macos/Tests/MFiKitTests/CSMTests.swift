import XCTest
@testable import MFiKit

final class CSMTests: XCTestCase {
    func testEmptyCertificateRequestMatchesVector() throws {
        let frame = try CSM.frame(messageID: 0xAA00)
        XCTAssertEqual([UInt8](frame), [0x40, 0x40, 0x00, 0x06, 0xAA, 0x00])
    }

    func testCertificateFrameMatchesVector() throws {
        let frame = try CSM.frame(
            messageID: 0xAA01,
            parameters: [CSMParameter(id: 0, payload: Data([0x41, 0x42, 0x43]))]
        )
        XCTAssertEqual(
            [UInt8](frame),
            [0x40, 0x40, 0x00, 0x0D, 0xAA, 0x01, 0x00, 0x07, 0x00, 0x00, 0x41, 0x42, 0x43]
        )
    }

    func testChallengeFrameMatchesVector() throws {
        let challenge = Data((0..<32).map { UInt8($0) })
        let frame = try CSM.frame(
            messageID: 0xAA02,
            parameters: [CSMParameter(id: 0, payload: challenge)]
        )
        XCTAssertEqual(frame.count, 42)
        XCTAssertEqual([UInt8](frame.prefix(10)), [0x40, 0x40, 0x00, 0x2A, 0xAA, 0x02, 0x00, 0x24, 0x00, 0x00])
        XCTAssertEqual([UInt8](frame.suffix(32)), [UInt8](challenge))
    }

    func testSignatureFrameMatchesVector() throws {
        let signature = Data((0x80...0xBF).map { UInt8($0) })
        let frame = try CSM.frame(
            messageID: 0xAA03,
            parameters: [CSMParameter(id: 0, payload: signature)]
        )
        XCTAssertEqual(frame.count, 74)
        XCTAssertEqual([UInt8](frame.prefix(10)), [0x40, 0x40, 0x00, 0x4A, 0xAA, 0x03, 0x00, 0x44, 0x00, 0x00])
    }

    func testDecoderSkipsGarbageAndSplitsConcatenatedFrames() throws {
        var decoder = CSMDecoder()
        let first = try CSM.frame(messageID: 0xAA00)
        let second = try CSM.frame(messageID: 0xAA05)
        var stream = Data([0xFF, 0x00, 0x13])
        stream.append(first)
        stream.append(second)

        let frames = decoder.push(stream)
        XCTAssertEqual(frames.map(\.messageID), [0xAA00, 0xAA05])
    }

    func testDecoderToleratesByteAtATimeChunking() throws {
        var decoder = CSMDecoder()
        let frame = try CSM.frame(
            messageID: 0xAA02,
            parameters: [CSMParameter(id: 0, payload: Data(repeating: 0x7C, count: 32))]
        )
        var collected: [CSMFrame] = []
        for byte in frame {
            collected.append(contentsOf: decoder.push(Data([byte])))
        }
        XCTAssertEqual(collected.count, 1)
        XCTAssertEqual(collected.first?.parameter(0), Data(repeating: 0x7C, count: 32))
    }

    func testDecoderKeepsTrailingHalfMarker() throws {
        var decoder = CSMDecoder()
        XCTAssertTrue(decoder.push(Data([0x00, 0x40])).isEmpty)
        // The kept 0x40 plus this 0x40 completes a marker; the rest of the frame follows.
        var rest = try CSM.frame(messageID: 0xAA04)
        rest.removeFirst(2)
        XCTAssertEqual(decoder.push(Data([0x40]) + rest).map(\.messageID), [0xAA04])
    }

    func testInvalidParameterLengthIsRejected() {
        let payload = Data([0x00, 0x02, 0x00, 0x00])
        XCTAssertThrowsError(try CSM.parseParameters(payload))
    }
}
