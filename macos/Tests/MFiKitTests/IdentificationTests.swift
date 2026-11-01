import XCTest
@testable import MFiKit

final class IdentificationTests: XCTestCase {
    func testInformationFrameCarriesTheRequiredFields() throws {
        let identification = AccessoryIdentification()
        let frame = try identification.informationFrame()
        var decoder = CSMDecoder()
        let decoded = try XCTUnwrap(decoder.push(frame).first)
        XCTAssertEqual(decoded.messageID, 0x1D01)

        let ids = decoded.parameters.map(\.id)
        for required in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 13, 16] {
            XCTAssertTrue(ids.contains(UInt16(required)), "missing parameter \(required)")
        }
        // Any declared external-accessory protocol is rejected by the phone (field 10),
        // so the default omits it.
        XCTAssertFalse(ids.contains(10))
    }

    func testMessageListsDoNotDeclareIdentificationItself() {
        let identification = AccessoryIdentification()
        for forbidden: UInt16 in [0x1D00, 0x1D01, 0x1D02, 0x1D03] {
            XCTAssertFalse(identification.messagesSent.contains(forbidden))
            XCTAssertFalse(identification.messagesReceived.contains(forbidden))
        }
        XCTAssertTrue(identification.messagesSent.contains(AccAuth.certificate))
        XCTAssertTrue(identification.messagesReceived.contains(AccAuth.requestChallenge))
    }

    func testStringsAreNullTerminatedAndIntegersBigEndian() throws {
        XCTAssertEqual(AccessoryIdentification.string("ab"), Data([0x61, 0x62, 0x00]))
        XCTAssertEqual(AccessoryIdentification.messageIDs([0xAA00, 0x1D02]),
                       Data([0xAA, 0x00, 0x1D, 0x02]))
    }

    func testDeclaringAProtocolAddsParameter10() throws {
        var identification = AccessoryIdentification()
        identification.protocolName = "com.apple.carplay"
        let frame = try identification.informationFrame()
        var decoder = CSMDecoder()
        let decoded = try XCTUnwrap(decoder.push(frame).first)
        let protocolParameter = try XCTUnwrap(decoded.parameters.first { $0.id == 10 })
        // Nested parameter list: id 1, name, match action.
        let nested = try CSM.parseParameters(protocolParameter.payload)
        XCTAssertEqual(nested.first?.id, 0)
    }

    func testLinkChecksumValidates() {
        let payload = Data([0x40, 0x40, 0x00, 0x06, 0xAA, 0x00])
        var signed = payload
        signed.append(IAP2Link.checksum(payload))
        XCTAssertEqual(IAP2Link.checksum(signed), 0)
    }

    func testLinkHeaderPacksAndValidates() {
        // 9-byte header: FF5A, length, control, seq, ack, session, checksum.
        var header = Data()
        header.append(contentsOf: [0xFF, 0x5A])
        header.append(bigEndian: UInt16(9))
        header.append(contentsOf: [0x40, 0x63, 0x00, 0x00])
        header.append(IAP2Link.checksum(header))
        XCTAssertEqual(header.count, 9)
        XCTAssertEqual(IAP2Link.checksum(header), 0)
    }
}

final class StartSessionTests: XCTestCase {
    func testStartSessionCarriesWiredAddressPortAndIdentity() throws {
        let start = CarPlayStartSession(
            ipAddresses: ["fe80::1c75:6ad0:ec83:2db5%en9"],
            port: 7000,
            deviceIdentifier: "72:22:fe:c8:b5:66"
        )
        let frame = try start.frame()
        var decoder = CSMDecoder()
        let message = try XCTUnwrap(decoder.push(frame).first)
        XCTAssertEqual(message.messageID, 0x4301)

        // Port is a big-endian u32.
        XCTAssertEqual(message.parameter(2), Data([0x00, 0x00, 0x1B, 0x58]))
        XCTAssertEqual(message.parameter(3), AccessoryIdentification.string("72:22:fe:c8:b5:66"))

        // The wired group holds the bare IPv6 address, without the scope suffix.
        let wired = try XCTUnwrap(message.parameter(0))
        let nested = try CSM.parseParameters(wired)
        XCTAssertEqual(nested.first?.payload, AccessoryIdentification.string("fe80::1c75:6ad0:ec83:2db5"))
    }

    func testSubscriptionsCoverPowerRouteCallAndCommunications() {
        let frames = AccessorySubscriptions.frames()
        var decoder = CSMDecoder()
        let ids = frames.compactMap { decoder.push($0).first?.messageID }
        XCTAssertEqual(ids, [0xAE03, 0xAE00, 0x5200, 0x4154, 0x4157])
    }
}
