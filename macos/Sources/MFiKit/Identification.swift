import Foundation

/// Accessory identification (iAP2 `0x1D00` + `0x1D01`).
///
/// The phone will not start AccAuthentication until it has accepted this. Field
/// encodings follow iAP2 CSM: strings are UTF-8 with a trailing NUL, integers are
/// big-endian, flags are zero-length parameters, and a list is one parameter whose
/// payload is the concatenation of its elements (or nested parameter lists, for a
/// list of groups).
public struct AccessoryIdentification {
    public var name: String
    public var model: String
    public var manufacturer: String
    public var serial: String
    public var firmware: String
    public var hardware: String
    public var currentLanguage: String
    public var supportedLanguages: [String]
    /// Interface number that carries CarPlay's data on the accessory side.
    public var carPlayInterfaceNumber: UInt8
    /// The one external-accessory protocol we declare.
    public var protocolName: String
    public var protocolMatchAction: UInt8
    public var protocolTransportID: UInt16?
    public var protocolCarPlay: Bool
    /// Which transport component the accessory declares. Wired CarPlay uses the
    /// host side on macOS; the device side is here to test what the phone wants.
    public var declaresUSBHostTransport: Bool
    public var declaresUSBDeviceTransport: Bool
    /// iAP2 specs parameter 10 as a list of protocol strings; CarPlay implementations
    /// use a nested group. Both are tried while the phone's expectation is unknown.
    public var protocolAsStringList: Bool
    /// Identifies the accessory app to the phone; may be what makes a protocol
    /// declaration valid.
    public var appMatchTeamID: String?
    /// Vehicle/status/location/route-guidance components. LIVI sends these by
    /// default; they are here to test whether the phone needs them before it
    /// accepts a CarPlay protocol declaration.
    public var declaresVehicleComponents: Bool
    /// What we promise to send / accept. The phone checks these lists.
    public var messagesSent: [UInt16]
    public var messagesReceived: [UInt16]

    public init(
        name: String = "CarPlayDesk",
        model: String = "CarPlayDesk",
        manufacturer: String = "MockMFI",
        serial: String = "CPD0001",
        firmware: String = "0.1.0",
        hardware: String = "0.1",
        currentLanguage: String = "en",
        supportedLanguages: [String] = ["en"],
        carPlayInterfaceNumber: UInt8 = 3,
        protocolName: String = "",
        protocolMatchAction: UInt8 = 4,
        protocolTransportID: UInt16? = nil,
        protocolCarPlay: Bool = false,
        declaresUSBHostTransport: Bool = true,
        declaresUSBDeviceTransport: Bool = false,
        protocolAsStringList: Bool = false,
        appMatchTeamID: String? = nil,
        declaresVehicleComponents: Bool = false,
        messagesSent: [UInt16] = AccessoryIdentification.minimalSent,
        messagesReceived: [UInt16] = AccessoryIdentification.minimalReceived
    ) {
        self.name = name
        self.model = model
        self.manufacturer = manufacturer
        self.serial = serial
        self.firmware = firmware
        self.hardware = hardware
        self.currentLanguage = currentLanguage
        self.supportedLanguages = supportedLanguages
        self.carPlayInterfaceNumber = carPlayInterfaceNumber
        self.protocolName = protocolName
        self.protocolMatchAction = protocolMatchAction
        self.protocolTransportID = protocolTransportID
        self.protocolCarPlay = protocolCarPlay
        self.declaresUSBHostTransport = declaresUSBHostTransport
        self.declaresUSBDeviceTransport = declaresUSBDeviceTransport
        self.protocolAsStringList = protocolAsStringList
        self.appMatchTeamID = appMatchTeamID
        self.declaresVehicleComponents = declaresVehicleComponents
        self.messagesSent = messagesSent
        self.messagesReceived = messagesReceived
    }

    /// Identification plus the MFi replies this app can actually produce.
    /// Identification messages are implicit and must not be declared here; the phone
    /// rejects the list if they are (observed: fields 6 and 7 came back flagged).
    public static let minimalSent: [UInt16] = [
        AccAuth.certificate, AccAuth.response,
    ]
    public static let minimalReceived: [UInt16] = [
        AccAuth.requestCertificate, AccAuth.requestChallenge,
        AccAuth.failed, AccAuth.succeeded,
    ]

    /// The message set a CarPlay accessory advertises (LIVI's lists), used to test
    /// whether the phone validates a protocol declaration against it.
    public static let carPlaySent: [UInt16] = [
        0xA101, 0x5703, 0x5000, 0x5002, 0x5003, 0x5200, 0x5203, 0xFFFB, 0xAE00, 0xAE02,
        0x4157, 0x4159, 0x4154, 0x4156, 0x4301, 0xAE03,
    ]
    public static let carPlayMinimalSent: [UInt16] = [
        0x4301, 0xAE03, 0xAE00, 0x4157, 0x4154, 0x5200,
    ]
    public static let carPlayMinimalReceived: [UInt16] = [
        0x4300, 0xAE01, 0x4158, 0x4155, 0x5201, 0x5702,
    ]

    /// The AccAuthentication replies are not part of the declared set; listing them
    /// makes the phone reject fields 6 and 7.
    public static let carPlayReceived: [UInt16] = [
        0xEA00, 0xEA01, 0xA100, 0xA102, 0x4E0D, 0x4E0E, 0x5702, 0x5001, 0x5201, 0x5202,
        0xFFFA, 0xFFFC, 0xAE01, 0x4158, 0x4155, 0x4E0B, 0x4300,
    ]

    /// `0x1D00 StartIdentification`, no parameters.
    public var startFrame: Data {
        (try? CSM.frame(messageID: 0x1D00)) ?? Data()
    }

    /// `0x1D01 IdentificationInformation`.
    public func informationFrame() throws -> Data {
        var parameters: [CSMParameter] = [
            CSMParameter(id: 0, payload: Self.string(name)),
            CSMParameter(id: 1, payload: Self.string(model)),
            CSMParameter(id: 2, payload: Self.string(manufacturer)),
            CSMParameter(id: 3, payload: Self.string(serial)),
            CSMParameter(id: 4, payload: Self.string(firmware)),
            CSMParameter(id: 5, payload: Self.string(hardware)),
            CSMParameter(id: 6, payload: Self.messageIDs(messagesSent)),
            CSMParameter(id: 7, payload: Self.messageIDs(messagesReceived)),
            // PowerProvidingCapability.advanced, and 20 * 100 mA drawn from the phone.
            CSMParameter(id: 8, payload: Data([2])),
            CSMParameter(id: 9, payload: Data([0x00, 0x14])),
            ]
        if !protocolName.isEmpty {
            parameters.append(CSMParameter(id: 10, payload: externalAccessoryProtocol()))
        }
        if let appMatchTeamID {
            parameters.append(CSMParameter(id: 11, payload: Self.string(appMatchTeamID)))
        }
        parameters.append(contentsOf: [
            CSMParameter(id: 12, payload: Self.string(currentLanguage)),
            CSMParameter(id: 13, payload: supportedLanguages.map(Self.string).reduce(Data(), +)),
        ])
        if declaresUSBDeviceTransport {
            parameters.append(CSMParameter(id: 15, payload: usbDeviceTransport()))
        }
        if declaresUSBHostTransport {
            parameters.append(CSMParameter(id: 16, payload: usbHostTransport()))
        }
        if declaresVehicleComponents {
            parameters.append(CSMParameter(id: 20, payload: vehicleInformation()))
            parameters.append(CSMParameter(id: 21, payload: vehicleStatus()))
            parameters.append(CSMParameter(id: 22, payload: locationInformation()))
            parameters.append(CSMParameter(id: 30, payload: routeGuidanceDisplay()))
        }
        return try CSM.frame(messageID: 0x1D01, parameters: parameters)
    }

    /// id 1, name, `MatchAction.noActionNoCommunication`, no CarPlay flag: CarPlay is
    /// declared by the USB host transport component below, not by this protocol name.
    func externalAccessoryProtocol() -> Data {
        if protocolAsStringList {
            return Self.string(protocolName)
        }
        var out = Data()
        out.append(contentsOf: Self.parameter(0, Data([0x01])))                // id 1 (u8, not u16)
        out.append(contentsOf: Self.parameter(1, Self.string(protocolName)))
        out.append(contentsOf: Self.parameter(2, Data([protocolMatchAction])))
        if let transport = protocolTransportID {
            out.append(contentsOf: Self.parameter(3, Data([UInt8(transport >> 8), UInt8(transport & 0xFF)])))
        }
        if protocolCarPlay {
            out.append(contentsOf: Self.parameter(4, Data()))
        }
        return out
    }

    func vehicleInformation() -> Data {
        var out = Data()
        out.append(contentsOf: Self.parameter(0, Data([0x00, 0x00])))
        out.append(contentsOf: Self.parameter(1, Self.string(name)))
        out.append(contentsOf: Self.parameter(2, Data([2])))                       // engine: electric
        out.append(contentsOf: Self.parameter(6, Self.string(name)))               // display name
        out.append(contentsOf: Self.parameter(8, Self.string(name)))               // maps name
        return out
    }

    func vehicleStatus() -> Data {
        var out = Data()
        out.append(contentsOf: Self.parameter(0, Data([0x00, 0x00])))
        out.append(contentsOf: Self.parameter(1, Self.string(name)))
        for flag in [3, 4, 6] {                                                    // range, temp, warning
            out.append(contentsOf: Self.parameter(UInt16(flag), Data()))
        }
        return out
    }

    func locationInformation() -> Data {
        var out = Data()
        out.append(contentsOf: Self.parameter(0, Data([0x00, 0x00])))
        out.append(contentsOf: Self.parameter(1, Self.string(name)))
        out.append(contentsOf: Self.parameter(17, Data()))
        out.append(contentsOf: Self.parameter(18, Data()))
        return out
    }

    func routeGuidanceDisplay() -> Data {
        var out = Data()
        out.append(contentsOf: Self.parameter(0, Data([0x00, 0x00])))
        out.append(contentsOf: Self.parameter(1, Self.string(name)))
        for (id, value) in [(2, 64), (3, 64), (4, 64), (5, 64), (6, 4), (7, 32), (8, 4)] {
            out.append(contentsOf: Self.parameter(UInt16(id), Data([0x00, UInt8(value)])))
        }
        return out
    }

    func usbDeviceTransport() -> Data {
        var out = Data()
        out.append(contentsOf: Self.parameter(0, Data([0x00, 0x00])))
        out.append(contentsOf: Self.parameter(1, Self.string("USBDeviceTransport")))
        out.append(contentsOf: Self.parameter(2, Data()))          // supports iAP2
        out.append(contentsOf: Self.parameter(3, Data([0x00])))    // audio sample rate
        return out
    }

    func usbHostTransport() -> Data {
        var out = Data()
        out.append(contentsOf: Self.parameter(0, Data([0x00, 0x00])))            // id 0
        out.append(contentsOf: Self.parameter(1, Self.string("USBHostTransport")))
        out.append(contentsOf: Self.parameter(2, Data()))                       // supports iAP2
        out.append(contentsOf: Self.parameter(3, Data([carPlayInterfaceNumber])))
        out.append(contentsOf: Self.parameter(4, Data()))                       // supports CarPlay
        return out
    }

    // MARK: - Primitives

    static func string(_ value: String) -> Data {
        Data(value.utf8) + Data([0x00])
    }

    static func messageIDs(_ ids: [UInt16]) -> Data {
        var out = Data()
        for id in ids { out.append(bigEndian: id) }
        return out
    }

    static func parameter(_ id: UInt16, _ payload: Data) -> Data {
        (try? CSM.parameter(id: id, payload: payload)) ?? Data()
    }
}
