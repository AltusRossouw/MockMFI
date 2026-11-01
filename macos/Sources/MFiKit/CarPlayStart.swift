import Foundation

/// `0x4301 CarPlayStartSession`: the accessory tells the phone where to connect.
///
/// Wired carries the accessory's link-local IPv6 address on the USB network
/// interface, the AirPlay port, a device identifier and an optional public key for
/// mutual authentication.
public struct CarPlayStartSession {
    public var ipAddresses: [String]
    public var port: UInt32
    public var deviceIdentifier: String
    public var publicKey: String?
    public var sourceVersion: String
    public var supportsMutualAuthentication: Bool

    public init(
        ipAddresses: [String],
        port: UInt32 = 7000,
        deviceIdentifier: String,
        publicKey: String? = nil,
        sourceVersion: String = "0.1.0",
        supportsMutualAuthentication: Bool = false
    ) {
        self.ipAddresses = ipAddresses
        self.port = port
        self.deviceIdentifier = deviceIdentifier
        self.publicKey = publicKey
        self.sourceVersion = sourceVersion
        self.supportsMutualAuthentication = supportsMutualAuthentication
    }

    public func frame() throws -> Data {
        var wired = Data()
        // The phone wants a bare address; the "%en9" scope suffix is a local detail.
        let bare = ipAddresses.map { $0.split(separator: "%").first.map(String.init) ?? $0 }
        wired.append(contentsOf: Self.parameter(0, bare.map { AccessoryIdentification.string($0) }.reduce(Data(), +)))

        var parameters: [CSMParameter] = [
            CSMParameter(id: 0, payload: wired),
            CSMParameter(id: 2, payload: Data([
                UInt8((port >> 24) & 0xFF), UInt8((port >> 16) & 0xFF),
                UInt8((port >> 8) & 0xFF), UInt8(port & 0xFF),
            ])),
            CSMParameter(id: 3, payload: AccessoryIdentification.string(deviceIdentifier)),
            CSMParameter(id: 5, payload: AccessoryIdentification.string(sourceVersion)),
        ]
        if let publicKey {
            parameters.append(CSMParameter(id: 4, payload: AccessoryIdentification.string(publicKey)))
        }
        if supportsMutualAuthentication {
            parameters.append(CSMParameter(id: 8, payload: Data([1])))
        }
        return try CSM.frame(messageID: 0x4301, parameters: parameters)
    }

    static func parameter(_ id: UInt16, _ payload: Data) -> Data {
        (try? CSM.parameter(id: id, payload: payload)) ?? Data()
    }
}
