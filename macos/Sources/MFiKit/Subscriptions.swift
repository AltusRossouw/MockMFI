import Foundation

/// The messages an accessory sends right after identification in wired CarPlay:
/// a power-source update and the "start … updates" subscriptions. The phone offers
/// `0x4300 CarPlayAvailability` only after these arrive.
public enum AccessorySubscriptions {
    /// `announceAvailability` is an experiment: LIVI receives `0x4300` from the
    /// phone, and sending it from the accessory produced no answer either way.
    public static func frames(availableCurrentMilliamps: UInt16 = 500, announceAvailability: Bool = false) -> [Data] {
        var frames: [Data] = []

        if announceAvailability {
            var wired = Data()
            wired.append(contentsOf: [(0 as UInt16, Data([1])), (1, AccessoryIdentification.string("0"))]
                .map { try? CSM.parameter(id: $0.0, payload: $0.1) }
                .compactMap { $0 }
                .reduce(Data(), +))
            frames.append(frame(0x4300, [(0, wired)]))
        }

        // 0xAE03 PowerSourceUpdate { 0: current mA, 1: should charge }
        frames.append(frame(0xAE03, [
            (0, Data([UInt8(availableCurrentMilliamps >> 8), UInt8(availableCurrentMilliamps & 0xFF)])),
            (1, Data([1])),
        ]))

        // 0xAE00 StartPowerUpdates: all six fields.
        frames.append(frame(0xAE00, [0, 1, 2, 4, 5, 6].map { ($0, Data()) }))

        // 0x5200 StartRouteGuidanceUpdates { 0: display component id }
        frames.append(frame(0x5200, [(0, Data([0x00, 0x00]))]))

        // 0x4154 StartCallStateUpdates: the fields LIVI subscribes to.
        frames.append(frame(0x4154, [0, 1, 2, 3, 4, 11, 12].map { ($0, Data()) }))

        // 0x4157 StartCommunicationsUpdates: signal strength, carrier, cellular.
        frames.append(frame(0x4157, [0, 1, 4, 5].map { ($0, Data()) }))

        return frames
    }

    static func frame(_ messageID: UInt16, _ parameters: [(UInt16, Data)]) -> Data {
        let list = parameters.map { CSMParameter(id: $0.0, payload: $0.1) }
        return (try? CSM.frame(messageID: messageID, parameters: list)) ?? Data()
    }
}
