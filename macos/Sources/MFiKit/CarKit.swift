import Foundation
import CIMobileDevice

public struct LockdownDevice: Identifiable, Hashable {
    public let udid: String
    public let connection: String
    public var id: String { udid }
}

public enum CarKitError: Error, CustomStringConvertible {
    case open(String)
    case io(String)

    public var description: String {
        switch self {
        case .open(let reason): return reason
        case .io(let reason): return reason
        }
    }
}

/// A byte stream to `com.apple.carkit.service` on the phone.
///
/// This is the macOS route: usbmuxd owns the USB device, lockdown authenticates the
/// Mac, and StartService hands back a port that carries the iAP2 session. TLS is
/// enabled when the phone asks for it. Nothing here claims the USB interface
/// directly — that is what makes it work on macOS at all.
public final class CarKitLink {
    private var handle: OpaquePointer?
    public let ssl: Bool
    public let udid: String

    public init(udid: String) throws {
        var out: OpaquePointer?
        var ssl: Int32 = 0
        var error = [CChar](repeating: 0, count: 256)
        let result = cpd_open_carkit(udid, &out, &ssl, &error, error.count)
        guard result == 0, let handle = out else {
            throw CarKitError.open(String(cString: error))
        }
        self.handle = handle
        self.ssl = ssl == 1
        self.udid = udid
    }

    deinit { close() }

    /// Reads what the phone sends; 0 bytes means the timeout expired.
    public func read(max: Int = 64 * 1024, timeoutMs: UInt32 = 1000) throws -> Data {
        guard let handle else { throw CarKitError.io("link closed") }
        var buffer = [UInt8](repeating: 0, count: max)
        let count = cpd_read(handle, &buffer, buffer.count, timeoutMs)
        if count < 0 { throw CarKitError.io("read failed (\(count))") }
        return Data(buffer.prefix(Int(count)))
    }

    public func write(_ data: Data) throws {
        guard let handle else { throw CarKitError.io("link closed") }
        let written = data.withUnsafeBytes { raw in
            cpd_write(handle, raw.baseAddress, raw.count)
        }
        if written < 0 { throw CarKitError.io("write failed (\(written))") }
        if written != data.count { throw CarKitError.io("short write \(written)/\(data.count)") }
    }

    public func close() {
        if let handle { cpd_close(handle) }
        handle = nil
    }
}

public enum CarKitTransport {
    /// Devices libimobiledevice can see (USB and network).
    public static func devices() -> [LockdownDevice] {
        var buffer = [cpd_device](repeating: cpd_device(), count: 8)
        let count = cpd_list(&buffer, Int32(buffer.count))
        guard count > 0 else { return [] }
        return (0..<Int(count)).map { index in
            withUnsafePointer(to: &buffer[index]) { pointer in
                LockdownDevice(
                    udid: String(cString: cpd_device_udid(pointer)),
                    connection: String(cString: cpd_device_connection(pointer))
                )
            }
        }
    }
}
