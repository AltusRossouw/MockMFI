import Foundation
import Darwin

/// A minimal TCP listener for the AirPlay port the phone is told to connect to.
///
/// Nothing AirPlay-shaped is implemented yet: this only proves whether the phone
/// accepts the start session and dials the accessory, and captures what it says
/// first.
public final class AirPlayListener {
    public struct Connection {
        public let peer: String
        public let firstBytes: Data
    }

    private let port: UInt16
    private var descriptor: Int32 = -1

    public init(port: UInt16 = 7000) {
        self.port = port
    }

    deinit { close() }

    public func open() throws {
        descriptor = socket(AF_INET6, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw POSIXError(.ENFILE) }
        var reuse: Int32 = 1
        setsockopt(descriptor, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))

        var address = sockaddr_in6()
        address.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
        address.sin6_family = sa_family_t(AF_INET6)
        address.sin6_port = port.bigEndian
        address.sin6_addr = in6addr_any

        let bound = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                bind(descriptor, sockaddrPointer, socklen_t(MemoryLayout<sockaddr_in6>.size))
            }
        }
        guard bound == 0 else {
            let code = errno
            Darwin.close(descriptor)
            descriptor = -1
            throw POSIXError(POSIXErrorCode(rawValue: code) ?? .EIO)
        }
        guard listen(descriptor, 4) == 0 else {
            let code = errno
            Darwin.close(descriptor)
            descriptor = -1
            throw POSIXError(POSIXErrorCode(rawValue: code) ?? .EIO)
        }
    }

    /// Waits up to `timeout` seconds for one connection and reads its first bytes.
    public func acceptFirstConnection(timeout: TimeInterval) -> Connection? {
        guard descriptor >= 0 else { return nil }
        var pollDescriptor = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
        let ready = poll(&pollDescriptor, 1, Int32(timeout * 1000))
        guard ready > 0 else { return nil }

        var peer = sockaddr_in6()
        var length = socklen_t(MemoryLayout<sockaddr_in6>.size)
        let client = withUnsafeMutablePointer(to: &peer) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                accept(descriptor, sockaddrPointer, &length)
            }
        }
        guard client >= 0 else { return nil }
        defer { Darwin.close(client) }

        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        withUnsafePointer(to: &peer) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                _ = getnameinfo(sockaddrPointer, length, &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST)
            }
        }

        var buffer = [UInt8](repeating: 0, count: 512)
        var readDescriptor = pollfd(fd: client, events: Int16(POLLIN), revents: 0)
        _ = poll(&readDescriptor, 1, 2000)
        let count = recv(client, &buffer, buffer.count, 0)
        let data = count > 0 ? Data(buffer.prefix(count)) : Data()
        return Connection(peer: String(cString: host), firstBytes: data)
    }

    public func close() {
        if descriptor >= 0 { Darwin.close(descriptor) }
        descriptor = -1
    }
}
