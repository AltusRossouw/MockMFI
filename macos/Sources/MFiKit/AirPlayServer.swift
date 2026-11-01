import Foundation
import Darwin
import CryptoKit

/// A minimal AirPlay receiver surface: enough to answer the handshake the phone
/// performs for screen mirroring, and to log exactly how far it gets.
///
/// Implemented: `GET /info`, `POST /auth-setup` (MFiSAP v1). Everything else — pair
/// verification, FairPlay, RTSP setup — is logged and refused, because guessing at
/// them would hide the point where the phone actually stops.
public final class AirPlayServer {
    public struct Request {
        public let method: String
        public let path: String
        public let headers: [String: String]
        public let body: Data
    }

    public struct Response {
        public let status: Int
        public let contentType: String
        public let body: Data
    }

    private let port: UInt16
    private let identity: MFiIdentity
    private let deviceID: String
    private var listener: Int32 = -1
    private let companionKey = Curve25519.Signing.PrivateKey()
    private let log: (String) -> Void

    public init(port: UInt16 = 7000, identity: MFiIdentity, deviceID: String, log: @escaping (String) -> Void) {
        self.port = port
        self.identity = identity
        self.deviceID = deviceID
        self.log = log
    }

    public var publicKeyBase64: String {
        companionKey.publicKey.rawRepresentation.base64EncodedString()
    }

    public func runOnce(timeout: TimeInterval = 300) throws {
        listener = socket(AF_INET6, SOCK_STREAM, 0)
        guard listener >= 0 else { throw POSIXError(.ENFILE) }
        var reuse: Int32 = 1
        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))

        var address = sockaddr_in6()
        address.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
        address.sin6_family = sa_family_t(AF_INET6)
        address.sin6_port = port.bigEndian
        address.sin6_addr = in6addr_any
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(listener, $0, socklen_t(MemoryLayout<sockaddr_in6>.size)) }
        }
        guard bound == 0, listen(listener, 8) == 0 else {
            let code = errno
            Darwin.close(listener)
            throw POSIXError(POSIXErrorCode(rawValue: code) ?? .EIO)
        }
        log("airplay: listening on :\(port), deviceid \(deviceID)")

        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            var pollDescriptor = pollfd(fd: listener, events: Int16(POLLIN), revents: 0)
            guard poll(&pollDescriptor, 1, 1000) > 0 else { continue }
            var peer = sockaddr_in6()
            var length = socklen_t(MemoryLayout<sockaddr_in6>.size)
            let client = withUnsafeMutablePointer(to: &peer) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { accept(listener, $0, &length) }
            }
            guard client >= 0 else { continue }
            serve(client: client)
            Darwin.close(client)
        }
        Darwin.close(listener)
    }

    // MARK: - Connection

    private func serve(client: Int32) {
        var buffer = Data()
        while true {
            guard let request = readRequest(client: client, buffer: &buffer) else { return }
            log("airplay: \(request.method) \(request.path) (\(request.body.count) bytes)")

            if let response = respond(to: request) {
                write(client: client, response: response)
            } else {
                write(client: client, response: Response(status: 403, contentType: "text/plain", body: Data("not implemented".utf8)))
            }
        }
    }

    private func respond(to request: Request) -> Response? {
        switch (request.method, request.path) {
        case ("GET", "/info"):
            return Response(status: 200, contentType: "application/x-apple-binary-plist", body: infoPlist())

        case ("POST", "/auth-setup"):
            do {
                guard let result = try MFiSAP.authSetup(identity: identity, request: request.body) else {
                    log("airplay: /auth-setup rejected the request")
                    return Response(status: 400, contentType: "text/plain", body: Data("bad auth-setup".utf8))
                }
                log("airplay: /auth-setup answered, \(result.response.count) bytes")
                return Response(status: 200, contentType: "application/octet-stream", body: result.response)
            } catch {
                log("airplay: /auth-setup failed: \(error)")
                return Response(status: 500, contentType: "text/plain", body: Data("auth-setup failed".utf8))
            }

        default:
            if request.path == "/pair-setup" || request.path == "/pair-verify" || request.path == "/fp-setup" {
                let hex = request.body.prefix(32).map { String(format: "%02x", $0) }.joined(separator: " ")
                log("airplay: \(request.path) body \(hex)")
            }
            return nil
        }
    }

    private func infoPlist() -> Data {
        // Minimal AirPlay receiver description. features covers mirroring-ish bits;
        // the phone decides from this and from /fp-setup whether to continue.
        let info: [String: Any] = [
            "deviceid": deviceID,
            "features": 0x5A7FFFF7,
            "model": "AppleTV3,2",
            "protovers": "1.1",
            "srcvers": "220.68",
            "flags": 0x4,
            "vv": 2,
            "pk": Data(companionKey.publicKey.rawRepresentation).base64EncodedString(),
        ]
        return (try? PropertyListSerialization.data(fromPropertyList: info, format: .binary, options: 0)) ?? Data()
    }

    // MARK: - HTTP

    private func readRequest(client: Int32, buffer: inout Data) -> Request? {
        func fill() -> Bool {
            var chunk = [UInt8](repeating: 0, count: 4096)
            var descriptor = pollfd(fd: client, events: Int16(POLLIN), revents: 0)
            guard poll(&descriptor, 1, 5000) > 0 else { return false }
            let count = recv(client, &chunk, chunk.count, 0)
            guard count > 0 else { return false }
            buffer.append(contentsOf: chunk[0..<count])
            return true
        }

        while buffer.range(of: Data("\r\n\r\n".utf8)) == nil {
            guard fill() else { return nil }
        }
        guard let headerEnd = buffer.range(of: Data("\r\n\r\n".utf8)) else { return nil }
        let headerData = buffer[buffer.startIndex..<headerEnd.lowerBound]
        let head = String(decoding: headerData, as: UTF8.self).split(separator: "\r\n", omittingEmptySubsequences: false)
        guard let requestLine = head.first else { return nil }
        let parts = requestLine.split(separator: " ")
        guard parts.count >= 2 else { return nil }

        var headers: [String: String] = [:]
        for line in head.dropFirst() {
            guard let colon = line.firstIndex(of: ":") else { continue }
            let name = line[..<colon].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            headers[name] = value
        }

        buffer.removeSubrange(buffer.startIndex..<headerEnd.upperBound)
        let length = Int(headers["content-length"] ?? "0") ?? 0
        while buffer.count < length {
            guard fill() else { return nil }
        }
        let body = Data(buffer.prefix(length))
        buffer.removeFirst(min(length, buffer.count))
        return Request(method: String(parts[0]), path: String(parts[1]), headers: headers, body: body)
    }

    private func write(client: Int32, response: Response) {
        let head = "HTTP/1.1 \(response.status) OK\r\n" +
            "Content-Type: \(response.contentType)\r\n" +
            "Content-Length: \(response.body.count)\r\n" +
            "Server: AirTunes/220.68\r\n\r\n"
        var payload = Data(head.utf8)
        payload.append(response.body)
        _ = payload.withUnsafeBytes { send(client, $0.baseAddress, payload.count, 0) }
    }
}
