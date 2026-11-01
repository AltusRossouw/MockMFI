import Foundation
import Darwin

/// IPv4/IPv6 facts about the Mac's interfaces, enough to find the iPhone's NCM link.
public enum LocalNetwork {
    public struct Interface {
        public let name: String
        public let linkLocalIPv6: String?
        public let ipv4: String?
    }

    public static func interfaces() -> [Interface] {
        var result: [Interface] = []
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return [] }
        defer { freeifaddrs(head) }

        var seen: [String: (v6: String?, v4: String?)] = [:]
        var pointer: UnsafeMutablePointer<ifaddrs>? = first
        while let entry = pointer {
            defer { pointer = entry.pointee.ifa_next }
            let name = String(cString: entry.pointee.ifa_name)
            guard let address = entry.pointee.ifa_addr else { continue }
            let family = address.pointee.sa_family
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            let length = socklen_t(address.pointee.sa_len)
            guard getnameinfo(address, length, &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 else {
                continue
            }
            let text = String(cString: host)
            var current = seen[name] ?? (nil, nil)
            switch Int32(family) {
            case AF_INET6:
                if text.hasPrefix("fe80"), current.v6 == nil { current.v6 = text }
            case AF_INET:
                if current.v4 == nil { current.v4 = text }
            default:
                break
            }
            seen[name] = current
        }
        for (name, value) in seen.sorted(by: { $0.key < $1.key }) {
            result.append(Interface(name: name, linkLocalIPv6: value.v6, ipv4: value.v4))
        }
        return result
    }

    /// Hardware address of an interface, e.g. `72:22:fe:c8:b5:66`.
    public static func macAddress(of name: String) -> String? {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return nil }
        defer { freeifaddrs(head) }
        var pointer: UnsafeMutablePointer<ifaddrs>? = first
        while let entry = pointer {
            defer { pointer = entry.pointee.ifa_next }
            guard String(cString: entry.pointee.ifa_name) == name,
                  let address = entry.pointee.ifa_addr,
                  Int32(address.pointee.sa_family) == AF_LINK else { continue }
            // sockaddr_dl: len, family, index(2), type, nlen, alen, slen, then data.
            // The hardware address starts at data + nlen, i.e. offset 8 + nlen.
            let raw = UnsafeRawPointer(address)
            let nameLength = Int(raw.load(fromByteOffset: 5, as: UInt8.self))
            let addressLength = Int(raw.load(fromByteOffset: 6, as: UInt8.self))
            guard addressLength >= 6 else { return nil }
            let bytes = (0..<6).map { raw.load(fromByteOffset: 8 + nameLength + $0, as: UInt8.self) }
            if ProcessInfo.processInfo.environment["CPD_DEBUG_MAC"] == "1" {
                let dump = (0..<20).map { raw.load(fromByteOffset: $0, as: UInt8.self) }
                FileHandle.standardError.write(Data("mac debug \(name): len=\(dump[0]) fam=\(dump[1]) nlen=\(nameLength) alen=\(addressLength) raw=\(dump.map { String(format: "%02x", $0) }.joined(separator: " "))\n".utf8))
            }
            return bytes.map { String(format: "%02x", $0) }.joined(separator: ":")
        }
        return nil
    }

    /// The iPhone's NCM interface: a link-local IPv6 plus a self-assigned 169.254
    /// address, not the Mac's primary interface.
    public static func carPlayInterface() -> Interface? {
        // Apple's internal anpi/ap/nan interfaces also carry 169.254 addresses and
        // dummy MACs; the phone's NCM link is a plain "en" interface.
        let candidates = interfaces().filter { interface in
            guard interface.name.hasPrefix("en"), interface.name != "en0" else { return false }
            guard interface.linkLocalIPv6 != nil, let ipv4 = interface.ipv4 else { return false }
            return ipv4.hasPrefix("169.254.")
        }
        return candidates.first
    }
}
