import Foundation
import MFiKit

// Headless companion to the app: proves the MFi layer on any Mac, with no window
// and no phone. Exit code 0 means the identity signs and the handshake completes.

var identityDirectory = MFiIdentity.defaultDirectory
var runSimulation = true
var listDevices = false
var probeTransport = false
var identify = false
var airplay = false
var airplayPort: UInt16 = 7100
var listInterfaces = false

var arguments = Array(CommandLine.arguments.dropFirst())
while let argument = arguments.first {
    arguments.removeFirst()
    switch argument {
    case "--identity":
        guard let value = arguments.first else {
            FileHandle.standardError.write(Data("--identity needs a directory\n".utf8))
            exit(2)
        }
        arguments.removeFirst()
        identityDirectory = URL(fileURLWithPath: value)
    case "--no-simulate":
        runSimulation = false
    case "--devices":
        listDevices = true
    case "--transport":
        probeTransport = true
    case "--identify":
        identify = true
    case "--airplay":
        airplay = true
    case "--ifaces":
        listInterfaces = true
    case "--port":
        guard let value = arguments.first.flatMap(UInt16.init) else {
            FileHandle.standardError.write(Data("--port needs a number\n".utf8))
            exit(2)
        }
        arguments.removeFirst()
        airplayPort = value
    case "--help", "-h":
        print("""
        usage: carplaydesk-cli [--identity DIR] [--no-simulate] [--devices] [--transport] [--identify]

          --identity DIR   folder with identity.pk8 + certificate.p7b
                           (default: \(MFiIdentity.defaultDirectory.path))
          --no-simulate    only load the identity and run the signature self-test
          --devices        list Apple USB devices currently attached
          --transport      open com.apple.carkit.service over usbmuxd + lockdown and
                           report whether the phone hands back a byte stream
          --identify       identify as a CarPlay accessory and run the MFi exchange
          --airplay        run the AirPlay receiver (GET /info, POST /auth-setup) on :7000
        """)
        exit(0)
    default:
        FileHandle.standardError.write(Data("unknown argument: \(argument)\n".utf8))
        exit(2)
    }
}

if listDevices {
    let devices = USBProbe.appleDevices()
    if devices.isEmpty {
        print("no Apple USB device attached")
    } else {
        for device in devices {
            let configuration = device.configurationValue.map(String.init) ?? "?"
            print(String(format: "%04X:%04X  config %@  %@  %@",
                         device.vendorID, device.productID, configuration,
                         device.productName, device.serial))
        }
    }
    exit(0)
}

if listInterfaces {
    for interface in LocalNetwork.interfaces() {
        let mac = LocalNetwork.macAddress(of: interface.name) ?? "-"
        print("\(interface.name)\t\(interface.ipv4 ?? "-")\t\(interface.linkLocalIPv6 ?? "-")\t\(mac)")
    }
    exit(0)
}

if ProcessInfo.processInfo.environment["CPD_DUMP_IDENT"] == "1" {
    var identification = AccessoryIdentification()
    let env = ProcessInfo.processInfo.environment
    if let name = env["CPD_PROTO_NAME"] { identification.protocolName = name }
    if let match = env["CPD_PROTO_MATCH"].flatMap(UInt8.init) { identification.protocolMatchAction = match }
    if let carplay = env["CPD_PROTO_CARPLAY"] { identification.protocolCarPlay = carplay != "0" }
    if let transport = env["CPD_PROTO_TRANSPORT"] {
        identification.protocolTransportID = transport == "none" ? nil : UInt16(transport)
    }
    let frame = try identification.informationFrame()
    let hex = frame.map { String(format: "%02x", $0) }.joined()
    print(hex)
    var decoder = CSMDecoder()
    for parameter in decoder.push(frame).first?.parameters ?? [] {
        print("param \(parameter.id) len \(parameter.payload.count): \(parameter.payload.map { String(format: "%02x", $0) }.joined())")
    }
    exit(0)
}

if airplay {
    do {
        let identity = try MFiIdentity(directory: identityDirectory)
        let deviceID = identity.airPlayDeviceID
        let server = AirPlayServer(port: airplayPort, identity: identity, deviceID: deviceID) { line in
            print(line)
            fflush(stdout)
        }
        print("AirPlay receiver for \(identity.summary())")
        try server.runOnce(timeout: 3600)
        exit(0)
    } catch {
        FileHandle.standardError.write(Data("airplay: \(error)\n".utf8))
        exit(1)
    }
}

if identify {
    let identity: MFiIdentity
    do {
        identity = try MFiIdentity(directory: identityDirectory)
    } catch {
        FileHandle.standardError.write(Data("identity: \(error)\n".utf8))
        exit(1)
    }
    let devices = CarKitTransport.devices()
    guard let target = devices.first(where: { $0.connection == "USB" }) else {
        FileHandle.standardError.write(Data("no USB device to identify to\n".utf8))
        exit(1)
    }
    print("identifying to \(target.udid)")
    do {
        let link = try CarKitLink(udid: target.udid)
        defer { link.close() }
        print("carkit: open, ssl=\(link.ssl)")
        var identification = AccessoryIdentification()
        let env = ProcessInfo.processInfo.environment
        if let name = env["CPD_PROTO_NAME"] { identification.protocolName = name }
        if let match = env["CPD_PROTO_MATCH"].flatMap(UInt8.init) { identification.protocolMatchAction = match }
        if let carplay = env["CPD_PROTO_CARPLAY"] { identification.protocolCarPlay = carplay != "0" }
        if let transport = env["CPD_PROTO_TRANSPORT"] {
            identification.protocolTransportID = transport == "none" ? nil : UInt16(transport)
        }
        if let iface = env["CPD_IFACE"].flatMap(UInt8.init) { identification.carPlayInterfaceNumber = iface }
        if env["CPD_PROTO_FORM"] == "strings" { identification.protocolAsStringList = true }
        if let team = env["CPD_TEAM_ID"] { identification.appMatchTeamID = team }
        if env["CPD_COMPONENTS"] == "1" { identification.declaresVehicleComponents = true }
        if env["CPD_LIST_PROFILE"] == "minimal" {
            identification.messagesSent = AccessoryIdentification.carPlayMinimalSent
            identification.messagesReceived = AccessoryIdentification.carPlayMinimalReceived
        }
        if env["CPD_FULL_LISTS"] == "1" {
            identification.messagesSent = AccessoryIdentification.carPlaySent
            identification.messagesReceived = AccessoryIdentification.carPlayReceived
        }
        if env["CPD_DEV_TRANSPORT"] == "1" {
            identification.declaresUSBDeviceTransport = true
            identification.declaresUSBHostTransport = env["CPD_HOST_TRANSPORT"] != "0"
        }
        var start: CarPlayStartSession?
        let ifaceName = ProcessInfo.processInfo.environment["CPD_AV_IFACE"]
        if let interface = ifaceName.flatMap({ name in LocalNetwork.interfaces().first { $0.name == name } })
            ?? LocalNetwork.carPlayInterface() {
            start = CarPlayStartSession(
                ipAddresses: interface.linkLocalIPv6.map { [$0] } ?? [],
                port: 7100,
                deviceIdentifier: identity.airPlayDeviceID
            )
            print("av interface: \(interface.name) \(interface.linkLocalIPv6 ?? "no link-local")")
        } else {
            print("av interface: none found (no 169.254 link-local interface)")
        }
        let listener = AirPlayListener(port: 7100)
        if start != nil {
            do {
                try listener.open()
                print("listening on :7100 for the phone")
            } catch {
                print("listener: \(error)")
            }
        }
        let session = MFISession(identity: identity)
        let run = try session.run(link: link, identification: identification, startSession: start, timeout: 14)
        if start != nil, let connection = listener.acceptFirstConnection(timeout: 5) {
            let hex = connection.firstBytes.prefix(48).map { String(format: "%02x", $0) }.joined(separator: " ")
            let text = String(data: connection.firstBytes.prefix(48), encoding: .utf8) ?? ""
            print("phone connected from \(connection.peer), \(connection.firstBytes.count) bytes")
            print("  hex: \(hex)")
            print("  text: \(text.replacingOccurrences(of: "\r\n", with: " | "))")
        } else if start != nil {
            print("phone did not connect to :7000")
        }
        listener.close()
        for line in run.log { print("  \(line)") }
        switch run.outcome {
        case .authSucceeded:
            print("result: MFi authentication succeeded on the wire")
            exit(0)
        case .identificationRejected(let fields):
            print("result: identification rejected, fields \(fields)")
            exit(3)
        case .timedOut:
            print("result: timed out")
            exit(2)
        }
    } catch {
        FileHandle.standardError.write(Data("session error: \(error)\n".utf8))
        exit(1)
    }
}

if probeTransport {
    let devices = CarKitTransport.devices()
    print("lockdown devices: \(devices.count)")
    for device in devices {
        print("  \(device.udid)  [\(device.connection)]")
    }
    guard let target = devices.first(where: { $0.connection == "USB" }) ?? devices.first else {
        FileHandle.standardError.write(Data("no device to probe\n".utf8))
        exit(1)
    }
    print("opening com.apple.carkit.service on \(target.udid) …")
    do {
        let link = try CarKitLink(udid: target.udid)
        print("carkit: open, ssl=\(link.ssl)")
        for attempt in 1...4 {
            let start = Date()
            do {
                let data = try link.read(max: 4096, timeoutMs: 800)
                let ms = Int(Date().timeIntervalSince(start) * 1000)
                let hex = data.prefix(32).map { String(format: "%02x", $0) }.joined(separator: " ")
                print("  read \(attempt): \(data.count) bytes in \(ms) ms \(data.isEmpty ? "" : "— " + hex)")
            } catch {
                let ms = Int(Date().timeIntervalSince(start) * 1000)
                print("  read \(attempt): \(ms) ms, error \(error)")
            }
        }
        // Experimental: the phone normally waits for identification first, but a
        // certificate request tells us whether anything answers on this stream.
        let request = try CSM.frame(messageID: AccAuth.requestCertificate)
        try link.write(request)
        print("  wrote 0xAA00 (\(request.count) bytes), waiting 2 s")
        let reply = try link.read(max: 8192, timeoutMs: 2000)
        if reply.isEmpty {
            print("  reply: none")
        } else {
            let hex = reply.prefix(64).map { String(format: "%02x", $0) }.joined(separator: " ")
            print("  reply: \(reply.count) bytes — \(hex)")
        }
        link.close()
        print("carkit: closed")
    } catch {
        FileHandle.standardError.write(Data("transport error: \(error)\n".utf8))
        exit(1)
    }
    exit(0)
}

do {
    let identity = try MFiIdentity(directory: identityDirectory)
    print("identity: \(identityDirectory.path)")
    print("  \(identity.summary())")

    let signature = try identity.selfTest()
    print("selftest: ok (\(signature.count)-byte raw r||s, verifies)")

    if runSimulation {
        let events = try SimulatedPhone.run(identity: identity)
        print("simulate: ok (\(events.count) events)")
        for event in events where event.direction != "note" {
            print("  \(event.direction): \(event.text)")
        }
    }
    exit(0)
} catch {
    FileHandle.standardError.write(Data("error: \(error)\n".utf8))
    exit(1)
}
