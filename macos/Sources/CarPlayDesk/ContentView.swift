import Foundation
import AppKit
import SwiftUI
import MFiKit

@MainActor
final class AppModel: ObservableObject {
    enum IdentityState {
        case missing
        case loaded(summary: String)
        case failed(String)
    }

    @Published var identityDirectory: URL = MFiIdentity.defaultDirectory
    @Published private(set) var identityState: IdentityState = .missing
    @Published private(set) var identity: MFiIdentity?
    @Published private(set) var selfTest: String = "not run"
    @Published private(set) var events: [SimulationEvent] = []
    @Published private(set) var devices: [AppleUSBDevice] = []
    @Published private(set) var lastError: String?
    @Published private(set) var transportStatus: String = "not probed"
    @Published private(set) var transportBusy = false
    @Published private(set) var wireStatus: String = "not run"
    @Published private(set) var wireBusy = false

    init() {
        load()
        refreshDevices()
    }

    var identityPath: String { identityDirectory.path }

    func chooseDirectory() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        panel.prompt = "Use identity folder"
        panel.message = "Pick the folder that holds identity.pk8 and certificate.p7b"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        identityDirectory = url
        load()
    }

    func load() {
        lastError = nil
        do {
            try FileManager.default.createDirectory(
                at: identityDirectory,
                withIntermediateDirectories: true
            )
            let loaded = try MFiIdentity(directory: identityDirectory)
            identity = loaded
            identityState = .loaded(summary: loaded.summary())
            selfTest = "not run"
        } catch {
            identity = nil
            identityState = .failed("\(error)")
        }
    }

    func runSelfTest() {
        guard let identity else {
            selfTest = "load an identity first"
            return
        }
        do {
            let signature = try identity.selfTest()
            selfTest = "ok — \(signature.count)-byte raw r||s over a fixed digest verifies"
        } catch {
            selfTest = "failed — \(error)"
        }
    }

    func runSimulation() {
        guard let identity else {
            events = [SimulationEvent(direction: "note", text: "load an identity first")]
            return
        }
        do {
            events = try SimulatedPhone.run(identity: identity)
        } catch {
            events.append(SimulationEvent(direction: "note", text: "failed — \(error)"))
        }
    }

    func runWireSession() {
        guard !wireBusy, let identity else { return }
        wireBusy = true
        wireStatus = "opening com.apple.carkit.service …"
        DispatchQueue.global(qos: .userInitiated).async {
            var lines: [String] = []
            let devices = CarKitTransport.devices()
            guard let target = devices.first(where: { $0.connection == "USB" }) else {
                DispatchQueue.main.async {
                    self.wireStatus = "no USB device attached"
                    self.wireBusy = false
                }
                return
            }
            do {
                let link = try CarKitLink(udid: target.udid)
                defer { link.close() }
                lines.append("carkit: open, ssl=\(link.ssl)")
                var start: CarPlayStartSession?
                if let interface = LocalNetwork.carPlayInterface(), let address = interface.linkLocalIPv6 {
                    lines.append("av interface: \(interface.name) \(address)")
                    start = CarPlayStartSession(
                        ipAddresses: [address],
                        port: 7000,
                        deviceIdentifier: identity.airPlayDeviceID
                    )
                }
                let session = MFISession(identity: identity)
                let run = try session.run(link: link, identification: AccessoryIdentification(), startSession: start, timeout: 20)
                lines.append(contentsOf: run.log)
                switch run.outcome {
                case .authSucceeded: lines.append("result: MFi authentication succeeded")
                case .identificationRejected(let fields): lines.append("result: identification rejected, fields \(fields)")
                case .timedOut: lines.append("result: timed out")
                }
            } catch {
                lines.append("error: \(error)")
            }
            DispatchQueue.main.async {
                self.wireStatus = lines.joined(separator: "\n")
                self.wireBusy = false
            }
        }
    }

    func refreshDevices() {
        devices = USBProbe.appleDevices()
    }

    /// Opens `com.apple.carkit.service` and reports what the phone does. Blocking,
    /// so it runs off the main thread.
    func probeTransport() {
        guard !transportBusy else { return }
        transportBusy = true
        transportStatus = "opening com.apple.carkit.service …"
        DispatchQueue.global(qos: .userInitiated).async {
            var lines: [String] = []
            let devices = CarKitTransport.devices()
            lines.append("lockdown devices: \(devices.count)")
            for device in devices {
                lines.append("  \(device.udid) [\(device.connection)]")
            }
            if let target = devices.first(where: { $0.connection == "USB" }) ?? devices.first {
                do {
                    let link = try CarKitLink(udid: target.udid)
                    lines.append("carkit: open, ssl=\(link.ssl)")
                    if let greeting = try? link.read(max: 4096, timeoutMs: 1500), !greeting.isEmpty {
                        let hex = greeting.prefix(24).map { String(format: "%02x", $0) }.joined(separator: " ")
                        lines.append("greeting: \(greeting.count) bytes — \(hex)")
                    } else {
                        lines.append("greeting: none within 1.5 s")
                    }
                    let request = (try? CSM.frame(messageID: AccAuth.requestCertificate)) ?? Data()
                    try? link.write(request)
                    let reply = (try? link.read(max: 4096, timeoutMs: 1500)) ?? Data()
                    lines.append("0xAA00 reply: \(reply.isEmpty ? "none (identification first)" : "\(reply.count) bytes")")
                    link.close()
                } catch {
                    lines.append("transport error: \(error)")
                }
            } else {
                lines.append("no device attached")
            }
            DispatchQueue.main.async {
                self.transportStatus = lines.joined(separator: "\n")
                self.transportBusy = false
            }
        }
    }
}

struct ContentView: View {
    @ObservedObject var model: AppModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                header
                identitySection
                mfiSection
                handshakeSection
                deviceSection
                transportSection
                wireSection
                roadmap
            }
            .padding(20)
        }
        .frame(minWidth: 760, minHeight: 620)
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("CarPlayDesk")
                .font(.largeTitle.weight(.semibold))
            Text("A macOS CarPlay accessory, built here: MFi authentication first, USB transport next.")
                .foregroundStyle(.secondary)
        }
    }

    private var identitySection: some View {
        GroupBox("Identity") {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Text(model.identityPath)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .lineLimit(2)
                    Spacer()
                    Button("Choose…") { model.chooseDirectory() }
                    Button("Reload") { model.load() }
                }
                switch model.identityState {
                case .missing:
                    Label("No identity yet", systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                case .loaded(let summary):
                    Label(summary, systemImage: "checkmark.seal")
                        .foregroundStyle(.green)
                case .failed(let message):
                    Label(message, systemImage: "xmark.seal")
                        .foregroundStyle(.red)
                }
                Text("identity.pk8 + certificate.p7b, the same layout libmfi and LIVI read.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .padding(6)
        }
    }

    private var mfiSection: some View {
        GroupBox("MFi signature") {
            VStack(alignment: .leading, spacing: 8) {
                Text(model.selfTest)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                Button("Run self-test") { model.runSelfTest() }
                    .disabled(model.identity == nil)
                Text("Signs a fixed 32-byte digest with the key and verifies it, the same check the C library performs.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .padding(6)
        }
    }

    private var handshakeSection: some View {
        GroupBox("AccAuthentication handshake (simulated phone)") {
            VStack(alignment: .leading, spacing: 8) {
                Button("Run handshake") { model.runSimulation() }
                    .disabled(model.identity == nil)
                if !model.events.isEmpty {
                    VStack(alignment: .leading, spacing: 2) {
                        ForEach(model.events) { event in
                            HStack(alignment: .firstTextBaseline, spacing: 8) {
                                Text(event.direction)
                                    .font(.system(.caption2, design: .monospaced))
                                    .foregroundStyle(.secondary)
                                    .frame(width: 150, alignment: .leading)
                                Text(event.text)
                                    .font(.system(.caption, design: .monospaced))
                                    .textSelection(.enabled)
                            }
                        }
                    }
                    .padding(8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 6))
                }
                Text("0xAA00 → certificate, 0xAA02 → signature, 0xAA05 → done. Over USB this runs on the iAP2 link.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .padding(6)
        }
    }

    private var deviceSection: some View {
        GroupBox("Apple devices on USB") {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Button("Refresh") { model.refreshDevices() }
                    Spacer()
                    Text("\(model.devices.count) device(s)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                if model.devices.isEmpty {
                    Text("No Apple device attached.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(model.devices) { device in
                        HStack {
                            Text(device.productName).bold()
                            Text(String(format: "%04X:%04X", device.vendorID, device.productID))
                                .font(.system(.caption, design: .monospaced))
                            if let configuration = device.configurationValue {
                                Text("config \(configuration)")
                                    .font(.system(.caption, design: .monospaced))
                                    .foregroundStyle(device.isInCarPlayConfiguration ? .green : .secondary)
                            }
                            Spacer()
                            Text(device.serial.isEmpty ? "no serial" : device.serial)
                                .font(.system(.caption, design: .monospaced))
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                Text("Observation only: claiming the usbmux interface on macOS is the next gate (spec/11).")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .padding(6)
        }
    }

    private var wireSection: some View {
        GroupBox("Identification + MFi authentication") {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Button("Identify to the phone") { model.runWireSession() }
                        .disabled(model.wireBusy || model.identity == nil)
                    if model.wireBusy {
                        ProgressView().controlSize(.small)
                    }
                    Spacer()
                }
                Text(model.wireStatus)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                Text("The phone asks for the certificate first, then a challenge; identification is accepted afterwards.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .padding(6)
        }
    }

    private var transportSection: some View {
        GroupBox("Transport — com.apple.carkit.service") {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Button("Probe carkit") { model.probeTransport() }
                        .disabled(model.transportBusy)
                    if model.transportBusy {
                        ProgressView().controlSize(.small)
                    }
                    Spacer()
                }
                Text(model.transportStatus)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                Text("usbmuxd owns the cable; lockdown authenticates the Mac and StartService hands back this stream.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .padding(6)
        }
    }

    private var roadmap: some View {
        GroupBox("Where this is going") {
            VStack(alignment: .leading, spacing: 4) {
                Label("MFi identity + AccAuthentication responder — done", systemImage: "checkmark.circle")
                Label("CSM framing with the dossier's vectors — done", systemImage: "checkmark.circle")
                Label("Transport: carkit service over usbmuxd + lockdown + TLS — done", systemImage: "checkmark.circle")
                Label("Link negotiation + identification accepted by a real iPhone — done", systemImage: "checkmark.circle")
                Label("MFi authentication on the wire (0xAA05) — done", systemImage: "checkmark.circle")
                Label("CarPlayStartSession → MFi4 → AirPlay — next", systemImage: "circle")
                Label("H.264 via VideoToolbox, audio, touch HID", systemImage: "circle")
            }
            .font(.callout)
            .padding(6)
        }
    }
}
