import Foundation
import IOKit

/// An Apple USB device as macOS currently sees it.
public struct AppleUSBDevice: Identifiable {
    public let id: String
    public let productName: String
    public let serial: String
    public let vendorID: Int
    public let productID: Int
    /// `bConfigurationValue` — 6 is the CarPlay/usbmux configuration.
    public let configurationValue: Int?
    public let numberOfConfigurations: Int?

    public var isInCarPlayConfiguration: Bool { configurationValue == 6 }
}

/// Read-only view of the Apple devices on the bus.
///
/// Enumeration needs no entitlement. *Claiming* the usbmux interface is the part
/// that still has to be proven on macOS (see spec/11) — this type deliberately
/// stops at observation so the app can show what the cable sees before anything
/// takes ownership of a device.
public enum USBProbe {
    public static let appleVendorID = 0x05AC

    public static func appleDevices() -> [AppleUSBDevice] {
        var devices: [AppleUSBDevice] = []
        for serviceClass in ["IOUSBHostDevice", "IOUSBDevice"] {
            guard let matching = IOServiceMatching(serviceClass) else { continue }
            var iterator: io_iterator_t = 0
            guard IOServiceGetMatchingServices(kIOMainPortDefault, matching, &iterator) == KERN_SUCCESS else {
                continue
            }
            defer { IOObjectRelease(iterator) }

            var service = IOIteratorNext(iterator)
            while service != 0 {
                defer {
                    IOObjectRelease(service)
                    service = IOIteratorNext(iterator)
                }
                guard let device = makeDevice(service: service) else { continue }
                if !devices.contains(where: { $0.id == device.id }) {
                    devices.append(device)
                }
            }
        }
        return devices
    }

    private static func makeDevice(service: io_object_t) -> AppleUSBDevice? {
        func value(_ key: String) -> Any? {
            IORegistryEntryCreateCFProperty(service, key as CFString, kCFAllocatorDefault, 0)?
                .takeRetainedValue()
        }

        guard let vendor = (value("idVendor") as? NSNumber)?.intValue, vendor == appleVendorID else {
            return nil
        }
        let product = (value("idProduct") as? NSNumber)?.intValue ?? 0
        let serial = (value("USB Serial Number") as? String) ?? ""
        let name = (value("USB Product Name") as? String) ?? "Apple device"
        // The device node publishes the selected configuration as
        // kUSBCurrentConfiguration; bConfigurationValue sits on the interface nodes.
        let configuration = (value("kUSBCurrentConfiguration") as? NSNumber)?.intValue
            ?? (value("bConfigurationValue") as? NSNumber)?.intValue
        let configurations = (value("bNumConfigurations") as? NSNumber)?.intValue

        return AppleUSBDevice(
            id: "\(vendor):\(product):\(serial)",
            productName: name,
            serial: serial,
            vendorID: vendor,
            productID: product,
            configurationValue: configuration,
            numberOfConfigurations: configurations
        )
    }
}
