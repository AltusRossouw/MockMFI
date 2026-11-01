// swift-tools-version: 6.0
import PackageDescription

// CarPlayDesk: a macOS CarPlay accessory, built here.
//
// MFiKit holds the parts that talk to the phone: the identity (PKCS#8 key +
// PKCS#7 certificate), the iAP2 CSM framing, the AccAuthentication responder, and
// the transport. The transport goes through libimobiledevice — the same route
// LIVI uses on macOS: usbmuxd, lockdown, `com.apple.carkit.service`, TLS.
let package = Package(
    name: "CarPlayDesk",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "CarPlayDesk", targets: ["CarPlayDesk"]),
        .executable(name: "carplaydesk-cli", targets: ["CarPlayDeskCLI"]),
        .library(name: "MFiKit", targets: ["MFiKit"]),
    ],
    targets: [
        .target(
            name: "CIMobileDevice",
            path: "Sources/CIMobileDevice",
            publicHeadersPath: "include",
            cSettings: [.unsafeFlags(["-I/opt/homebrew/include"])],
            linkerSettings: [
                .linkedLibrary("imobiledevice-1.0"),
                .linkedLibrary("usbmuxd-2.0"),
                .linkedLibrary("plist-2.0"),
                .unsafeFlags(["-L/opt/homebrew/lib", "-Xlinker", "-rpath", "-Xlinker", "/opt/homebrew/lib"]),
            ]
        ),
        .target(name: "MFiKit", dependencies: ["CIMobileDevice"]),
        .executableTarget(name: "CarPlayDesk", dependencies: ["MFiKit"]),
        .executableTarget(name: "CarPlayDeskCLI", dependencies: ["MFiKit"], path: "Sources/CarPlayDeskCLI"),
        .testTarget(name: "MFiKitTests", dependencies: ["MFiKit"]),
    ],
    swiftLanguageModes: [.v5]
)
