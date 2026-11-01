# CarPlayDesk (macOS)

A macOS CarPlay accessory, built from scratch. This is M1: the MFi layer the rest of a session
depends on, plus a SwiftUI shell. LIVI is not used.

```sh
make test        # 17 tests: CSM vectors, auth responder, identity, optional real-identity run
make cli ARGS="--identity /path/to/mfi"     # headless proof: load, sign, handshake
make cli ARGS="--transport"                 # open com.apple.carkit.service on the attached iPhone
make cli ARGS="--identify"                  # link + MFi auth + identification against the phone
make cli ARGS="--airplay"                   # AirPlay receiver on :7100 (GET /info, POST /auth-setup)
make app         # builds and ad-hoc signs CarPlayDesk.app
make run
```

Requirements: macOS 14+; Xcode for `swift test` (XCTest is not in the Command Line Tools);
`brew install libimobiledevice` for the transport (the app links `/opt/homebrew` paths).

Identity layout — the same two files the C library and LIVI read:

```
~/Library/Application Support/CarPlayDesk/mfi/
  identity.pk8        PKCS#8, unencrypted, P-256
  certificate.p7b     PKCS#7 container, presented byte for byte
```

`make cli ARGS="--identify"` goes all the way to a real session handshake: iAP2 link negotiation,
the MFi certificate/challenge/signature exchange, identification, and the follow-up subscriptions.
A real iPhone has accepted authentication and identification, then refused every protocol
declaration this identity can make — so it never offers `0x4300 CarPlayAvailability`.
See the wall in [spec/11 §4b](../spec/11-macos-app.md), and the mirroring path the identity *is*
provisioned for in [§4c](../spec/11-macos-app.md). `make cli ARGS="--devices"` lists Apple USB devices with their current configuration (6 is the
CarPlay/usbmux configuration). `--transport` goes further: usbmuxd → lockdown →
`com.apple.carkit.service` → TLS, and reports the byte stream. The phone stays silent until the
accessory sends identification, which is the next piece of protocol work — see
[spec/11](../spec/11-macos-app.md).

Layout:

- `Sources/MFiKit` — identity and signing (CryptoKit + Security), CSM framing, AccAuthentication
  responder, simulated phone, USB observation.
- `Sources/CarPlayDesk` — the app: identity status, self-test, handshake log, device list.
- `Sources/CarPlayDeskCLI` — the same proofs without a window.
