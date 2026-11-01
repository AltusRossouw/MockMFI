# CarPlayDesk: a macOS CarPlay accessory, built from scratch

This note starts a second product line in this repository. The Pi/LIVI work is a Linux head unit
that borrows GPL code; this branch is a **native macOS app** that implements the accessory side
itself. LIVI is not linked, vendored or required here — its protocol work stays a reference, and the
wire facts in [spec/02](02-protocol.md) and [spec/06](06-livi-integration.md) stay the contract.

Branch: `feat/macos-usb-carplay`. Everything below was built and run on this machine
(macOS 27.2, arm64, Swift 6.4) against a real iPhone 14 Pro (iPhone15,2, iOS 27.2) on 2026-10-29.

## 1. Why not just wrap LIVI

| | LIVI | CarPlayDesk |
| --- | --- | --- |
| Target | Linux head unit (DRM/KMS, GStreamer, GPL) | macOS app (SwiftUI, VideoToolbox, CoreAudio) |
| MFi | one of three back-ends inside a larger stack | the layer this app is built around |
| Transport | usbfs via `nusb` on Linux | usbmuxd + lockdown + a TLS service stream |
| Licence | GPL-3.0-or-later, whole product | this repository's terms |

The macOS transport is not the Linux one at all, which is the main reason a port would not have
helped: on macOS Apple's own `usbmuxd` owns the cable, and the CarPlay link is reached through
lockdown rather than by claiming a USB interface.

## 2. What exists on this branch

```
macos/
  Package.swift                 SwiftPM: CIMobileDevice + MFiKit + CarPlayDesk + carplaydesk-cli
  Sources/CIMobileDevice/       C shim over libimobiledevice (lockdown, service, TLS, I/O)
  Sources/MFiKit/
    Identity.swift              PKCS#8 load, raw-digest signing, DER↔raw, self-test
    CSM.swift                   iAP2 CSM framing + incremental decoder
    IAP2Auth.swift              AccAuthentication responder (0xAA00–0xAA05)
    SimulatedPhone.swift        phone stand-in that drives the responder
    USB.swift                   read-only IOKit view of Apple devices
    CarKit.swift                transport: devices, `com.apple.carkit.service`, read/write
  Sources/CarPlayDesk/          SwiftUI app: identity, self-test, handshake, devices, transport
  Sources/CarPlayDeskCLI/       headless proof: --identity, --devices, --transport
  Tests/MFiKitTests/            16 hermetic tests + 1 env-gated integration test
```

### 2.1 Signing without a re-hash

MFi signs a **final digest**: no hashing at the accessory. CryptoKit's signing API always hashes
its input and `SHA256Digest` has no public initialiser, so the identity uses two frameworks:

- **CryptoKit** parses the unencrypted PKCS#8 (`P256.Signing.PrivateKey(derRepresentation:)`).
- **Security** signs the digest itself: `SecKeyCreateWithData` accepts the x9.63 private form
  (`0x04 || X || Y || K`), and `SecKeyCreateSignature(.ecdsaSignatureDigestX962SHA256)` signs the
  32-byte digest as-is.
- The DER result is unwrapped to the 64-byte `r||s` MFi expects; `derSignature(fromRaw:)` puts it
  back for verification.

### 2.2 CSM and AccAuthentication

`CSM.frame`/`parseParameters`/`CSMDecoder` reproduce the dossier's framing including its tolerance
rules. `IAP2AuthResponder` answers `0xAA00` with the certificate byte for byte, signs `0xAA02`'s
challenge, throws on `0xAA04`, completes on `0xAA05`; challenges are 1..128 and, for P-256, exactly
32 bytes for a signature to exist. `SimulatedPhone` drives the same frames a phone sends and checks
the certificate, the signature and completion.

## 3. The macOS transport and link layer, as they actually work

```
CarPlayDesk ──► usbmuxd (/var/run/usbmuxd)
             └► lockdown :62078   QueryType / GetValue / StartSession
                 └► StartService "com.apple.carkit.service" → port + ssl
                     └► idevice_connect(port) + TLS  →  byte stream  →  iAP2
```

This is the route LIVI uses on macOS (`iap2-wired` → `idevice` → `usbmuxd`, service
`com.apple.carkit.service`), and it is the only one that works: the USB interfaces belong to Apple's
drivers, and `usbmuxd` will not let a second client claim the device. The app therefore does not
claim USB at all. It speaks to the daemon, which is why this works without entitlements.

Implementation: a small C shim (`Sources/CIMobileDevice`) over libimobiledevice
(`brew install libimobiledevice`), with `cpd_open_carkit` doing device lookup → lockdown handshake
→ `StartService` → connect → `idevice_connection_enable_ssl`.

Above the stream sits iAP2's **link layer**, which is not optional: the phone starts with a
six-byte marker (`FF 55 02 00 EE 10`), then a SYN carrying link parameters, and only accepts data
packets after the ACK exchange. Each packet has a 9-byte header (`FF5A | u16 length | control |
seq | ack | session`, checksum in the last byte) and data carries a payload checksum byte. Link
frames are `IAP2Link`; CSM frames are its payload.

One library quirk worth recording: `idevice_connection_receive_timeout` on an **SSL** connection
returns success with a bogus length on an idle stream (7 bytes, unchanged buffer). `cpd_read`
therefore `poll()`s the socket first and only then calls `idevice_connection_receive`.

## 4. Verified on this machine

```
$ make test
Executed 17 tests, with 1 test skipped and 0 failures      # hermetic default

$ swift run -q carplaydesk-cli --identity /tmp/mfikey
identity: /tmp/mfikey
  certificate container 607 bytes, sha256 634a93dd6c433808…, protocol major 3
selftest: ok (64-byte raw r||s, verifies)
simulate: ok (8 events)
  phone → accessory: 0xAA00 RequestAuthenticationCertificate
  accessory → phone: 0xAA01, 617 bytes
  phone → accessory: 0xAA02 challenge (32 bytes)
  accessory → phone: 0xAA03, 74 bytes
  phone → accessory: 0xAA05 AuthenticationSucceeded

$ swift run -q carplaydesk-cli --identify          # iPhone attached, unlocked, trusted
identifying to 00008120-001A28C03A38C01E
carkit: open, ssl=true
  → iAP2 marker + SYN (link negotiation)
  ← SYN from the phone, ACK sent
  ← link negotiated
  ← 0xAA00 RequestAuthenticationCertificate
  → 0xAA01 certificate (607 bytes) (617 bytes)
  ← 0xAA02 challenge (32 bytes)
  → 0xAA03 signature (64 bytes) (74 bytes)
  ← 0xAA05 AuthenticationSucceeded
  → 0x1D00 StartIdentification (6 bytes)
  → 0x1D01 IdentificationInformation (169 bytes)
  ← 0x1D00, 0 bytes (ignored)
  ← 0x1D02 IdentificationAccepted

  ← 0x1D02 IdentificationAccepted
  → 0xAE03 PowerSourceUpdate, 0xAE00/0x5200/0x4154/0x4157 subscriptions
  (the phone offered no 0x4300 CarPlayAvailability in 12 s)

$ swift run -q carplaydesk-cli --transport         # iPhone attached, unlocked, trusted
lockdown devices: 1
  00008120-001A28C03A38C01E  [USB]
opening com.apple.carkit.service on 00008120-001A28C03A38C01E …
carkit: open, ssl=true
  read 1: 0 bytes in 801 ms
  read 2: 0 bytes in 801 ms
  wrote 0xAA00 (6 bytes), waiting 2 s
  reply: none
carkit: closed
```

What that means, precisely:

- The phone hands back a **TLS-wrapped byte stream** on `com.apple.carkit.service`. macOS's hardest
  gate (device ownership) is solved without a driver extension.
- **MFi authentication completes against a real iPhone**: certificate out, 32-byte challenge in,
  64-byte raw `r||s` out, `0xAA05 AuthenticationSucceeded` back. The key is the artifact identity;
  the signature is produced by Security.framework over the raw digest.
- **Identification is accepted** (`0x1D02`) with this app's own parameters.
- The stream is silent until the accessory speaks, which is why the link layer must go first.

Note the two hashes: `634a93dd…` is the 607-byte PKCS#7 **container** this app sends; spec/01
records `58d50d66…`, the DER certificate inside it.

## 4a. What the phone actually asked for

Three findings worth writing down, because each one cost a run:

1. **Auth comes before identification.** Right after link negotiation the phone sends `0xAA00`,
   not `0x1D00`. The accessory must answer the MFi exchange first and identify afterwards.
2. **Identification must not advertise itself.** Listing `0x1D00`/`0x1D01` in
   `messages_sent_by_accessory`, or `0x1D02`/`0x1D03` in the received list, makes the phone reject
   the message with those exact parameters flagged (fields 6 and 7).
3. **A declared external-accessory protocol is rejected** (field 10) for every shape tried —
   `com.apple.carplay` with the CarPlay flag and a transport id, the LIVI-style
   `dev.f-io.livi` without them, and match actions 1 and 4. Omitting parameter 10 entirely is
   accepted, so the app ships without it until the correct declaration is known.
4. **Availability is not offered yet.** After identification the accessory sends the wired
   power-source update and the four `Start…Updates` subscriptions (0xAE03, 0xAE00, 0x5200,
   0x4154, 0x4157); the phone has not answered with `0x4300 CarPlayAvailability`, so
   `0x4301 CarPlayStartSession` is built and waiting but has never been sent.
5. **Protocol declarations were rejected — until the field width was fixed.** `ExternalAccessoryProtocol.id`
   is a **u8**, not a u16. Encoding it as two bytes made the phone reject the whole parameter
   (field 10) in every shape tried: CarPlay group with transport id and CarPlay flag, the same
   without the transport id, LIVI's `dev.f-io.livi` shape, match actions 1 and 4, a bare string
   list, and a USB *device* transport. With `01` instead of `00 01`, the same declarations are
   accepted (`0x1D02`), CarPlay flag included. Lesson: one wrong integer width looks exactly like
   "this identity is not provisioned for it".

## 4b. Still missing: the phone never offers availability

With identification accepted (protocol declaration included), the phone still does not send
`0x4300 CarPlayAvailability`, so `0x4301` is never solicited; offering it unsolicited is ignored,
and the phone never dials the AirPlay port.

One more rejection is worth recording: declaring the CarPlay message set in
`messages_sent_by_accessory` / `messages_received_from_accessory` (LIVI's own lists) makes the
phone reject both fields (6 and 7), while the AccAuthentication-only default is accepted. So the
declared message set is validated against something this session has not satisfied yet — the same
chicken-and-egg as availability.

The decisive next step is a **reference capture**: build LIVI's helperd on this Mac (it reached
CarPlay with this identity on 2026-10-28, spec/06 §3.3) and log its exact identification bytes and
whether `0x4300` follows. Guessing further from the source has cost more runs than it saved.

## 4c. What the certificate says

The identity's MFi marker (`1.2.840.113635.100.6.36`, critical) is a 32-byte type value ending in
`0x02`:

```
04 22 04 20 00×31 02
```

That is a certificate *type*, not a protocol list: nothing in the certificate names an accessory
protocol. Together with finding 5 it points at one explanation: **this identity authenticates
(iAP2 AccAuthentication works, the phone is satisfied) but is not provisioned to declare a CarPlay
accessory protocol**, so the phone will not offer `0x4300` and no `0x4301` is ever accepted. The
wall is identity provisioning, not this code.

Two ways forward, both honest about cost:

| Path | What it needs | Cost |
| --- | --- | --- |
| A provisioned accessory identity | an MFi-issued identity whose type authorises a CarPlay accessory protocol | not purchasable outside Apple's MFi programme |
| AirPlay mirroring, what DiPlay actually does | MFiSAP v1 `/auth-setup` (libmfi implements it), an AirPlay receiver (RTSP + AES-CTR via CryptoKit/CommonCrypto), and **FairPlay** for the encrypted stream — open implementations use the reverse-engineered PlayFair library | weeks, plus the FairPlay question |

The second path is why DiPlay exists in the first place: its identity is provisioned for AirPlay
mirroring, and its `/auth-setup` path is MFiSAP v1, not iAP2 CarPlay.

## 4d. The AirPlay receiver (mirroring path)

Since the phone will not offer CarPlay with this identity, the app now speaks the path the identity
was provisioned for: AirPlay, whose `/auth-setup` is MFiSAP v1 (spec/02 §4).

`make cli ARGS="--airplay"` runs a receiver on :7100 with:

| Endpoint | Behaviour |
| --- | --- |
| `GET /info` | binary plist: deviceid, features, model `AppleTV3,2`, srcvers, vv, pk (Ed25519) |
| `POST /auth-setup` | MFiSAP v1: X25519 (CryptoKit) → SHA-1 key/IV derivation → SHA-256 digest → P-256 signature → AES-128-CTR (CommonCrypto) → `pub │ u32 │ cert │ u32 │ enc` |
| `POST /pair-setup`, `/pair-verify`, `/fp-setup` | logged with the first bytes of the body, then refused (FairPlay and SRP pairing are not implemented) |
| anything else | logged, refused |

Verified locally: `/info` returns the plist; `/auth-setup` with a synthetic 33-byte request returns
711 bytes = 32 (public) + 4 + 607 (certificate) + 4 + 64 (encrypted signature), and the unit tests
prove the peer can derive the same key/IV and verify the signature inside.

Two practical findings:

- **Port 7000 is taken by macOS itself** (`ControlCenter` listens there for the system AirPlay
  Receiver), so the app uses **7100** and advertises that port.
- **macOS redacts interface MACs** from `getifaddrs` in this process — every address reads back as
  `02:00:00:00:00:00`, while `ifconfig` shows the real one. The AirPlay device id is therefore
  derived from the certificate hash (`62:4a:93:dd:6c:43`), which is stable and needs no hardware
  access.

The receiver is advertised over Bonjour as **CarPlayDesk** (`_airplay._tcp`, TXT: deviceid,
features, model, srcvers, vv, flags, pk). What happens next is the phone's call: screen mirroring
needs SRP pairing and FairPlay, so the log will show `/pair-setup` and `/fp-setup` arriving and
being refused — which is the next gate, not a regression.

## 5. What is left, in order

| Step | What it needs | State |
| --- | --- | --- |
| **M3 — identification** | `0x1D00`/`0x1D01` with the fields this phone accepts | done: `0x1D02` accepted |
| **M3b — auth on the wire** | AccAuthentication over the link | done: `0xAA05` from a real iPhone |
| **M4a — CarPlayStartSession** | sent as `0x4301` once the phone offers `0x4300` | built and waiting; **blocked**: the phone never offers availability with this identity (§4b) |
| **M4b — MFi4** | `0x5200`→`0x5201` mutual authentication (`livi-cp/src/mfi4` is the public reference) | not started |
| **M4c — AirPlay session** | stream setup, H.264 → VideoToolbox, CoreAudio, HID | not started |
| **M5 — product** | launch behaviour, window/display handling, notarisation | not started |

## 6. What this branch does not claim

- No CarPlay screen, audio or input yet: the phone authenticates this app, but the session that
  would project its UI has not been requested (`0x5000`) or implemented.
- MFi4 and the AirPlay session are unimplemented; the MFiSAP `/auth-setup` path is not ported.
- The external-accessory-protocol declaration is omitted because every shape tried is rejected;
  what the phone expects there is still unknown.
- The identity is a development identity recovered from an artifact; a product needs its own
  licensed accessory identity.
- The transport depends on libimobiledevice being installed (`/opt/homebrew` paths are compiled in).
  A shipping app would vendor or statically link it.
