# MockMFI

Reverse engineering of the MFi authentication layer in **DiPlay 0.2.22**, plus **libmfi** — a C
library that implements the accessory side of that layer on Linux. The identity pipeline it
builds is verified against a real iPhone: **wired CarPlay over USB came up on a Mac** with the
Apple MFi identity recovered from the APK (iPhone 14 Pro, iOS 27.2, LIVI 10.1.0, 2026-10-28).

```
iPhone ──USB──> LIVI (CarPlay accessory) ──MFi──> identity (identity.pk8 + certificate.p7b)
                                        │
                                        └── iAP2 AccAuthentication + /auth-setup (MFiSAP / MFi4)
libmfi: same exchanges, same identity files, for a Linux head unit
```

## Status

| | |
| --- | --- |
| **USB CarPlay, real phone** | verified: `usbmuxd carkit up → identification accepted → MFi auth succeeded → session started`, H.265 1280×720 + audio |
| **libmfi** | iAP2 AccAuthentication `0xAA00–0xAA05`, AirPlay `/auth-setup` (MFiSAP v1), MFi coprocessor over I²C, software coprocessor, LIVI `mfid` TCP coprocessor — 164 checks, `make test` |
| **Reference model** | Node.js test double, 67 tests, cross-checked against the C library both directions |
| **Provenance** | shipped `classes3.dex` decompiled with REA/JADX; every constant confirmed ([spec/05](spec/05-rea-shipped-dex.md)) |
| **CarPlay MFi4** | not implemented in libmfi; modern iOS negotiates MFi4 at `/auth-setup` (LIVI implements it) |
| **Wireless** | native on Linux (BlueZ + hostapd); on macOS only with a LIVI Link dongle ([spec/06 §5](spec/06-livi-integration.md)) |

## Quick start

```sh
cd mfi-linux
make                 # build/libmfi.a, build/libmfi.so, build/mfid
make test            # 164 checks: framing, ECDSA raw, SAP, coprocessor, iAP2 end to end, mfid
make selftest        # CLI: sign/verify, SAP round trip, coprocessor discovery
```

The module takes an identity directory in the DiPlay/LIVI layout:

```
identity.pk8       PKCS#8 P-256 key (unencrypted)
certificate.p7b    PKCS#7 container presented to the phone, byte for byte
```

```sh
mfid --identity /etc/mfi cert       # subject, issuer, serial, SHA-256, container size
mfid --identity /etc/mfi selftest   # signs, verifies, round-trips iAP2 + SAP + coprocessor
mfid --identity /etc/mfi sign   <32-byte digest hex>     # -> 64-byte r||s
mfid --identity /etc/mfi verify <digest> <signature>     # raw-digest ECDSA
mfid --identity /etc/mfi sap    <33-byte /auth-setup body>
mfid --identity /etc/mfi net    --bind 0.0.0.0 --port 5000   # LIVI network coprocessor
mfid --target i2c --i2c /dev/i2c-1 discover                  # MFi chip at 0x10/0x11
mfid --identity /etc/mfi serve --serial /dev/ttyGS0          # iAP2 over a UART
```

C integration, in a head unit process:

```c
mfi_identity_load_dir(&id, "/etc/mfi", err, sizeof err);
mfi_auth_local_create(&auth, id, err, sizeof err);   /* takes ownership */
mfi_link_fd(&link, stream_fd, 0, err, sizeof err);   /* your USB/BLE/UART stream */
mfi_iap2_authenticate(auth, link, 30000, log, NULL, err, sizeof err);

size_t n = mfi_sap_handle(auth, body, body_len, reply, sizeof reply); /* 0 => 400 */
```

## Reproducing the USB result

The Mac run used LIVI as the CarPlay accessory and its "imported files" MFi backend, which reads
exactly the identity layout `libmfi` produces. Same identity, same signing contract:

```sh
# 1. pull the identity out of the APK and check it with libmfi
mkdir -p /tmp/mfi && chmod 700 /tmp/mfi
unzip -p DiPlay-0.2.22.apk assets/offline-mfi/identity.pk8       > /tmp/mfi/identity.pk8
unzip -p DiPlay-0.2.22.apk assets/offline-mfi/certificate.p7b    > /tmp/mfi/certificate.p7b
chmod 600 /tmp/mfi/*
mfi-linux/build/mfid --identity /tmp/mfi cert

# 2. install LIVI (macOS: the -arm64.dmg from github.com/f-io/LIVI/releases)
# 3. give LIVI the identity
mkdir -p "$HOME/Library/Application Support/LIVI/mfi"
cp /tmp/mfi/identity.pk8 /tmp/mfi/certificate.p7b "$HOME/Library/Application Support/LIVI/mfi/"

# 4. run LIVI, plug the iPhone in, trust it, allow CarPlay
open -a ~/Applications/LIVI.app
tail -f /tmp/livi.log | grep -E "MFi|wired|CarPlay|auth-setup"
```

Observed on a wired session:

```
[wired] 00008120: usbmuxd carkit up, starting iAP2
[cp] wired: identification accepted
[cp] wired: MFi auth succeeded
[cp] CarPlayStartSession … mutual-auth
[cp] mfi4 0x5100 -> 0x5201 (SetUp)      … [cp] mfi4: the phone and LIVI proved each other
[cpStack] RECORD (session started)
[gst_video] codec=h265 decoder=vtdec (hw) … decoded 1280x720
[core] CarPlay audio media started
```

On macOS LIVI signs with its own file backend; on Linux the same identity is served by the same
files, by `mfid net` (LIVI's `mfid` protocol on :5000), or by a real coprocessor on I²C. All three
were cross-checked: LIVI's `FileCoprocessor` and `NcmCoprocessor` built against our service
produce signatures our library verifies, and vice versa.

## What was reverse engineered

- **iAP2 CSM** `40 40 | u16 len | u16 msgId | params`, params `u16 len | u16 id | payload`.
- **AccAuthentication** `0xAA00 → 0xAA01` (param 0 = whole PKCS#7 container), `0xAA02 → 0xAA03`
  (param 0 = 64-byte raw `r||s`), `0xAA04`/`0xAA05`; challenge 1..128, 30 s budget.
- **AirPlay `/auth-setup`** MFiSAP v1: `01 || X25519 pub`, `AES-KEY`/`AES-IV` from
  `SHA-1(label || shared)`, `SHA-256(pub || peer)` (SHA-1 for major 2), AES-128-CTR signature,
  `pub | u32 certLen | cert | u32 encLen | enc`, plus the BAA `baIC` OPACK object.
- **Coprocessor** registers `0x00,0x02,0x05,0x10–0x12,0x20,0x21,0x30,0x31+`, 128-byte certificate
  windows, 2 s select/retry at 20 ms, 3 s `0x10` poll at 10 ms, `0x05` error on timeout.
- **LIVI `mfid` protocol** `op | [u16 len | challenge]` → `status | u16 len | payload`,
  ops `0x01` cert, `0x02` sign, `0x03` protocol major.

## Layout

```
mfi-linux/                     C11 + OpenSSL library and mfid tool (see its README)
  include/mfi/mfi.h            public API
  src/                         csm, iap2, sap, identity, cp (I2C + sim), mfid server, links
  cli/mfid.c                   CLI/daemon
  test/test_main.c             164 checks
mfi-model/                     Node.js reference model + remote /mfi/* test service (67 tests)
spec/                          dossier
  01-artifact-and-identity.md  hashes, certificate profile, key/cert check
  02-protocol.md               CSM, iAP2, SAP, register map, remote API
  03-wire-vectors.md           byte/JSON vectors
  04-unknowns.md               bounded claims, incl. the Node ECDSA pitfall
  05-rea-shipped-dex.md        decompiled shipped code + evidence ids
  06-livi-integration.md       LIVI wiring, mfid protocol, USB/wireless results
  07-validation.md             automated + manual results
tools/
  livi-integration.sh          protocol client + LIVI's own coprocessors + helperd check
  livi-mfid-client.py          client for LIVI's mfid protocol
  livi-probe/                  Rust probe built inside a LIVI checkout (GPL-3.0-or-later)
  livi-linux-wireless-setup.sh wireless CarPlay config for a Linux head unit
  livi-default-config.json     LIVI's own defaults, used as the config seed
  rea-decompile-apk.sh         REA CLI: decompile the MFi classes method by method
  DecompileApk.java            one-load JADX decompilation of whole packages
  crosscheck-mfid.mjs          Node model vs C accessory over a PTY
  analyze-apk-identity.sh      public-only certificate/key profiler
DiPlay-0.2.22.apk              supplied artifact (git-ignored)
DiPlay-main/                   supplied source snapshot (git-ignored)
```

## Tests

```sh
cd mfi-linux && make test && make selftest        # C library, 164 checks
cd mfi-model && npm test                          # Node model, 67 tests
node tools/crosscheck-mfid.mjs                    # both implementations, one PTY
./tools/livi-integration.sh --stage-files         # LIVI's code + shipped helperd (needs LIVI)
```

REA notes: decompilation needs a caller-supplied JDK 17+ and `jadx-headless-mcp` 0.7.1
(`REA_JADX_MCP_JAR`); see `spec/05-rea-shipped-dex.md`.

## Limits

- No MFi4 in libmfi: modern CarPlay negotiates MFi4 mutual authentication at `/auth-setup`; the
  library implements MFiSAP v1 (DiPlay's AirPlay-mirroring path), which is what the dossier and
  tests cover.
- Wireless CarPlay is native on Linux; on macOS LIVI has no Bluetooth stack of its own and needs
  a LIVI Link dongle.
- The I²C backend compiles for Linux and is exercised against the software coprocessor; it was
  not run on a physical bus here. BAA signing over 64 bytes is modelled, not observed.
- This repository does not bundle the Apple identity; it stays in the supplied APK and is read
  where it is. Use an identity you are entitled to.

## Credits

- [LIVI](https://github.com/f-io/LIVI) by Lasse Heitgres (GPL-3.0-or-later) — the CarPlay head
  unit used for the end-to-end run. `tools/livi-probe` is GPL-3.0-or-later to match it.
- DiPlay 0.2.22 — the artifact under analysis.
