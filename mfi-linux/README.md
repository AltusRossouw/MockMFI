# libmfi — MFi accessory authentication for Linux vehicle hosts

`libmfi` answers the two authentication exchanges a wired/wireless CarPlay accessory must win,
and drives the MFi authentication coprocessor that normally holds the accessory identity:

| Exchange | Where it happens | Code |
| --- | --- | --- |
| iAP2 `AccAuthentication` `0xAA00`–`0xAA06` | CSM control session over USB/BLE/UART | `src/iap2.c`, `src/csm.c` |
| AirPlay `/auth-setup` (MFiSAP v1) | HTTP control channel, TCP 7000 | `src/sap.c` |
| Coprocessor register protocol | I2C `0x10`/`0x11`, `/dev/i2c-N` | `src/cp.c`, `src/i2c_linux.c` |

Both exchanges end in the same `mfi_auth` contract — `protocol_major`, `read_certificate`,
`sign_challenge` — exactly the shape of DiPlay's `MfiAuthenticator`. Three backends implement it:

- `mfi_auth_local_create()` — software P-256 signer from `identity.pk8` + `certificate.p7b`
  (protocol major 3; what the shipped app calls "Local MFi v3").
- `mfi_cp_create()` — a real MFi coprocessor behind any `mfi_i2c_io` (Linux `/dev/i2c-N`, or
  your own bus driver).
- `mfi_cp_sim_create()` — a software coprocessor speaking the *same register protocol*, so the
  driver path, the framing and the whole chain can be tested on a bench without hardware.

Everything is C11 + libcrypto, no other dependencies, no threads required.

Wire formats were taken from the shipped `DiPlay-0.2.22.apk` (`classes3.dex`) decompiled with
REA; the evidence trail is `../spec/05-rea-shipped-dex.md`.

## Build

```sh
make                    # build/libmfi.a, build/libmfi.so, build/mfid
make test               # 164 checks, incl. iAP2 end to end over a socket pair
make selftest           # CLI: sign, SAP round trip, coprocessor discovery
sudo make install       # PREFIX=/usr/local by default
```

Linux needs `libssl-dev` (OpenSSL 3.x). The Makefile finds OpenSSL through `pkg-config` and falls
back to the usual prefixes; override with `make OPENSSL_PREFIX=/usr`.

## Identity

The DiPlay directory layout is used directly:

```
/etc/mfi/identity.pk8       PKCS#8 EC P-256 private key (unencrypted)
/etc/mfi/certificate.p7b    PKCS#7 certificate container presented to the phone
```

```sh
sudo install -d -m 0700 /etc/mfi
sudo install -m 0600 identity.pk8 certificate.p7b /etc/mfi/
sudo mfid --identity /etc/mfi cert
```

`mfid cert` prints subject/issuer/serial/SHA-256; loading already fails closed when the key does
not match the certificate, or when either side is not P-256. The container is sent to the phone
byte for byte — the app presents the whole PKCS#7 blob (607 bytes in the shipped APK), not just
the leaf.

The APK's own container can be inspected without copying anything into the tree:

```sh
unzip -p DiPlay-0.2.22.apk assets/offline-mfi/certificate.p7b > /tmp/identity/certificate.p7b
unzip -p DiPlay-0.2.22.apk assets/offline-mfi/identity.pk8      > /tmp/identity/identity.pk8
build/mfid --identity /tmp/identity cert
```

## CLI

```
mfid [--identity DIR] [--target local|i2c|sim] [--i2c DEV] [--addr N] <command>

  selftest        sign/verify, CSM, SAP round trip, coprocessor path
  cert            certificate profile
  sign HEX        sign a 32-byte digest -> 64-byte r||s
  sap HEX         process a 33-byte /auth-setup body -> reply hex ("rejected" otherwise)
  vectors         deterministic CSM / iAP2 / SAP request vectors
  discover        probe 0x10 then 0x11 on the bus
  serve           answer AccAuthentication on --serial /dev/... | --pty | --fd N
  net             serve the LIVI mfid TCP coprocessor protocol (--bind, --port 5000)
```

Examples:

```sh
# Real coprocessor on a Raspberry Pi / head unit
mfid --target i2c --i2c /dev/i2c-1 discover
mfid --target i2c --i2c /dev/i2c-1 --addr 0x10 selftest

# Bench loop: expose a PTY, then let a phone simulator or `socat` talk to it
mfid --identity /etc/mfi --target local serve --pty --once

# Sign a challenge the way the accessory does (no re-hash: input is the digest)
mfid sign 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f

# Network MFi coprocessor for a head unit (LIVI "mfid" protocol, port 5000)
mfid --identity /etc/mfi net --bind 0.0.0.0 --port 5000
```

## Integrating in a vehicle host

### iAP2 link

The library does not own your USB/BLE stack. Hand it the byte stream that carries iAP2 CSM
frames:

```c
#include <mfi/mfi.h>

mfi_auth *auth;
char err[256];
mfi_identity *id;
mfi_identity_load_dir(&id, "/etc/mfi", err, sizeof err);
mfi_auth_local_create(&auth, id, err, sizeof err);   /* takes ownership of id */

mfi_link *link;
mfi_link_fd(&link, stream_fd, 0, err, sizeof err);   /* your USB/BLE/UART fd */

if (mfi_iap2_authenticate(auth, link, 30000, my_log, NULL, err, sizeof err) == MFI_OK) {
    /* the phone accepted the certificate and signature: continue with the
     * iAP2 identification/control session on the same stream */
}
mfi_link_free(link);
auth->destroy(auth);
```

`mfi_link_serial("/dev/ttyUSB0", 115200)` is provided for UART-attached accessories;
`mfi_link_pty()` is what `mfid serve --pty` uses for bench work. Any transport can be plugged in
by filling `mfi_link_ops`.

### AirPlay `/auth-setup`

In the accessory's HTTP/RTSP handler:

```c
uint8_t reply[MFI_MAX_CERTIFICATE + 256];
size_t n = mfi_sap_handle(auth, body, body_len, reply, sizeof reply);
if (n == 0) {
    /* empty 400 — same as DiPlay's MfiSapAuthSetup.handle returning null */
} else {
    /* 200, Content-Type: application/octet-stream, body = reply[0..n) */
}
```

The accessory keeps its X25519 ephemeral per exchange; `mfi_sap_handle` generates a fresh key
pair on every call and rejects low-order peer keys.

### Coprocessor on I2C

```c
mfi_i2c_io *io;
mfi_i2c_linux_open(&io, "/dev/i2c-1", err, sizeof err);
mfi_auth *cp;
mfi_cp_create(&cp, io, -1 /* discover 0x10/0x11 */, err, sizeof err);
/* cp->protocol_major(cp), cp->read_certificate(...), cp->sign_challenge(...) */
```

Wiring and permissions on a Linux head unit:

```
MFi coprocessor      SBC / SoM
  VDD 3V3   -------  3V3
  GND       -------  GND
  SDA       -------  I2C SDA (pull-up 2.2k-4.7k to 3V3)
  SCL       -------  I2C SCL (pull-up 2.2k-4.7k to 3V3)
```

```sh
# udev rule so the accessory service can open the bus without root
echo 'SUBSYSTEM=="i2c-dev", GROUP="i2c", MODE="0660"' | sudo tee /etc/udev/rules.d/60-mfi-i2c.rules
sudo usermod -aG i2c mfi
```

systemd unit sketch:

```ini
[Unit]
Description=MFi accessory authentication
After=network.target

[Service]
ExecStart=/usr/local/bin/mfid --identity /etc/mfi --target i2c --i2c /dev/i2c-1 serve --serial /dev/ttyGS0 --once
Restart=always
User=mfi
Group=mfi
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
```

## Using it as a network coprocessor (LIVI)

LIVI's CarPlay stack accepts an MFi coprocessor over TCP (`livi-link.local:5000`) using a small
protocol: `op | [u16 len | challenge]` in, `status | u16 len | payload` out, ops `0x01` cert,
`0x02` sign, `0x03` protocol major. `mfid net` implements the server side, so a Linux box with the
identity becomes the coprocessor for a head unit that has no I²C chip:

```sh
mfid --identity /etc/mfi net --bind 0.0.0.0 --port 5000
```

Verified against LIVI's own Rust coprocessors (`FileCoprocessor` and `NcmCoprocessor`) and the
macOS `livi-helperd`; see `../spec/06-livi-integration.md` and `tools/livi-integration.sh`.

## Behaviour worth knowing

- **No re-hash.** `sign_challenge` takes the already-computed digest. For iAP2 the phone sends
  the digest directly; for `/auth-setup` the accessory hashes `pub || peer` with SHA-256
  (protocol major 3) or SHA-1 (major 2) first. Passing a 32-byte digest to a version-2 identity
  will fail, by design.
- **Raw signatures.** Every P-256 signature leaves the library as 64-byte `r||s`, matching the
  app's `derToRaw`; DER never reaches the phone.
- **Certificate container.** `read_certificate` returns the file as shipped (PKCS#7). Keep it
  that way; the CN/serial come from the leaf inside.
- **Retries.** The coprocessor driver retries a whole select+read for 2 s at 20 ms, polls
  `0x10` for 3 s at 10 ms, and on timeout reads `0x05` for the error code. Same numbers as the
  app, so the same hardware behaves identically.
- **BAA.** `MFI_CERT_TYPE_BAA` builds the three-parameter `0xAA01` body and the `baIC` OPACK
  object. No BAA identity ships in the APK, so that branch is modelled from the decompiled code
  and covered by unit vectors only.

## Limits

- USB device-mode enumeration, BLE GATT, and the AirPlay HTTP server itself are out of scope:
  this is the authentication layer, not a full CarPlay stack.
- No remote (`/mfi/*`) backend: a vehicle host should hold its identity locally.
- BAA signing of a 64-byte input is implemented per the decompiled app; it has not been
  observed against a real BAA coprocessor.
- `/auth-setup` here is MFiSAP v1 (the DiPlay/AirPlay-mirroring path). Modern CarPlay on iOS 17+
  negotiates **MFi4 mutual authentication** at the same endpoint; that layer sits on top of the
  same identity and signing primitives and is not part of this library.

## Layout

```
include/mfi/mfi.h   public API
src/csm.c           CSM framing + resynchronising stream parser
src/iap2.c          AccAuthentication responder and frame builders
src/sap.c           /auth-setup handler, AES-CTR and baIC encoding
src/identity.c      PKCS#8 + PKCS#7 loading, self test, profile
src/auth_local.c    software P-256 authenticator
src/cp.c            coprocessor register driver + discovery
src/cp_sim.c        software coprocessor (test fixture / no-hardware mode)
src/i2c_linux.c     /dev/i2c-N backend
src/link.c          fd / UART / PTY links
src/crypto.c        OpenSSL wrappers (ECDSA raw, X25519, hashes, AES-CTR)
cli/mfid.c          CLI/daemon
test/test_main.c    test suite
```
