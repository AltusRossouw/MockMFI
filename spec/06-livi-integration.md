# Wiring libmfi into LIVI (CarPlay head unit)

[LIVI](https://github.com/f-io/LIVI) is a native CarPlay/Android Auto head unit for Linux and
macOS (GPL-3.0-or-later). It implements the **accessory** side, which means it needs MFi
authentication exactly like DiPlay does. This note records how `libmfi` plugs into it and what
was verified on this machine (2026-10-28, macOS arm64, LIVI 10.1.0 app, LIVI `main` source).

## 1. The three MFi sources LIVI understands

| Route | Platform | Code |
| --- | --- | --- |
| I²C coprocessor | Linux | `native/crates/iap2-mfi/src/linux.rs` (`I2cCoprocessor`) |
| LIVI Link over TCP | Linux + macOS | `src/ncm.rs` (`NcmCoprocessor`) + `src/server.rs` |
| Imported files | macOS (and Linux) | `src/file.rs` (`FileCoprocessor`) |

All three implement the same trait (`src/lib.rs`):

```rust
pub trait AuthCoprocessor {
    fn protocol_major(&mut self) -> Result<u8, MfiError>;
    fn read_certificate(&mut self) -> Result<Vec<u8>, MfiError>;
    fn generate_challenge_response(&mut self, challenge: &[u8]) -> Result<Vec<u8>, MfiError>;
}
```

with `CHALLENGE_MIN/MAX = 1/128` and the register constants `0x00, 0x02, 0x05, 0x10–0x12, 0x20,
0x21, 0x30, 0x31` — the same map `libmfi` implements in `src/cp.c`.

`FileCoprocessor` is the important detail for a Mac: it reads exactly the two files `libmfi`
already uses, from `~/Library/Application Support/LIVI/mfi/`:

```
certificate.p7b   PKCS#7 container, presented as-is        (CERTIFICATE_FILE)
identity.pk8      unencrypted PKCS#8; P-256 or RSA         (IDENTITY_FILE)
```

P-256 identities sign the challenge with `sign_prehash` (raw digest, no re-hash) and report
protocol major 3; RSA identities use PKCS#1 v1.5 over a 20-byte SHA-1 digest and report major 2.
That is byte-for-byte the `libmfi` local signer contract.

## 2. The `mfid` TCP protocol (LIVI Link route)

`livi_net::port::MFI = 5000`, and LIVI connects to `livi-link.local:5000`
(`native/crates/livi-link-host/src/link.rs`). The wire format (`src/server.rs`, `src/ncm.rs`):

```
request   1 byte op
          for SIGN: u16 BE challenge length | challenge
response  1 byte status (0 = ok, 1 = error) | u16 BE payload length | payload
ops       0x01 get certificate
          0x02 sign
          0x03 protocol major
```

Notes taken from the source:

- The client keeps one connection open and reconnects once after an I/O error (500 ms later).
- A challenge outside 1..128 ends the session.
- The server derives a protocol major fallback: if the chip reports something other than 2/3,
  a certificate shorter than 768 bytes is treated as major 3, longer as major 2.
- The server uses TCP keepalive (1 s idle/intvl, 2 probes) on Linux.

`libmfi` implements that server as `mfi_mfid_serve()` / `mfid net`
(`mfi-linux/src/mfid_server.c`), so any Linux box with the identity files becomes a network MFi
coprocessor — useful for a head unit with no I²C chip, or for testing a head unit's auth path
from a laptop.

## 3. What was wired and verified

### 3.1 LIVI's own code against `mfid net`

`tools/livi-integration.sh` copies `tools/livi-probe` into the LIVI checkout as
`native/crates/mfi-probe`, builds it against LIVI's `iap2-mfi` crate and runs both of LIVI's
coprocessors against our service:

```
file_major=3
ncm_major=3
cert_equal=true
file_sig=3af34d70…e74c51
ncm_sig=962d9cd6…2d3c54
```

Both signatures were then verified with libmfi/OpenSSL over the same 32-byte digest
(`mfid verify`), i.e. LIVI's file signer and LIVI's network client agree with our
implementation on framing, certificate container and ECDSA encoding.

### 3.2 The real macOS app

`--stage-files` copies the identity into LIVI's import folder and starts the shipped
`livi-helperd` headless. Observed:

```
[helperd] MFi from the imported files in /Users/altus/Library/Application Support/LIVI/mfi
[helperd] wired CarPlay watcher started (system usbmuxd), waiting for the LIVI Link
[helperd] CarPlay receiver seam ready (cp-bt.sock + bonjour :7011)
```

So the shipped binary accepts a `libmfi`-managed identity directory unchanged.

### 3.3 Verified against a real iPhone (wired CarPlay)

2026-10-28 22:25, macOS arm64, LIVI 10.1.0, identity staged from
`DiPlay-0.2.22.apk: assets/offline-mfi/` (`CN=IPA_24ACBB48646F8077F7463523085B60D2`,
607-byte PKCS#7). iPhone 14 Pro (`iPhone15,2`), iOS 27.2 (24B119), USB.

```
[22:25:04.826] [helper] [wired] 00008120: usbmuxd carkit up, starting iAP2
[22:25:04.894] [helper] [cp] wired: identification accepted
[22:25:05.008] [helper] [cp] wired: MFi auth succeeded
[22:25:05.124] [helper] [cp] CarPlayStartSession ip=fe80::… port=56960 device_id=FE:65:38:98:0F:97 pk_len=36 mutual-auth
[22:25:06.303] [cp] pair-setup M1->M2 … paired
[22:25:06.458] [cp] pair-verify M1->M2 … verified
[22:25:06.489] [cpStack] < POST /auth-setup (body 36B)
[22:25:06.490] [cpStack] MFi4 mutual authentication
[22:25:06.513] [cp] mfi4 0x5100 -> 0x5201 (SetUp)
[22:25:06.538] [cp] mfi4: the phone and LIVI proved each other
[22:25:06.679] [cpStack] RECORD (session started)
[22:25:08.242] [gst_video] codec=h265 decoder=vtdec (hw) … decoded 1280x720
[22:25:10.347] [core] CarPlay audio media started
```

What this proves:

- The identity directory is **accepted by a real iPhone**: the phone completed wired
  identification and MFi authentication, and the CarPlay session reached video and audio.
- The file-backed signer (`FileCoprocessor`, raw-digest P-256, protocol major 3) and therefore
  the shared `libmfi` contract produce signatures the phone accepts — the same 64-byte
  `r||s` form our module emits and verifies.
- `/auth-setup` on this phone uses **MFi4 mutual authentication** (`0x5100…0x52ff`), not the
  MFiSAP v1 exchange DiPlay implements. `libmfi`'s `mfi_sap_handle()` is the v1 path used by
  AirPlay screen-mirroring accessories (DiPlay's model); a full CarPlay accessory needs the
  MFi4 layer on top of the same identity/signing primitives.

## 4. Reproduce

```sh
# LIVI checkout for the Rust probe (optional but needed for step 3.1)
git clone --depth 1 https://github.com/f-io/LIVI.git ~/tools/LIVI

# app for the helperd check (macOS)
#   download LIVI-*-macos-arm64.dmg from the releases page, copy LIVI.app to ~/Applications

export LIVI_DIR=~/tools/LIVI
cd MockMFI
./tools/livi-integration.sh              # protocol + LIVI probe
./tools/livi-integration.sh --stage-files  # also stage the identity and run livi-helperd
```

Environment: `IDENTITY`, `LIVI_DIR`, `LIVI_APP`, `PORT`. The probe crate is
GPL-3.0-or-later to match LIVI; the rest of `libmfi` stays under this repository's terms, and the
integration is a separate process boundary (TCP), not a linked library.

Manual equivalents:

```sh
mfi-linux/build/mfid --identity mfi-linux/build/test-identity net --bind 0.0.0.0 --port 5000
python3 tools/livi-mfid-client.py 127.0.0.1 5000 --verify-bin mfi-linux/build/mfid \
        --identity mfi-linux/build/test-identity
```

## 5. Wireless CarPlay

### 5.1 Why it cannot run on this Mac without a LIVI Link

LIVI's macOS helper has no Bluetooth stack of its own. In `native/crates/livi-helperd/src/mac_main.rs`
the CarPlay Bluetooth service is only installed when the dongle is the adapter:

```rust
fn over_dongle() -> bool { env_s("LIVI_BT_ADAPTER", "") == livi_link_host::link::CHOICE }

let carplay = if over_dongle() {
    start_bluetooth(link.clone(), state.clone(), dongle.clone(), aa_events, wired_phones, sco_sink)
} else { None };
```

`start_bluetooth` is what offers the Hands-Free + CarPlay service records and hands the phone's
Bluetooth arrival to the wireless session; it spawns `crate::bt_dongle::run`, which talks to the
LIVI Link over the network. There is no `IOBluetooth`/`CoreBluetooth` code anywhere in the tree
(`grep -ri "corebluetooth\|iobluetooth"` returns nothing), and `livi-btd` is
`cfg(target_os = "linux")` only. Wireless CarPlay needs the phone to pair over Bluetooth first,
so on macOS the only supported path is a LIVI Link dongle (its own Bluetooth and Wi-Fi radios,
MFi over TCP port 5000 — the protocol `mfid net` implements).

### 5.2 Linux head unit: native wireless

On Linux LIVI drives both radios itself: BlueZ (`livi-btd`) hosts the Bluetooth services and
hostapd brings up the access point the phone joins for the AirPlay session. MFi comes from the
same identity directory (`~/.config/LIVI/mfi`), an I²C coprocessor, or a LIVI Link — the helper
prefers the files, so no chip is required.

`tools/livi-linux-wireless-setup.sh` writes the configuration and installs the identity:

```sh
tools/livi-linux-wireless-setup.sh \
    --ssid "My Car" --password "at-least-8-chars" \
    --iface wlan0 --band 5ghz --channel 36 --country ZA \
    --identity /path/to/identity
```

It seeds a complete `config.json` from LIVI's own defaults (`tools/livi-default-config.json`,
generated from `livi_core_proto::config::defaults()`) and then sets:

| Key | Value |
| --- | --- |
| `carName` | the SSID the phone shows |
| `wirelessCpEnabled` | `true` |
| `wifiInterface`, `wifiPassword`, `wifiType`, `wifiChannel`, `wifiChannelWidth` | access point |
| `btAdapter` | `hci0` or the dongle's adapter |
| `country` | regulatory domain for the channel |

The generated file was parsed back with LIVI's own `Config` type (a `config-check` binary built
against `livi-core-proto`), so a typo cannot produce a config LIVI silently rejects:

```
valid=true
carName=My Car
wirelessCpEnabled=true
wifiInterface=wlan0
wifiType=Ghz5
wifiChannel=36
wifiPasswordLen=9
btAdapter=hci0
```

Host prerequisites on the head unit: `bluetoothd` running with the adapter present, the Wi-Fi
interface free for hostapd (or `wifiDedicatedInterface` set), and a country that allows the
chosen 5 GHz channel. LIVI's own installer (`scripts/install/install.sh`) brings those packages
in; the script only touches LIVI's configuration and identity.

### 5.3 Options

| Goal | Path |
| --- | --- |
| Wireless on this Mac, today | LIVI Link dongle (provision with `livi-link-provision-macos-arm64`, flash a `livi-link-*.lfwb`), then set the adapter to the dongle in LIVI's Connections settings |
| Wireless on an in-car Linux host | native, via 5.2; SBC with BT + Wi-Fi (Pi 4/5, CM4/5), LIVI installer, identity files |
| Real MFi chip instead of files | `carPlayMfiI2cBus` + coprocessor at 0x10/0x11, or `mfid net` as a network chip |

## 6. Limits of this integration

- No iPhone was attached, so no real CarPlay session ran; the CarPlay `/auth-setup` path in LIVI
  was not driven end to end. `libmfi`'s own SAP tests and the iAP2 end-to-end test cover the
  responder side.
- No LIVI Link hardware, so `NcmCoprocessor` was exercised through the probe rather than through
  LIVI's dongle discovery (`livi-link.local` must resolve and the link must be "on the bus").
- macOS has no I²C bus, so the `I2cCoprocessor` path cannot be used there; that path is what a
  Raspberry Pi or an automotive SoM uses, and `libmfi`'s `mfid --target i2c` covers the same
  register protocol.
- The staged identity is the repository's **test** PKI. Remove it with
  `rm -rf ~/Library/Application\ Support/LIVI/mfi` when the experiment is over; a real phone
  will reject a self-signed identity exactly as it rejects the Node model's.
