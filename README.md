# CarPlay on a Raspberry Pi — no dongle, no MFi chip

This repository is the working record of getting **CarPlay running on a Raspberry Pi 3B with
nothing between the phone and the Pi but software**: no CarlinKit/Autokit dongle, no MFi
coprocessor, no Apple accessory chip of any kind. The Pi *is* the head unit — it authenticates the
iPhone itself, terminates the AirPlay/iAP2 session, decodes and displays the video on a 7" panel,
and runs its own 2.4 GHz access point so the phone can join it wirelessly.

It started as reverse engineering of the MFi authentication layer in DiPlay 0.2.22 and grew a C
library (**libmfi**) that implements the accessory side of MFi on Linux. That library is what makes
the "no hardware" claim real, and this repo contains the full path from a byte-level identity to a
booting car dashboard.

```
        ┌─────────┐   USB or Wi-Fi   ┌──────────────────────────────────┐
        │ iPhone  │ ◄──────────────► │ Raspberry Pi 3B                  │
        └─────────┘                  │  LIVI (GPL-3.0)                  │
                                     │   ├─ iAP2 / MFi  ── software identity
                                     │   ├─ AirPlay video/audio          │
                                     │   ├─ compositor → DSI 800×480     │
                                     │   ├─ Bluetooth + hostapd (2.4 GHz)│
                                     │   └─ telemetry ← OBD-II / GPS     │
                                     └──────────────────────────────────┘
```

---

## 1. The claim, precisely

| Route to CarPlay | Who holds the MFi identity | Hardware needed | Works here |
| --- | --- | --- | --- |
| CarlinKit / Autokit dongle | the dongle | dongle + USB host | n/a — see [spec/08](spec/08-hudiy.md) |
| MFi coprocessor (real Apple chip) | the chip, over I²C | the chip, wired to the Pi | supported by LIVI and `mfid`, not required |
| **Software identity on the Pi** | **files on the SD card** | **none** | **this is what runs** |

The third row is the interesting one. MFi is not a secret handshake with a server at session time:
the accessory must present a certificate chain and sign challenges with a P-256 private key. If you
have that key and certificate — and they can be recovered, as documented here — you can implement
the accessory side entirely in software. LIVI does exactly that, and this repo supplies the identity
handling, verification tooling and the numbers to prove it works against a real iPhone.

| Evidence | Where |
| --- | --- |
| Wired CarPlay, real iPhone 14 Pro (iOS 27.2): `usbmuxd carkit up → identification accepted → MFi auth succeeded → session started` | [spec/07](spec/07-validation.md) |
| Wireless CarPlay on the Pi 3B's own 2.4 GHz radio (channel 6, 20 MHz), station at 65/24 Mbit/s | [spec/10 §12](spec/10-pi-wired-bringup.md) |
| 19.5 s cold boot, panel from first frame to LIVI UI | [spec/10 §14](spec/10-pi-wired-bringup.md) |
| Identity import tested through LIVI's own `livi-helperd`, files preferred over the chip | [spec/09](spec/09-livi-mfid-port.md) |

---

## 2. Hardware

| Part | Notes |
| --- | --- |
| Raspberry Pi 3B | 1.2 GHz A53, 905 MB usable, Wi-Fi/BT combo (BCM43438 — **2.4 GHz only**) |
| 7" DSI panel, 800×480 | the mode is pinned with `video=DSI-1:800x480@60` |
| microSD, 16 GB+ | 8 GB is tight once LIVI's bundle is in place |
| 5.1 V / 3 A supply | the board browns out on weaker supplies (`throttled=0x50005`) |
| iPhone | any CarPlay-capable model |
| *optional* ELM327 on USB | live OBD-II data for the dashboard |
| *optional* u-blox GPS on USB | position and clock without a network |
| *optional* USB Bluetooth dongle | moves the phone link off the onboard radio |
| *optional* USB microphone | only for measuring/tuning the equaliser |

The Pi 3B is the minimum that works well: the video decode is fine at 800×480, but keep the panel
at ≤ 30 fps — at 40 fps the compositor starts competing with the USB bus.

---

## 3. How CarPlay is assembled

| Layer | What happens | Where |
| --- | --- | --- |
| USB or Wi-Fi link | wired: Apple USB config 6 claimed over usbfs; wireless: the phone joins the Pi's AP and discovers the accessory over Bonjour | `iap2-usbmux`, `livi-wifi-ap` |
| iAP2 | identification, `StartSession`, MFi `AccAuthentication` (`0xAA00–0xAA05`) | LIVI core |
| MFi | certificate chain + ECDSA signatures over the accessory's identity | `livi-helperd` (files) |
| AirPlay | `/auth-setup` (MFiSAP), then `/info`, `/stream`, RTP video + audio | LIVI core |
| Video | H.264 in, v4l2 hardware decode, composited to DRM | `livi-gst-host`, `livi-compositor` |
| Audio | decoded to PipeWire, optional equaliser, out to the sink | `livi-gst-host` |
| Input | touch and keys back over iAP2 | LIVI UI |

`livi-mfid` (this repo's port, [PR #398](https://github.com/f-io/LIVI/pull/398)) is **not needed** if
you use the identity files directly: `livi-helperd` opens `identity.pk8` + `certificate.p7b` before
it ever looks at I²C. That is the configuration this repository runs.

---

## 4. The identity

Two files, nothing else:

```
~/.config/LIVI/mfi/identity.pk8      PKCS#8, unencrypted, P-256
~/.config/LIVI/mfi/certificate.p7b   PKCS#7 container, presented byte-for-byte
```

Permissions matter — the helper runs as root and refuses a world-readable key: directory `700`,
files `600`, owner the LIVI user.

Inspect it without a phone:

```sh
mfid --identity ~/.config/LIVI/mfi cert       # subject, issuer, serial, SHA-256, container size
mfid --identity ~/.config/LIVI/mfi selftest   # signs, verifies, round-trips iAP2 + SAP
```

The research path that produced these files — the shipped `classes3.dex`, the App Store receipt
check, the SAP vectors — is documented in [spec/01](spec/01-artifact-and-identity.md),
[spec/02](spec/02-protocol.md), [spec/05](spec/05-rea-shipped-dex.md) and
[spec/03](spec/03-wire-vectors.md). Treat the key as a credential: it *is* the accessory.

---

## 5. Build the card

Three routes, in order of how much you want to repeat yourself.

### 5.1 Clone a card that already works (fastest)

```sh
sudo image/capture.sh --to /media/usb --shrink   # writes .img.gz + .sha256
```

Raspberry Pi Imager accepts the result directly. The script refuses to write onto the device it is
reading, syncs, shrinks the filesystem, gzips and hashes.

### 5.2 Provision a fresh Raspberry Pi OS Lite

```sh
sudo image/provision.sh            # idempotent; --dry-run prints every action first
```

What it does, in order: installs LIVI, extracts the AppImage to `/opt/livi/app` (see §7), masks the
services that only cost boot time, seeds a Jimny-shaped LIVI config, installs the EQ/dashboard
patches' binaries if supplied, adds the boot splash, and drops the two sudoers rules the helper
needs. Every number in §8 comes from a card built this way.

### 5.3 From source

LIVI is GPL-3.0-or-later and builds natively for arm64. The careful path is an arm64 VM (a Lima
Debian 13 guest is what produced the binaries in `tools/patches`):

```sh
sudo apt-get install build-essential pkg-config cmake libssl-dev \
     libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev libwayland-dev \
     libxkbcommon-dev libfontconfig1-dev libudev-dev libinput-dev libseat-dev libgbm-dev
git clone https://github.com/f-io/LIVI && cd LIVI/native
cargo build --release -p livi-core -p livi-ui -p livi-gst-host
```

Then apply this repo's patches before building:

```sh
git apply ../MockMFI/tools/patches/livi-eq.patch          # equaliser, preamp, test tone
git apply ../MockMFI/tools/patches/livi-dashboard.patch   # telemetry readouts, EQ badge
```

---

## 6. Configure LIVI

The config is `~/.config/LIVI/config.json`, camelCase, 130+ keys. The ones that matter for a car
like the Suzuki Jimny this was built for:

| Key | Value here | Why |
| --- | --- | --- |
| `carName`, `oemName` | `Jimny`, `Suzuki` | shown on the phone's CarPlay screen |
| `hand` | `1` | **right-hand drive** (numeric enum; `0` is LHD) |
| `carType` | `1` | combustion |
| `projectionWidth/Height/Fps` | `800 / 480 / 30` | the panel's own mode; 30 fps keeps the USB bus sane |
| `carPlayDockPosition` | `side` | dock on the side of an 800×480 screen |
| `wifiType`, `wifiChannel`, `wifiChannelWidth` | `2.4ghz`, `6`, `20` | the 3B has no 5 GHz radio |
| `country` | `ZA` | regulatory domain |
| `btAdapter` | `hci1` when a dongle is fitted | keeps the phone link off the onboard radio |
| `gpsEnabled`, `gpsDevice`, `gpsBaudRate` | on, by-id path, `9600` | u-blox 7 |
| `displayBrightness` | `1.0` | the panel backlight is otherwise never touched |
| `carplay-images/livi.png` | 180×180 PNG | the accessory icon on the phone |

Writing the config for a given car is scripted:

```sh
tools/livi-linux-wireless-setup.sh --rhd --resolution 800x480 --fps 30 --dock side
tools/livi-pi-preflight.sh --mode wireless        # read-only verdict before you reboot
```

`--print-config` prints the resulting JSON without touching the live card; `--check` reports what a
running card would need. The preflight exits `0` ready, `2` no AP-capable radio, `3` fixable
problems, `4` missing dependencies, `5` identity/display/touch.

---

## 7. The black screen, and why LIVI runs from a fixed tree

This is the single most valuable piece of operational knowledge in the repo, because it looks like a
CarPlay bug and is not one.

LIVI probes the GStreamer codecs at start-up with a **10 second budget**
(`livi-media/src/gst_host.rs`). The AppImage mounts at a random `/tmp/.mount_LIVI.XXXX` path on every
boot, and the GStreamer registry is keyed by plugin path — so every boot starts with a cold plugin
scan:

```
probe from the AppImage mount : 13.8 s   ← loses the race
probe from a fixed tree       :  0.26 s cold, 0.17 s warm
```

When the scan loses, LIVI logs `gst-host codec probe failed`, never builds a video pipeline, and
**audio keeps working** — CarPlay with sound and a black screen. Intermittent, because it depends on
SD card speed and on how much the SoC is throttling that boot.

Fix, both parts required:

```sh
# 1. a fixed tree, so the registry stays valid across boots
LIVI.AppImage --appimage-extract && mv squashfs-root /opt/livi/app && chmod -R a+rX /opt/livi/app
# kiosk drop-in
ExecStart=
ExecStart=/opt/livi/app/AppRun

# 2. a pre-warmed registry before core probes
/usr/local/lib/livi/gst-warm.sh     # runs the bundle's gst-host --probe with the bundle's env
```

Gotcha that cost an evening: from the extracted tree, core launches the helper as
`resources/driver/livi-helperd`, but the installer's sudoers rule only authorises
`~/.config/LIVI/driver/livi-helperd`. `sudo` refuses, the helper gives up after six restarts, and the
panel stays completely black with **no UI at all** — a different symptom from the codec race:

```
Cmnd_Alias LIVI_HELPER_APP = /opt/livi/app/resources/driver/livi-helperd
jimnt ALL=(root) NOPASSWD: SETENV: LIVI_HELPER_APP
```

Distinguishing them is easy: codec race → audio works, black picture. Helper failure → nothing at
all, no UI, and `journalctl` shows `sudo: a password is required`.

---

## 8. Boot behaviour

Measured on the card this repo produced, from power-on to the LIVI UI:

```
 0.0 –  6.0 s   kernel
13.4 – 18.3 s   Plymouth (Jimny splash) window
17.8 s          plymouth-quit, DRM released
~20 s           LIVI: display DSI-1 800x480, UI started
                total ≈ 19.5 – 23 s (was 57 s on a stock install)
```

What bought the time: masking `NetworkManager` (with it gone, nothing waits on `network.target`),
`cloud-init`, `ModemManager`, `cups`, apt timers, swap, `e2scrub`, `rp1-test`, `keyboard-setup`,
`wpa_supplicant`, `getty@tty1`, plus volatile journald and purges. The kiosk is ordered after
`plymouth-quit-wait` so the compositor never fights Plymouth for DRM (that fight is the mid-boot
blink).

The boot splash is Plymouth with the panel's own mode pinned last on the command line, so it never
renders at an EDID preference:

```
cmdline: quiet splash plymouth.ignore-serial-consoles loglevel=0 logo.nologo
         vt.global_cursor_default=0 video=DSI-1:800x480@60
```

---

## 9. Wired and wireless

**Wired** — the phone's Apple USB configuration (6) is claimed over usbfs with `nusb`, the usbmux
interface (1) is driven directly, bulk endpoints `0x04/0x85`, NCM bridged for IP. Nothing else on the
bus may claim config 6; a dongle or a hub that re-enumerates will break it.

**Wireless** — the phone pairs over Bluetooth, learns the accessory's address, joins the Pi's own
AP and connects back. On the 3B this is 2.4 GHz only; measured working at channel 6, 20 MHz, WPA2
with `country=ZA`, station associated at 65/24 Mbit/s. Practical notes:

- 800×480 at 30 fps is comfortable on 2.4 GHz; 40 fps is not.
- After a kiosk restart the phone is dropped and must reconnect — expect `station` to be 0 for a
  minute.
- A CSR-class USB dongle as `hci1` is more reliable than the onboard radio for the phone link.

---

## 10. In-car integration (this repo's additions)

### OBD-II bridge — `tools/livi-obd-elm327.py`

ELM327 → LIVI telemetry at `127.0.0.1:4000`. What it took to make it feel immediate:

| Problem | Fix |
| --- | --- |
| 0.45 Hz updates | the car advertises 19 PIDs; four unsupported ones cost a 245 ms timeout each. Ask `0100/0120` first, poll only what exists |
| half a second of sleep | `--interval` defaults to 0 — the adapter paces the loop |
| blocking HTTP in the poll path | telemetry posted from a worker thread, newest sample wins |
| 123 ms per request | that is the ECU's own K-line latency; `ATAT1/2` and `ATST` change nothing |

Result: **1.9 Hz** from 0.45 Hz, with slow values (coolant, intake, MAP) refreshed every fourth pass.

KWP probing results on a 2009 Jimny (ISO 14230-4, fast init): mode `01` (19 PIDs), `03` DTCs, `06`
onboard monitoring, `09` calibration ID + CVN — and `02`, `05`, `08`, `0A`, `1A`, all 256 `21`
identifiers refused. There is no body/lighting data on this bus.

### Dashboard patches — `tools/patches/livi-dashboard.patch`

Coolant and intake readouts (labelled), the tachometer as a number in the speedo's own style, a trip
computer with average consumption and the litres it implies, a range line, and a one-tap **EQ badge**
for A/B comparisons.

### Fuel and trip — same bridge

```
fuel g/s = MAF / 14.7        L/h = fuel g/s × 3600 / 730
L/100km  = L/h ÷ km/h × 100  range = (tank − used) ÷ average × 100
```

Totals persist in `~/.local/state/livi-obd/trip.json`; `--trip-reset` starts a fresh trip at a
fill-up. This car does **not** report fuel level (PID `2F` unsupported) — the percentage is counted
down from the last reset, and [spec/10 §22](spec/10-pi-wired-bringup.md) describes the ADC route if
you want a measured tank.

---

## 11. Audio and the equaliser

LIVI has no EQ upstream; this repo adds a **10-band equaliser** to the touchscreen
(`tools/patches/livi-eq.patch`), plus a preamp and a pink-noise test tone.

```
appsrc ! audioconvert ! volume name=preamp ! equalizer-10bands name=eq ! clocksync !
         volume name=vol ! audioconvert ! audioresample ! S16LE 48k stereo ! pulsesink
```

Three coarse sliders (bass/mid/treble) and ten per-band trims are **summed and clamped**, so a cabin
mode can be cut without gutting its neighbours:

| Slider | Bands | Frequencies |
| --- | --- | --- |
| Bass | 0–2 | 29, 59, 119 Hz |
| Mid | 3–6 | 237, 474, 947, 1899 Hz |
| Treble | 7–9 | 3.8, 7.5, 15 kHz |
| Preamp | — | −24…+18 dB, applied **before** the EQ |

Three things learned the hard way, all documented in [spec/10 §24–25](spec/10-pi-wired-bringup.md):

1. **Gains set after `parse::launch` are ignored** by this GStreamer build. They must be baked into
   the pipeline string (`equalizer-10bands name=eq band0=…`). Until that was fixed, every EQ change
   was silent — which is why "bass is too strong" and "dull" could both be true at once.
2. **Preamp belongs before the EQ**, otherwise a boost clips the S16 stage and intermodulation shows
   up as midrange grit.
3. **Measuring noise with a single DFT bin is useless** (±6 dB scatter). Average overlapping
   Hann-windowed FFT segments per 1/3-octave band; then two halves of one recording agree within
   0.4–2.2 dB and pink noise reads flat.

Measure with the rig in `tools/livi-eq-test.py` (band analysis, sweeps) and the test tone in the UI:

```sh
tools/livi-eq-test.py --make /tmp          # pink.wav + sweep.wav
tools/livi-eq-test.py --analyze take.wav   # 1/3-octave table + suggested moves
```

A USB microphone is required; place it where your head is. On a 2009 Jimny the cabin mode measured
at 63–100 Hz, +12 dB relative to 1 kHz before correction.

---

## 12. Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| Audio but black screen | codec probe lost the 10 s race | fixed tree + warm registry (§7) |
| Nothing at all, no UI | helper cannot start | sudoers rule for the extracted helper path (§7) |
| `systemctl restart livi-kiosk` → "Job canceled" | getty conflict on tty1 | `stop` then `start`; mask `getty@tty1` |
| Phone will not reconnect | kiosk restarted, AP dropped | wait for `station` to reappear, or re-pair |
| OBD values shifted by one PID | two readers on the tty, stale replies | flush before write, one reader only |
| `pkill -f pink.wav` kills your own shell | `-f` matches the command line | `pkill -x pw-play` |
| EQ changes do nothing | gains set after parse | see §11.1 |
| Mic recordings clip at 0 dBFS | capture gain inside the USB device | lower it at the device, not in PipeWire |
| `throttled=0x50005` | undervoltage | 5.1 V / 3 A supply |
| Reboot loops at random | same | same |

---

## 13. Repository map

```
mfi-linux/            libmfi: accessory-side MFi in C (164 checks) + mfid CLI
mfi-model/            Node.js reference model of the same exchanges (67 tests)
macos/                CarPlayDesk: native macOS prototype, no LIVI
spec/                 01–11, the evidence: identity, protocol, vectors, LIVI integration,
                      the Pi bring-up, HUDIY analysis, the macOS app, the mfid port
tools/
  livi-obd-elm327.py  ELM327 → telemetry, PID discovery, trip computer
  livi-pi-preflight.sh read-only readiness verdict for a Pi
  livi-linux-wireless-setup.sh  config writer for a car (RHD, resolution, dock)
  livi-eq-test.py     pink noise, sweeps, 1/3-octave analysis
  livi-lights.py      illumination input → backlight + nightMode (ready for a GPIO)
  patches/            the two LIVI patches this build carries
  pi-lab/             boot-ordering lab (VM + containers), gst warm-up, splash installer
image/
  provision.sh        idempotent card provisioning (--dry-run)
  capture.sh          dd + shrink + gzip + sha256 → flashable image
  build-image.sh      edit an already-booted image through losetup + chroot
  assets/             splash art, CarPlay icon
```

---

## 14. Limits, honestly

- **Wireless on 2.4 GHz only** on a 3B; 5 GHz needs a Pi 4/5 or a USB radio.
- **No body data from this car.** The K-line carries the engine ECU and nothing else; lights,
  handbrake and fuel level need wires, not PIDs.
- **Fuel level is counted, not measured** — reset at each fill-up, or add an ADS1115 on the sender.
- **The equaliser is tuned on a bench, not in a moving car** — road noise changes the target curve.
- **Patched LIVI binaries live only on the card.** Rebuilding them needs the arm64 VM; the patches
  are the source of truth, the binaries are not.

## 15. What next

1. Capture the card (§5.1) so the working state survives a dead SD card.
2. A **USB DAC** — the EQ currently shapes the board's HDMI/mailbox fallback.
3. **Illumination → GPIO** for real night dimming (`tools/livi-lights.py` is written and tested).
4. **Fuel sender → ADS1115** for a measured tank.

## 16. Licence and credits

LIVI is **GPL-3.0-or-later** by Lasse Heitgres — the patches in `tools/patches` are derivative work
and carry the same licence. libmfi and the tooling here follow the repository's own licence. The
recovered MFi identity is a credential, not source code: keep it off public branches.
