# Wired CarPlay on a Raspberry Pi 3B: bring-up plan and preflight

This note answers one question for the board in hand — a Pi 3 Model B, 1 GB, with the official
7" 800x480 touchscreen — **can it run CarPlay through LIVI, and what is still missing once the
software is installed?** The answer is yes for the cable, and no for the radio: wired CarPlay needs
nothing the 3B lacks, while wireless needs a 5 GHz access point this board cannot provide. That
makes the cable the honest first target, and everything below is about getting there.

Recorded 2026-10-29 on macOS arm64 (the tools and the config are host-neutral); every step that
needs the Pi itself is marked as a gate, not as a result.

## 1. Verdict

| Target | On a Pi 3B | Why |
| --- | --- | --- |
| Wired CarPlay (USB) | **buildable** | LIVI claims the phone over usbfs, MFi comes from files, no radio is involved |
| Wireless CarPlay | **works on the 3B's own 2.4 GHz radio** | measured on 2026-10-29 (§12): AP on ch 6, BT MFi auth, session up at 10.10.0.29. 5 GHz is the headroom path, not a requirement this phone enforced |
| Display + touch | **supported** | LIVI drives DRM/KMS and libinput itself; the DSI panel is one multitouch node |

Wired also removes the two most fragile pieces of a wireless build (BlueZ pairing, hostapd on a
shared antenna) from the first session, which is what makes it the right thing to prove first.

## 2. What LIVI does on the cable

Nothing here is Raspberry Pi specific; it is what the Linux helper already ships.

- **Device claim.** `iap2-usbmux` matches Apple VID `0x05ac`, requires the phone to expose at least
  config **6** (`CP_CONFIG`, `lib.rs:6`), writes `bConfigurationValue` when it is not selected
  (`linux.rs:98-99`), then claims usbmux interface 1 (`usb_pipe.rs:14`, `:62`) and runs the NTB mux
  on bulk endpoints `0x04/0x85`. There is no `usbmuxd` daemon in this path.
- **USB networking.** The NCM interface is bridged by `ncm.rs`; the udev rule disables IPv6 DAD on
  it (`assets/linux/99-LIVI.rules.template:10`) and keeps `gphoto2`, `udisks` and ModemManager off
  the phone (`:8`).
- **Privileges.** `livi-helperd` runs as root through the installed sudoers drop-in
  (`/etc/sudoers.d/99-LIVI-helper`), so the config write and interface claim need no udev `MODE`.
  The UI runs as the normal user on `tty1` (`livi-kiosk.service`) with seatd for DRM/input.
- **MFi.** `livi-helperd/src/mfi_files.rs` opens `~/.config/LIVI/mfi` **before** it looks for an I²C
  chip (`linux_main.rs:287`), so the identity files are the whole requirement — the `livi-mfid`
  TCP endpoint from [spec/09](09-livi-mfid-port.md) is not used on this path.

## 3. What the 3B adds to the problem

| Constraint | Effect | Mitigation |
| --- | --- | --- |
| VC4 decodes H.264 only (no HEVC) | CarPlay must negotiate H.264 | LIVI advertises `hevc` only when a decoder exists; the stream stays H.264 |
| 1 GB RAM | UI + GStreamer bundle + session | 800x480@30, no cluster stream |
| USB budget 1.2 A shared across four ports | the phone may charge slowly or drop | 3 A supply, short cable, powered hub if needed |
| Decode path unproven on this SoC | `v4l2h264dec` against `bcm2835-codec` | preflight gate; `LIVI_GST_SWDEC=1` measures the software fallback |

LIVI's decoder order on Linux is `v4l2slh264dec` → `v4l2h264dec` → `vah264dec` → `avdec_h264`
(`livi-video/src/codec.rs:82-84`); the AppImage's GStreamer bundle ships
`libgstvideo4linux2.so`, whose comment names the Pi 4 as the validated stateful decoder. The Pi 3's
`bcm2835-codec` is the same stateful M2M shape, which is why this is a gate and not a blocker.

## 4. Configuration this repo writes

`tools/livi-linux-wireless-setup.sh` now has a `--wired` mode next to the wireless one it already
had. It seeds from LIVI's own defaults (`tools/livi-default-config.json`), overlays the existing
`config.json`, installs the identity, and only then writes:

| Key | wired | wireless |
| --- | --- | --- |
| `carName` | unchanged / `--ssid` | the SSID |
| `wirelessCpEnabled` | `false` | `true` |
| `wifi*`, `btAdapter`, `country` | untouched | set from the flags |
| `projectionWidth/Height` | `800x480` (or `--resolution`) | unchanged unless given |
| `projectionFps` | `30` (or `--fps`) | unchanged unless given |
| `projectionDpi` | unset unless `--dpi` | same |
| `hand` | `1` with `--rhd`, `0` with `--lhd` (unset otherwise) | same |
| `carPlayDockPosition` | `auto`/`side`/`bottom` with `--dock` | same |

`hand` is what tells the phone which side the driver sits on: LIVI forwards it as
`right_hand_drive` in the CarPlay accessory information (`livi-core/src/carplay.rs:385`), and the
phone mirrors its dock and driver-side UI accordingly. It is a number in `config.json` (`0` = LHD,
`1` = RHD, `config.rs:257-261`), not a string, so hand-editing it as `"rhd"` makes LIVI reject the
file.

Both outputs were parsed back with LIVI's own `Config` type (`livi-core-proto`, `serde`), the same
check [spec/06 §5.2](06-livi-integration.md) used:

```
$ cargo run -q -- /tmp/wired.json          # config-check built against livi-core-proto
valid=true
carName="LIVI"
wirelessCpEnabled=false
wifiInterface="wlan0"
wifiType=Ghz5
wifiChannel=36
projection=800x480@30
dedicated=false
```

```
$ cargo run -q -- /tmp/wl.json
valid=true
carName="My Car"
wirelessCpEnabled=true
wifiInterface="wlan1"
wifiType=Ghz5
wifiChannel=36
projection=1280x720@60
dedicated=true
```

`--print-config FILE` keeps working on any OS and copies no identity, so a config can be staged and
diffed before it ever reaches the head unit. `--check` runs the preflight first: it stops on `2`
(no radio in wireless mode), `4` (missing package/unit) and `5` (identity/display), and continues on
`3` with a warning, because a software-decode fallback is a performance decision, not a broken host.

## 5. Preflight

`tools/livi-pi-preflight.sh` is read-only, needs no root, and answers "what is missing" without
starting LIVI. Wired is the default mode; `--mode wireless` adds the radio checks.

| Check | Wired | Wireless |
| --- | --- | --- |
| `host.model`, `host.arch`, `host.ram`, `os.release` | yes | yes |
| `display.drm` (connected connector + mode), `display.touch` (ABS_MT_POSITION_X) | yes | yes |
| `video.decoder` (`v4l2h264dec` + `bcm2835` node), `video.avdec`, `video.cma` | yes | yes |
| `usb.rule`, `usb.kiosk`, `usb.helper`, `usb.phone` (config 6) | yes | yes |
| `mfi.files` (+ modes), `audio.sink`, `thermal` | yes | yes |
| `wifi.radio.<iface>` (bands, AP mode, 5 GHz AP channels), `wifi.5ghz_ap` (warns on a 2.4-only AP), `wifi.reg` | — | yes |
| `bt.adapter`, `deps.wifi` | — | yes |

Exit codes: `0` ready, `2` no AP-capable radio at all, `3` fixable config/codec/device, `4` missing
package/unit/udev rule, `5` identity/display/touch, `1` usage. A 2.4 GHz-only AP is **not** a defect:
it is a `warn` row plus a closing note, and the verdict stays `ready` (§12). On the 3B, both modes
therefore reach `0` once the installer and identity are in place; only a board with no AP-capable
radio at all returns `2`.

The verdict is computed from real checks, not from the model string: a Pi 4 with only 2.4 GHz
enabled reports exactly what a 3B does.

`--selftest` builds throw-away root filesystems and runs the real check code against them — a
dual-band Pi 4, a 2.4-only Pi 3, a 5 GHz radio that offers no AP mode, and a Pi with no identity:

```
$ tools/livi-pi-preflight.sh --selftest
ok     pi4-dual/wired    exit=0 want=0
ok     pi4-dual/wireless exit=0 want=0
ok     pi3-24/wired      exit=3 want=3
ok     pi3-24/wireless   exit=2 want=2
ok     noap5/wireless    exit=2 want=2
ok     no-mfi/wired      exit=5 want=5
6/6 fixtures match
```

The decoder row needs `gst-inspect-1.0` to be definitive; without it (the AppImage carries its own
GStreamer, not a system one) the row is a `warn` that says so, and `apt install gstreamer1.0-tools`
turns it into a pass/fail. The session log's `codec=h264` line is the real gate either way.

Two properties that make the tool safe to hand to an operator: it never writes (no `mkdir`, no
`install`, no `systemctl`), and every failing row carries the one command or setting that fixes it.

## 6. Bring-up runbook

```sh
# 1. OS: Raspberry Pi OS Trixie 64-bit (Lite). dtoverlay=vc4-kms-v3d, no display_rotate.
# 2. LIVI, headless (kiosk on tty1):
curl -fL -o install.sh https://raw.githubusercontent.com/f-io/LIVI/main/scripts/install/install.sh
chmod +x install.sh && ./install.sh --headless      # answer "no" to the coprocessor question

# 3. Identity for the kiosk user (not root):
mkdir -p ~/.config/LIVI/mfi && chmod 700 ~/.config/LIVI/mfi
install -m 600 identity.pk8 certificate.p7b ~/.config/LIVI/mfi/   # e.g. from the APK assets

# 4. Display + wired config, with the preflight as a gate:
tools/livi-pi-preflight.sh
tools/livi-linux-wireless-setup.sh --wired --check --resolution 800x480 --fps 30 \
        --identity /path/to/identity

# 5. Plug the iPhone into a USB-A port, unlock, "Trust", "Allow CarPlay".
#    Expected, in order:
#      [wired] 00008120: usbmuxd carkit up, starting iAP2
#      [cp] wired: identification accepted
#      [cp] wired: MFi auth succeeded
#      [cp] mfi4 0x5100 -> 0x5201 (SetUp)
#      [cpStack] RECORD (session started)
#      [gst_video] codec=h264 … decoded 800x480

# 6. Measure once with software decode, to know what the hardware path is worth:
LIVI_GST_SWDEC=1 <start LIVI>    # then compare frame pacing and CPU
```

Order matters in one place only: the identity must be staged **before** `--check`, because the
preflight judges the directory the helper will read, and `--wired` installs the identity before it
runs the gate.

## 7. Acceptance

| Gate | Pass |
| --- | --- |
| Preflight, wired | exit `0` with every check `ok`/`info` |
| Preflight, wired on a missing identity | exit `5`, `mfi.files` names the directory |
| Config round trip | `--print-config` parses as LIVI `Config`, `projection=800x480@30` |
| Cold boot | phone attached at power-on → kiosk starts → session up with no login |
| Decode | `codec=h264` on `v4l2h264dec`; `LIVI_GST_SWDEC=1` measured for comparison |
| Touch | taps land on the UI at 800x480, no offset, no rotation error |
| Audio | media out through the configured sink, mic up for Siri and a call |
| Soak | 20 min maps + music: no reconnect, `vcgencmd measure_temp` < 80 °C, `get_throttled` = `0x0` |

## 8. Failure modes

| Symptom | Likely cause | Where to look |
| --- | --- | --- |
| no `[wired]` line | phone not enumerated, helper not root | `lsusb`, `usb.phone` row, sudoers drop-in |
| `identification` never accepted | wrong identity directory (root's home), or config ≠ 6 | `mfi.files` row, `bConfigurationValue` |
| `MFi auth` fails | key/cert pair unusable | `mfid --identity DIR selftest` from `mfi-linux` |
| session starts, black screen | decoder/`glupload` path | pipeline log line, then `LIVI_GST_SWDEC=1` |
| touch offset or rotated | panel orientation vs projection size | `panel orientation` property, `projectionWidth/Height` |
| phone drops or will not charge | Pi 3 USB current budget | powered hub, shorter cable, 3 A supply |
| stutter after minutes | thermal throttling or software decode | `thermal` row, `get_throttled` |
| `systemctl restart livi-kiosk` ends with "Job canceled" and the screen stays dark | the unit's `Conflicts=getty@tty1` races its own `ExecStopPost` getty restart | `sudo systemctl start livi-kiosk` (or reboot); restart is not the reliable verb here |
| first boot logs `gst-host codec probe failed`, later boots do not | cold GStreamer registry on the SD card beats the 10 s probe timeout; the run after it is warm | restart once; the next start logs `gst-host codecs {"h264":{"hw":true,...}}` and video flows |

## 9. Evidence index

| Claim | Source |
| --- | --- |
| CarPlay config 6, usbmux interface 1, bulk `0x04/0x85` | `native/crates/iap2-usbmux/src/{lib.rs:6,usb_pipe.rs:14,usb_pipe.rs:62}` |
| `bConfigurationValue` is written by the helper | `native/crates/iap2-usbmux/src/linux.rs:98-99` |
| USB/media rules for `05ac`, IPv6 DAD off | `assets/linux/99-LIVI.rules.template:8-10` |
| rule + sudoers install paths | `scripts/install/common.sh:9-14` |
| files before chip | `native/crates/livi-helperd/src/{mfi_files.rs,linux_main.rs:287}` |
| Linux decoder order | `native/crates/livi-video/src/codec.rs:82-84` |
| software-decode switch | `native/crates/livi-video-player/src/lib.rs:320` |
| kiosk unit, Trixie requirement | `assets/linux/livi-kiosk.service.template`; `README.md` (supported hardware) |
| config keys accepted by LIVI | `livi-core-proto/src/config.rs:13-…`; the `config-check` runs in §4 |
| 3B radio is 2.4 GHz only | [CNX, 2016](https://www.cnx-software.com/2016/02/27/raspberry-pi-3-model-b-board-adds-wifi-and-bluetooth-connectivity/); board silkscreen/`iw phy` on the unit |
| preflight verdicts | §5, `--selftest` output |

## 10. Residual unknowns

- `v4l2h264dec` against `bcm2835-codec` on Trixie is untested here; §7's decode gate decides, and a
  software-only result means a Pi 4, not a config change.
- 800x480@30 is a deliberate ceiling for 1 GB; 60 fps or a cluster stream is unmeasured.
- USB power headroom with the panel, a DAC and the phone on one 3 A supply is a bench measurement.
- The recovered identity is the artifact's; a phone-side rejection is possible on any transport.

## 11. Deferred: 5 GHz

The 3B's combo chip is 2.4 GHz only, so the 5 GHz path needs a USB `mt76`-class adapter with AP
mode, `wifiInterface` pointed at it and `wifiDedicatedInterface: true` (§5's wireless preflight
returns `2` until such an adapter exists). It buys headroom, not function: §12 shows a session
running on the board's own radio.

## 12. Measured: wireless on the 3B's 2.4 GHz radio (2026-10-29)

`wlan0` became the access point, the phone paired over Bluetooth on the same chip, and CarPlay ran
over Wi-Fi. The evidence, in order, from one boot:

```
[wifi-ap] starting — ssid=LIVI channel=6 (2437 MHz) width=20MHz iface=wlan0
[wifi-ap] wlan0 offers 2.4 GHz 802.11n, WPA2 only
[11:04:04] [helper] [cp] bt: identification accepted
[11:04:04] [helper] [cp] bt: MFi auth succeeded
[11:04:04] [helper] [cp] CarPlayStartSession ip=fe80::ba27:ebff:fe26:31ad port=44725 …
[11:04:51] [cpStack] RECORD (session started)
[11:04:57] [helper] [cp] tunnel: identification accepted
[11:04:58] [helper] [cp] tunnel: CarPlayStartSession sent
wlan0: STA 6e:a5:52:72:b5:44 WPA: pairwise key handshake completed (RSN)
DHCPACK(wlan0) 10.10.0.29 6e:a5:52:72:b5:44
```

Hostapd ran `hw_mode=g`, `channel=6`, `ieee80211n=1`, `ht_capab=[SHORT-GI-20]`, `country_code=ZA`.
While the phone sat on the AP, `iw dev wlan0 station dump` reported **tx 65.0 Mbit/s, rx 24.0
Mbit/s** for the phone's randomized MAC — enough for the session, with little margin, on a radio it
shares with the Bluetooth link that carries pairing and call audio.

What this changes in the note: the earlier assumption that CarPlay's Wi-Fi link must be 5 GHz is not
what this phone enforced. What it does not change: 5 GHz remains the right target for a head unit
(throughput, latency, no coexistence with BT), and a 2.4 GHz-only board should be treated as
"works, unverified for long sessions" rather than "supported".

Costs seen in the same boot: the board still reports `throttled=0x50005` (under-voltage) under the
AP + BT + panel load, and a 40 fps projection was left in the config by hand — 30 fps is the safer
ceiling at 800x480 on this SoC.

To go back to the cable, on the device: `tools/livi-linux-wireless-setup.sh --wired`, then
`systemctl stop livi-kiosk && systemctl start livi-kiosk` (§8 explains why not `restart`). The
pre-test file is kept at `~/.config/LIVI/config.wired.json`.

## 13. The 2009 Jimny build: GPS, OBD-II and the Bluetooth route

Target vehicle: Suzuki Jimny 2009, 1.3 petrol, right-hand drive. The head unit is the Pi 3B with
the 7" panel, and three USB devices now hang off it.

| Device | Enumerates as | Used for |
| --- | --- | --- |
| u-blox 7 GNSS | `ttyACM0` (`/dev/serial/by-id/usb-u-blox_AG_-_www.u-blox.com_u-blox_7_-_GPS_GNSS_Receiver-if00`) | LIVI's own GPS reader, 9600 baud NMEA |
| ELM327 v1.5 (CH340) | `ttyUSB0` (`usb-1a86_USB2.0-Serial-if00-port0`) | the OBD bridge below, 38400 baud |
| CSR Bluetooth 2.1 dongle | `hci1` (`btusb`, `00:15:83:EE:42:C4`) | CarPlay pairing, call audio |

The onboard BCM43438 Bluetooth stays as `hci0` but is no longer used.

### 13.1 Configuration

```json
{
  "carName": "Jimny", "oemName": "Suzuki", "carType": 1,
  "btAdapter": "hci1",
  "gpsEnabled": true,
  "gpsDevice": "/dev/serial/by-id/usb-u-blox_AG_-_www.u-blox.com_u-blox_7_-_GPS_GNSS_Receiver-if00",
  "gpsBaudRate": 9600,
  "maxSpeedKph": 140, "maxRpm": 7000, "redlineRpm": 6000
}
```

`btAdapter` is the adapter `livi-helperd` installs its BlueZ profile and pairing agent on, so setting
it to `hci1` is the whole "USB dongle is the default BT route" change. The phone must pair again
afterwards — the adapter has its own address, so the old bond belongs to a controller that is no
longer used. The Wi-Fi side is untouched.

`gpsDevice` points at the `by-id` path, not `ttyACM0`: the ACM number changes if the module is
re-plugged while the panel is up.

### 13.2 The icon

LIVI publishes every PNG in `~/.config/LIVI/carplay-images/` as a CarPlay image asset, and
`livi.png` is the accessory logo it writes when the directory is empty (`livi-core/src/carplay.rs:543`).
Dropping a 180x180 PNG there and copying it over `livi.png` puts the car on the phone's CarPlay
screen; no rebuild is involved. The current art is `image/assets/carplay-icon.png` — the Suzuki
mark plus wordmark, keyed from the supplied design file (a Pixo/`.pxd` bundle whose original was a
1920x960 JPEG), trimmed to the artwork's bounding box and padded to 180x180 on black, matching the
splash.

### 13.3 OBD-II: a bridge, because LIVI has no OBD backend

LIVI consumes telemetry only through `POST /telemetry` on port 4000
(`livi-core/src/telemetry.rs:23`, `livi-core-proto/src/telemetry.rs`). There is no ELM327 or OBD
code in the tree, so this repo ships the missing half: `tools/livi-obd-elm327.py`, a standard-library
poller that speaks the adapter's AT/OBD dialect and pushes the fields LIVI knows.

| OBD PID | Telemetry field | Notes |
| --- | --- | --- |
| `01 0C` | `rpm` | `((A<<8)|B)/4` |
| `01 0D` | `speedKph` | also drives the dashboards and Android Auto |
| `01 05` | `coolantC` | `A-40` |
| `01 11` | `throttlePct` | `A*100/255` |
| `01 0B` | `mapKpa` | |
| `01 0F` | `iatC` | intake air, not ambient |
| `01 33` | `baroKpa` | |
| `01 42` | `batteryV` | `((A<<8)|B)/1000` |
| `01 2F` | `fuelPct` | if the cluster answers it |
| `01 46` | `ambientC` | often unsupported on this era |
| `03` | — | stored DTCs, logged at start |
| `01 01` | — | MIL state, logged at start |

`gear` and `reverse` are deliberately not derived: a 2009 Jimny reports neither over OBD, and a
speed-threshold guess would put the wrong gear on the dash. The bridge logs the DTC list once per
connection instead, which is the honest use of a 2009 ECU.

`--selftest` runs the parser and the HTTP push against a fake ELM327 behind a pty and a fake
telemetry endpoint, so the decode table is tested without a car:

```
$ tools/livi-obd-elm327.py --selftest
ok   adapter answers ATZ ELM327V1.5
ok   decode rpm got 1726.0
…
ok   push to endpoint
ok   decode DTCs P0133
all checks passed
```

On the head unit it runs as `livi-obd.service` (user `jimnt`, `Restart=always`), started after the
kiosk so the telemetry port exists.

### 13.4 What is still open on this build

- The unit install, the kiosk restart and the on-car verification (GPS fix line, first telemetry
  push, `BlueZ profile on hci1`) were cut short: the board keeps dropping off the bench link, and
  `throttled=0x50005` says why. A 5.1 V/3 A supply is a precondition, not a nicety, once the panel,
  the dongle, the GPS and the ELM327 are all on the same rail.
- `dtoverlay=disable-bt` in `config.txt` is worth doing once the dongle is trusted: it removes the
  onboard radio that shares the antenna with the 2.4 GHz access point CarPlay currently uses.

## 14. Boot time: the 57 s is NetworkManager, and a drop-in cannot fix it

The panel took 57 s to show the UI. `systemd-analyze blame` named `NetworkManager` at 34.7 s,
and the chain was:

```
livi-kiosk @57.2s ← systemd-user-sessions.service ← network.target ← NetworkManager @13.3s +34.7s
```

Two things were already removed before that measurement: cloud-init's four units and
`rpi-resize-swap-file` (masked, ~11 s), and `eth0` was pinned to `ipv4.method=disabled,
ipv6.method=link-local` so it no longer sat in DHCP for half a minute.

The remaining lever was tested in a Debian 13 arm64 VM (`tools/pi-lab/`), same systemd and
NetworkManager versions as the board, with a 20 s unit ordered `Before=network.target` and a
kiosk stand-in:

| Variant | network.target | kiosk started |
| --- | --- | --- |
| NM + slow unit before network.target | 22.8 s | 22.2 s |
| drop-in `After=basic.target` on the AP | 22.8 s | 22.8 s |
| kiosk pulled in at `basic.target` | 22.1 s | 22.2 s |
| **NetworkManager masked** | **3.1 s** | **3.2 s** |

- A drop-in **cannot** remove an ordering inherited from the main unit: both `After=` (empty)
  and `After=basic.target` left `network.target` in `systemctl show -p After`, and the unit
  still waited. This is why the same edit did nothing on the Pi.
- Pulling the kiosk in earlier does not help either, because it is ordered after
  `systemd-user-sessions.service`, which is itself ordered after `network.target`.

On a head unit NetworkManager has nothing to manage: the access point is hostapd started by
LIVI, and the bench link only needs link-local addressing. So the fix is to take it out and
bring `eth0` up with a two-line unit (`tools/pi-lab/`):

```sh
sudo systemctl mask NetworkManager
sudo cp bench-link.service /etc/systemd/system/ && sudo systemctl enable bench-link.service
sudo cp livi-kiosk-settle.conf /etc/systemd/system/livi-kiosk.service.d/20-drm-settle.conf
sudo systemctl daemon-reload
```

`livi-kiosk-settle.conf` adds `udevadm settle --timeout=15` before the kiosk launches, because
starting ~50 s earlier means the compositor could otherwise race the vc4 driver for
`/dev/dri/card0`. Reverting is one command at the console (`systemctl unmask NetworkManager`).

The VM is the place this was established, and `tools/pi-lab/README.md` records how to rebuild
it and what it cannot test (no DSI, no codec, no AP, no BlueZ).

**Applied on the board (2026-10-30):** 57.2 s → **21.4 s** (`6.8 s` kernel + `14.7 s` userspace)
after masking NetworkManager, adding `bench-link.service`, and masking `wpa_supplicant`,
`e2scrub_reap`, `rp1-test`, `keyboard-setup` and purging `nfs-common`/`rpcbind`. The remaining
blame is the SD card (`dev-mmcblk0p2` 2.7 s, `fsck` 1.7 s), `user@1000` 1.8 s for PipeWire, udev
trigger 1.2 s, avahi 1.2 s and the kiosk itself 2.8 s. `livi-wifi-ap` was serving and
`MFi auth succeeded` appeared twice in the first boot's log, so the AP path survived the change.

## 15. A dedicated image

`image/` turns the findings above into a repeatable system state instead of a series of
hand-applied fixes: `provision.sh` masks NetworkManager and cloud-init, points journald at RAM,
drops swap and the update timers, installs `bench-link.service` and the kiosk DRM settle, and
writes the Jimny config; `build-image.sh` applies it to a Raspberry Pi OS Lite image in an arm64
chroot. `image/README.md` has the boot budget and the reason the target is 12–15 s rather than
5 s: the kernel phase is already 8.6 s on this SoC, and the rest of the win comes from removing
services, not packages.

## 16. The intermittent black screen: a race against a 10 s probe

Symptom: wireless CarPlay connects, audio plays, the picture stays black. Present long before any
boot-time work, and intermittent — some sessions fine, some black.

Cause, measured on the board:

```
# probe from the AppImage mount (fresh path each boot)
$ time /tmp/.mount_LIVI.XXXX/resources/gst-host/livi-gst-host --probe
real 0m13.774s        # livi-core allows 10 s  →  "[core] gst-host codec probe failed"

# probe from a fixed extracted tree, cold cache
$ time /opt/livi/app/resources/gst-host/livi-gst-host --probe
real 0m0.257s         # warm: 0.174 s

# probe with LIVI's own bundle environment, after the failed probe rebuilt the cache
{"h264":{"hw":true,"sw":true},...}
```

`probe_codecs` (`livi-media/src/gst_host.rs`) gives the child 10 s. The AppImage mounts at a random
`/tmp/.mount_LIVI.XXXX` path every boot, and the GStreamer registry is keyed by plugin path, so
every boot starts with a cold cache and a plugin scan that takes ~14 s on this SD card while the
Pi 3 is throttling. When the scan loses the race, the probe returns nothing, LIVI never builds the
video pipeline, and the audio path — which does not depend on it — keeps working. A second session
in the same boot wins because the cache is warm by then, which is exactly the intermittency.

Fix, in two parts:

1. **Run LIVI from a fixed tree.** `LIVI.AppImage --appimage-extract` → `/opt/livi/app`, and the
   kiosk unit's `ExecStart` points at `/opt/livi/app/AppRun` (drop-in `30-extracted-app.conf`).
   Plugin paths stop changing, so the registry stays valid across boots: the probe is 0.26 s cold
   and 0.17 s warm.
2. **Warm the registry before core probes.** `/usr/local/lib/livi/gst-warm.sh` runs the bundled
   `livi-gst-host --probe` with the bundle's exact environment from the kiosk's `ExecStartPre`
   (`tools/pi-lab/gst-warm.sh`), so even a first boot after provisioning is warm.

One gotcha this created and the fix for it: running from `/opt/livi/app`, core launches the helper
as `resources/driver/livi-helperd`, but the installer's sudoers rule only authorises
`~/.config/LIVI/driver/livi-helperd`, so `sudo` refused, the helper gave up after six restarts, and
the panel stayed black with the UI never started (`[core] livi-kiosk` log: `sudo: a password is
required`). A second drop-in fixes it:

```
Cmnd_Alias LIVI_HELPER_APP = /opt/livi/app/resources/driver/livi-helperd
jimnt ALL=(root) NOPASSWD: SETENV: LIVI_HELPER_APP
```

Verified after the change, on a clean boot: `gst-host codecs {"h264":{"hw":true,"sw":true},…}` at
first start, `display DSI-1 Some(Main) at 800x480@60`, `UI started`, and then a live session —
`MFi auth succeeded`, `SETUP screen NATIVE (main … codec=H264)`, with the picture visible on the
panel (confirmed by the operator, 2026-10-30). The splash of §17 shows first and hands the display
over without a gap.

## 17. Boot splash

The panel shows the Jimny art from the first framebuffer until LIVI's compositor takes DRM, using
Plymouth (KMS, no firmware rainbow):

```
/usr/share/plymouth/themes/jimny/{jimny.plymouth,jimny.script,logo.png}   # logo 800x480 = panel mode
plymouth-set-default-theme jimny -R                                     # also rebuilds the initramfs
/etc/plymouth/plymouthd.conf                                            # Theme=jimny, ShowDelay=0
config.txt: disable_splash=1                                            # no rainbow, no firmware logo
cmdline:    quiet splash plymouth.ignore-serial-consoles loglevel=0
            logo.nologo vt.global_cursor_default=0 video=DSI-1:800x480@60
```

The theme script scales the image to *cover* the screen, so a different panel mode would still fill
it. `tools/pi-lab/install-splash.sh` is idempotent and keeps one `video=` pin last, which is what
makes Plymouth render at the panel's own mode instead of an EDID preference.

Measured after installing it: **23.6 s** total (6.2 s kernel + 17.4 s userspace), i.e. the splash
costs about 0.2 s; `plymouth-quit-wait` finished before the kiosk needed the display, and LIVI
logged `display DSI-1 Some(Main) at 800x480@60` + `UI started` afterwards.

### 17.1 Why it still blinks once, and what was done about it

The panel changes owner three times in one boot, and every handover is a visible event:

```
 0.0 –  ~3 s   firmware + kernel      (black, thanks to quiet + disable_splash)
 ~3 s – 17 s   Plymouth               (the Jimny art)
17.0 s         Console: switching to colour dummy device 80x25   ← plymouth releases DRM
17.0 – 20 s    black
20.0 s         LIVI compositor       (display DSI-1 …, UI started)
```

Changes made while chasing the mid-boot blink (none cost boot time; still ~22.6 s):

| Change | Effect |
| --- | --- |
| `console=serial0` removed, only `console=tty1` | Plymouth has one console instead of two |
| `fbcon=nodefer` | fbcon no longer takes the framebuffer over and clears the splash |
| `FRAMEBUFFER=y` + `update-initramfs` | same framebuffer and theme in initramfs and userspace, so the daemon does not rebuild the display |
| kiosk `After=plymouth-quit-wait.service` (+`Wants=`) | the compositor no longer grabs DRM while Plymouth is still drawing — this was the "image vanishes and comes back" |
| `getty@tty1` and `systemd-vconsole-setup` masked | nothing activates tty1 behind Plymouth's back |

What remains is structural: Plymouth has to release DRM before the compositor can become master,
and LIVI needs ~3 s to start core → compositor → UI. The art is black-bordered, so that gap reads
as the logo disappearing rather than a flash, but it cannot be removed without a compositor that
can wait on Plymouth.

## 18. A three-band equaliser in the touchscreen

LIVI ships no EQ and no plugin surface for one — the settings pages are compiled Rust. What made it
a small change is that audio is already a GStreamer pipeline with a controllable element:

```
appsrc ! … ! audioconvert ! equalizer-3bands name=eq ! clocksync ! volume name=vol ! … ! pulsesink
```

The patch (`tools/patches/livi-eq.patch`, branch `feat/audio-eq` in the LIVI fork, +124/−1 over five
files):

| File | Change |
| --- | --- |
| `livi-core-proto/config.rs` | `eqEnabled`, `eqBassDb`, `eqMidDb`, `eqTrebleDb`, all `#[serde(default)]` so older config files still load |
| `livi-audio/player.rs` | `Eq` type, the element in `pipeline_desc`, `apply_eq()` clamping to ±12 dB, `set_eq()`, `eq_element()` |
| `livi-gst-host/gst.rs` | reads the four keys from `~/.config/LIVI/config.json`, applies them at pipeline creation, and watches the file (2 s) so a slider is live without a protocol change |
| `livi-gst-host/Cargo.toml` | `serde_json`, `gstreamer` |
| `livi-ui-model/settings/schemas/audio.rs` | one `Equaliser` route under Settings → Audio, holding the toggle and the three ±12 dB steppers |

Built in the arm64 VM (`limactl shell pi-lab`, pinned beta toolchain, ~13 min of dependencies) and
installed over the extracted tree, which keeps rollback to one command:

```
livi-ui      → /opt/livi/app/livi-ui
livi-core    → /opt/livi/app/resources/core/livi-core
livi-gst-host→ /opt/livi/app/resources/gst-host/livi-gst-host
backup       → /opt/livi/app.bak-pre-eq
```

`equalizer-3bands` is in the bundle's `libgstaudiofx.so`, which is why no extra plugin is needed.

The page also carries a **Test tone** selector (Off / Pink noise): `livi-gst-host` watches the
`testTone` key and runs `audiotestsrc wave=pink-noise ! equalizer-3bands ! volume ! pulsesink`
through the *same* EQ and preamp stages, so a phone RTA measures the system as it actually plays.
Verified by watching PipeWire: one `sink-input` appears when it is set, none when it is cleared.

The same page carries a **Preamp** in dB (0…+18, 0.5 steps): a second `volume name=preamp` element
after the stream volume, because the car's amplifier is the real volume control and 100 % on the
head unit can still be quiet. Linear gain is `10^(dB/20)`, clamped at +18 dB — above roughly +6 dB
loud material will clip, since the decoder output is already normalised.
Verified on the panel: Settings → Audio shows a single *Equaliser* row, and its page holds Enabled,
Bass, Midrange and Treble; `UI started` + `display DSI-1` after each binary swap. The
audible check needs a DAC — the current sink is the board's HDMI/mailbox fallback.

Rollback: `sudo mv /opt/livi/app /opt/livi/app.eq && sudo mv /opt/livi/app.bak-pre-eq /opt/livi/app`
then `systemctl stop livi-kiosk && systemctl start livi-kiosk`.

## 19. Making OBD feel immediate

Measured on the car with the engine idling (ELM327 v1.5 over K-line, Jimny 2009):

```
0C rpm  123 ms    05 coolant  123 ms   2F fuel      245 ms  <- not supported
0D speed 123 ms    0F intake   123 ms   33 baro      245 ms  <- not supported
11 thrtl 123 ms                         46 ambient   245 ms  <- not supported
                                        42 volts     245 ms  <- not supported
one cycle 1721 ms + 500 ms sleep  =  0.45 Hz
```

Two faults, both ours rather than the adapter's:

1. **Polling PIDs the car does not answer.** An unsupported PID costs a full timeout, 245 ms —
   four of them wasted ~1 s of every cycle.
2. **A fixed 0.5 s sleep** on top, plus a blocking HTTP POST inside the polling loop.

Fixes, in `tools/livi-obd-elm327.py`:

| Change | Effect |
| --- | --- |
| `supported_pids()` — mode 01 bitmaps from `0100/0120/0140`, parsed as four bytes | the car advertises 19 PIDs; we poll only those, unsupported ones never cost a timeout |
| fast set (`rpm`, `speed`, `throttle`) every pass; slow set (`coolant`, `intake`, `map`) every `--slow-every` passes (default 4) | slow values refreshed ~2 s, which is all they need |
| `--interval` default **0** (the adapter paces the loop) | the sleep is gone |
| telemetry POST moved to a worker thread, newest sample wins | the poll loop never waits on LIVI |
| values cached and merged so every push carries a complete snapshot | the UI never sees holes |

Result on the same car: **19 cycles in 10 s = 1.9 Hz**, from 0.45 Hz — four times fresher, with the
LIVI UI re-rendering at 4 Hz, so the display is no longer the bottleneck.

The floor is physical: **123 ms per PID** regardless of `ATAT1`, `ATAT2` or `ATST 20` (all three
measured identically), because that is the ECU's response time on this car's K-line. Three fast
PIDs therefore cap the loop at about 2.7 Hz; polling only `rpm` and `speed` would reach ~4 Hz at the
cost of throttle.

## 20. Coolant and intake temperature on the dashboard

The telemetry model already carried `coolantC` and `iatC` (`livi-core-proto/src/telemetry.rs`) and the
poller already posted them — no UI rendered them. Added:

| File | Change |
| --- | --- |
| `livi-ui-model/dashboard/readings.rs` | `coolant_text/ratio/hot` (40–120 °C, warn at 105) and `intake_text/ratio` (−10–60 °C), both falling back to `—` when the car does not answer |
| `livi-ui/ui/dashboard/state.slint` | the five properties |
| `livi-ui/ui/dashboard.slint` | `COOLANT` / `INTAKE` captions (14 u, secondary) above each readout, since two thermostat icons and a number are otherwise indistinguishable; two `Level` widgets replacing the oil readout (removed — this car reports no oil temperature), `DeviceThermostat` for coolant and `ThermostatOutlined` for intake at x = 140 / 380 in the 1280-wide space, because a `Level` is ~190 u wide and fixed coordinates closer than that collide |
| `livi-ui/src/dashboard_ui.rs` | setters |

`settings.equalizer`, `eqEnabled`, `eqBass`, `eqMid`, `eqTreble`, `preamp`, `testTone`, `toneOff` and
`tonePink` went into `crates/livi-i18n/locales/en.json`; `cargo test -p livi-ui-model --lib` enforces
that every label key is translated, which is how that omission surfaced. 89 tests pass.

Patch: `tools/patches/livi-dashboard.patch`. The values ride the existing OBD bridge (`coolantC`,
`iatC` in `tools/livi-obd-elm327.py`), which now refreshes them every fourth pass (~2 s).

## 21. Fuel economy from MAF

This car answers PID `10` (MAF, 3.1 g/s at idle), which is all a consumption figure needs:

```
fuel g/s   = MAF / 14.7
L/h        = fuel g/s × 3600 / 730        (petrol, 730 g/L)
L/100 km   = L/h ÷ km/h × 100             (only above 3 km/h)
```

`tools/livi-obd-elm327.py` grew a `Trip` class: it integrates distance and litres, keeps the totals
in `~/.local/state/livi-obd/trip.json` so they survive a restart, and posts `fuelRateLph`,
`consumptionLPer100Km`, `consumptionAvgLPer100Km`, `odometerTripKm`, `rangeKm` and `afr` — all keys
LIVI's telemetry already defines (`livi-core-proto/src/telemetry.rs`), so no schema change was
needed. `--tank` (default 40 L) sizes the range estimate, `--trip-reset` starts a fresh trip at a
fill-up.

MAF joined the fast PID set and throttle moved to the slow one, so the loop still runs at ~1.9 Hz.

Dashboard, centred at the top (x = 640 − width ÷ 2, below the telltale lamps at y ≈ 48 and 76):

```
TRIP 312 km · 9.2 L/100 · 28.7 L     18 u, secondary — distance, average, litres (avg × km ÷ 100)
8.4 L/100                            24 u, primary   — instant, or 1.0 L/h at a standstill
RANGE 231 km                         18 u, secondary — remaining ÷ average, from the trip reset
```

The right-hand gauge readout now shows the **tachometer number** instead of the gear (`RPM` caption,
same `Readout` component and placement as the speedo), rounded to the nearest 10 rpm so it does not
jitter. The gear value stays in telemetry if it is ever wanted elsewhere.

The instant line drops the distance so the two lines do not repeat each other. The trip line appears
once the car has moved 100 m; below that there is nothing honest to show.

## 22. The fuel tank: what OBD will not tell you

PID `2F` (fuel level) is **not supported** on this car. The mode-01 bitmap says so directly: the
`0x20` range answers `80 00 00 00`, which advertises only PID `21` (distance since MIL), and a `2F`
request costs a full 245 ms timeout with an empty reply. So the dashboard's fuel percentage had no
source and was showing a default.

Two ways to get a real number:

**Counted down (implemented).** The trip computer already integrates litres from MAF. `fuelPct` is
now `(tank − litres used) ÷ tank × 100`, posted to LIVI, so the gauge is honest *provided the trip is
reset at a fill-up* (`--trip-reset`, tank 40 L by default). Drift comes from partial fills: if you add
20 L and do not reset, the gauge keeps counting down from where it was.

**Measured (hardware).** The tank sender is a float on a resistive track feeding the instrument
cluster. Reading it needs an ADC the Pi does not have:

```
sender ──┬── 10 kΩ ── 3V3
         └─────────── ADS1115 A0   (I²C, 16-bit, differential against GND)
```

Calibrate at empty and at full, fit a line, and post `fuelPct` from that — accurate regardless of how
you refuel, and it removes the dependency on resets. Caveats: the sender and the cluster share a
chassis ground, so take the ADC's ground from the same point and expect noise with the engine
running; and the cluster's own gauge will disagree slightly, because it is a moving-coil instrument.

## 23. A/B the equaliser without leaving the dashboard

A small **EQ badge** sits at the bottom right of the dashboard (x = 1150, 62 × 30 u): filled with the
accent colour while the equaliser is on, an outline while it is off. One tap flips `eqEnabled` through
the same `Action::SetConfig` path the settings page uses, so no new state exists to get out of sync —
the badge simply renders `config.eqEnabled`.

Two consequences worth knowing:

- **Program audio follows within ~2 s** — `livi-gst-host` watches `config.json` and applies the band
  gains to every live stream.
- **The test tone rebuilds itself too**: its watcher now hashes the tone *and* the EQ state/gains, so
  toggling the badge or moving a band restarts the tone with the new curve. Without that, a
  measurement would have described a pipeline that no longer existed.

## 24. Measuring properly, and why three bands were not enough

**The analysis was wrong before the equaliser was.** A single Goertzel bin of noise has
Rayleigh-distributed power: about ±6 dB of scatter no matter how long you record, which is why early
runs disagreed with each other and a "-8 dB" correction appeared to make the bass *louder*.
`tools/livi-eq-test.py` now averages overlapping Hann-windowed FFT segments and sums the bins inside
each 1/3-octave band. Two halves of the same recording then agree within **0.4–2.2 dB**, and pink
noise reads flat, which is the test's own sanity check.

**The three-band element was the wrong tool.** `equalizer-3bands` shelves at 100 Hz / 1 kHz / 10 kHz,
so "treble" could only lift the top octave while the measured dip sat at 3–8 kHz. The pipeline now uses
`equalizer-10bands`, with the three sliders mapped onto it:

```
bass    → band0..2   29, 59, 119 Hz
mid     → band3..6   237, 474, 947, 1899 Hz
treble  → band7..9   3777, 7523, 15049 Hz
```

Verified in isolation with `gst-launch-1.0`, independent of LIVI: pink noise with `band0..2 = -12 dB`
measures 63 Hz −12.4 dB, 125 Hz −12.2 dB, 250 Hz −1.9 dB, 1 kHz 0.0 dB — the gains land exactly where
they should.

**Preamp moved in front of the equaliser** and may now attenuate (−24…+18 dB). Boosts after the
equaliser clipped the S16 stage, which is what "distortion on the mids" sounded like: with the bass
hump at +14 dB the driver was already working hard, and intermodulation shows up as midrange grit.

## 25. Ten bands, and the reason the earlier EQ did nothing

**The gains were never applied.** `apply_eq` set properties on the element *after*
`parse::launch`, which this GStreamer build ignores silently. Proven inside a single recording:

```
before: flat 63 Hz +19.1  →  bass −12  +22.1      (a cut made it louder: the EQ was inert)
after:  flat 63 Hz +17.5  →  bass −12   +8.8      (correct)
```

Gains are now **baked into the launch string** (`equalizer-10bands name=eq band0=…`), with
`apply_eq` reserved for later changes.

**Bass sweep** (20–200 Hz log chirp, mic at the driver's ear, peak 0 dBFS so clipped and therefore
understated): `+4.2 dB at 63–80 Hz`, peak 71 Hz +6.1, trough 178 Hz −3.8 — a cabin mode, not a driver
artefact.

**Per-band control**: three sliders mapped onto ten bands could not cut one mode without gutting its
neighbours, so the Equaliser page now carries the ten bands themselves (29 Hz … 15 kHz, −24…+12 dB,
0.5 dB steps) *on top of* the coarse bass/mid/treble. Bands and coarse values are summed and clamped.

Result with `band1 −12, band2 −4`: **63 Hz +17.5 → +2.0, 80 Hz → +1.5**, and the 160–200 Hz dip that
remains is the car's own, visible in the sweep before any EQ was applied.
