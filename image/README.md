# A dedicated image

The goal is one flashable card that does exactly this job — LIVI on the 7" panel, GPS, OBD, the
USB Bluetooth route — with nothing else running, and a boot measured in seconds rather than a
minute.

## What the time actually goes on

Measured on the board (Pi 3B, kernel 6.18, 800×480 panel): **8.6 s kernel + 50–57 s userspace**.

Measured after applying it: **21.4 s total (6.8 s kernel + 14.7 s userspace)**, down from 57 s,
with the access point serving and CarPlay authenticating on the first boot.

| userspace cost | s | after this image |
| --- | --- | --- |
| NetworkManager (nothing to manage) | 34.7 | masked |
| cloud-init (four units) | 11.0 | masked + purged |
| `rpi-resize-swap-file` | 5.0 | masked |
| `dev-mmcblk0p2.device` (SD probe) | 3.2 | stays |
| `systemd-fsck` | 1.6 | stays |
| `user@1000` (PipeWire linger) | 2.7 | stays |
| `livi-wifi-ap` | 2.0 | stays |

The kernel phase is the floor: firmware, kernel, USB enumeration and the DSI panel come to
~8 s on this SoC and cannot be argued down much. Adding the kiosk, the FUSE mount of the
111 MB AppImage and a cold GStreamer registry, the realistic target is **12–15 s to UI**.
Anything promising 5 s is a different operating system, not a different image (see below).

The mask-NetworkManager change was proven in the Debian arm64 VM in `tools/pi-lab/`:
`network.target` 22.8 s → 3.1 s, kiosk 22.2 s → 3.2 s.

## What this image removes

| Removed | Why it is safe here |
| --- | --- |
| `NetworkManager` | the AP is hostapd started by LIVI; the bench link only needs a link-local address (`bench-link.service`) |
| `cloud-init` (masked and purged) | nothing provisions this board from a cloud |
| `ModemManager` | no WWAN |
| `cups`, `cups-browsed` | no printing |
| `man-db`, `triggerhappy`, `rpi-eeprom`, `apt-daily*`, `e2scrub_reap` | no man pages, no hotkey daemon, Pi 3 (no EEPROM), no unattended upgrades on a car |
| swap (`dphys-swapfile`, zram writeback) | 905 MB is enough for the kiosk, and SD wear matters |
| journald to disk | `Storage=volatile`, 32 MB in RAM |

## What must stay

Kernel and firmware (the vc4 driver and the DSI panel, `brcmfmac` for the AP), glibc, the
GStreamer bundle inside the AppImage, PipeWire, BlueZ, `seatd` + `libinput`, **fonts**
(`fonts-dejavu-core` — without them the UI is blank), `avahi-daemon` (CarPlay's mDNS
advertisement), `python3` (the OBD bridge).

Package count barely moves boot time; **services** do. A rebuilt rootfs with the same services
boots about as fast as a trimmed Raspberry Pi OS, so the win is in the removals, not in
distro-building heroics.

## Three ways to get there

| Approach | Effort | Expected boot | Risk |
| --- | --- | --- | --- |
| **Trim Raspberry Pi OS Lite 64-bit** with `provision.sh` (this directory) | low | 12–15 s | none new: the same packages that work today |
| `mmdebstrap` a minimal rootfs + Raspberry Pi kernel/firmware | medium | 11–14 s | firmware/panel packages, vendor repo quirks; needs a kernel and `config.txt` you maintain |
| Buildroot | high — porting LIVI's stack (Rust, GStreamer, femtovg, smithay, PipeWire) | 4–6 s | weeks of work, brittle updates |

The first row is what this directory implements, because it reuses everything already proven on
this board and can be re-applied after any upgrade.

It also installs the black-screen fix (§16 of the dossier): LIVI runs from a fixed extracted tree
with a pre-warmed GStreamer registry and a sudoers rule for the helper path that tree uses.

## Which image do I flash?

There is no `.img` in this repository, and `provision.sh` is not one. What you flash is a
Raspberry Pi OS image that has been through `provision.sh`; you have two ways to get one.

**A. Capture the card you already run (this is the reliable one).** The board currently has a
working install; trimming it is reversible and takes a minute:

```sh
sudo image/provision.sh --dry-run
sudo image/provision.sh
sudo reboot
systemd-analyze && systemctl --failed
```

Once that is green, capture the card — that capture *is* your dedicated image:

```sh
# on the Pi, writing to a USB stick (never to the card being read)
sudo image/capture.sh --to /media/usb --shrink
```

It refuses to write onto the source device, hashes the result, and gzips it
(Raspberry Pi Imager accepts `.img.gz`). Small caveat: copying a card image back onto a
*smaller* card needs the shrink step, which is what `--shrink` is for.

**B. Build from an already-provisioned image file.** `build-image.sh` edits a `.img` in place
inside the arm64 VM. Its input must be an image that has booted at least once — a virgin
Raspberry Pi OS download has no user account and no LIVI, so the chroot has nothing to
configure and `systemctl enable` has no running systemd.

```sh
limactl shell pi-lab -- sudo /Users/$USER/Documents/GitHub/MockMFI/image/build-image.sh \
    /Users/$USER/Downloads/jimny-card-backup.img
```

Flash the result with Raspberry Pi Imager or `dd`; the first boot still resizes the filesystem.

## Build

```sh
# on the Mac: download Raspberry Pi OS Lite (64-bit) and keep the original
limactl shell pi-lab -- sudo /Users/$USER/Documents/GitHub/MockMFI/image/build-image.sh \
    /Users/$USER/Downloads/2026-…-raspios-trixie-arm64-lite.img
```

`build-image.sh` loop-mounts partition 2, stages this directory plus `tools/`, and runs
`provision.sh --image` in a chroot. It edits the image in place; the first boot still resizes
the filesystem the way Raspberry Pi OS expects.

`provision.sh` is also the thing you run on a live board:

```sh
sudo image/provision.sh --dry-run    # print every change, touch nothing
sudo image/provision.sh              # apply
```

It installs nothing LIVI-specific: `install.sh --headless` from LIVI still owns the AppImage,
the kiosk unit and the helper. Run `provision.sh` **after** that, and again after a LIVI upgrade.

## If you want it built from nothing, not captured

`pi-gen` (the official Raspberry Pi OS builder) is the route to an image produced from zero rather
than copied from a card. It runs stages in a chroot, so it can install LIVI and apply
`provision.sh` without a booted board. Two honest caveats: a full build is 30–60 minutes and
several GB inside the arm64 VM, and LIVI's `install.sh` expects a running system (`systemctl`,
`loginctl`) — under pi-gen some of those calls need to be replaced with plain file writes, which is
the part that would have to be written and tested, not assumed.

Until that exists, the capture path above is the one that is guaranteed to produce a bootable
image, because it is a copy of a system that already booted, authenticated a phone and showed the
UI.

## State of the card this was written against

Confirmed on 2026-10-30, on the Pi 3B with the 7" panel: **23.6 s** boot, Jimny splash → LIVI UI
→ wireless CarPlay with a visible picture, access point `Jimny`, OBD/GPS/Bluetooth configured (the
three USB devices were unplugged at the time of writing, so their services were correctly waiting
and retrying).

## First boot checklist

```sh
systemd-analyze                        # target: ~12–15 s total
systemctl is-active livi-kiosk livi-obd livi-wifi-ap
journalctl -b -o cat | grep -E "\[gnss\]|BlueZ profile on|\[obd\]"
ip -br addr show eth0                  # link-local for the bench, no DHCP
```

## Known sharp edges

- `provision.sh` purges by name and tolerates absence, so it survives Raspberry Pi OS version
  differences — but read the dry run before the first real run on a new base image.
- Purging `avahi-daemon` would silently break wireless CarPlay discovery; it is deliberately
  not in the removal list.
- The AppImage lives in the user's home (`~/LIVI/LIVI.AppImage`) and the kiosk unit points at
  it; moving or upgrading LIVI means re-running `provision.sh` (it only rewrites what changed).
- This image keeps the distro's kernel. Kernel-level boot tricks (`disable_splash`,
  `boot_delay=0`, trimming the initramfs) are worth a second or two, not thirty.
