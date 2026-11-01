# Pi lab on the Mac

The Jimny head unit is a Pi 3B that keeps browning out on the bench, which makes every
boot-ordering experiment a race. A Debian 13 arm64 VM on the Mac removes the race: same
systemd, same NetworkManager, same netplan versions as the Pi, so the *dependency graph* can
be measured and fixed here, then applied once.

## What it is good for

- boot ordering, unit dependencies, drop-ins, `systemd-analyze`
- running the repo's own tools on real Debian arm64: `livi-pi-preflight.sh --selftest`,
  `livi-obd-elm327.py --selftest`, the config writer and its JSON round trip
- reproducing a service graph: this directory's units are stand-ins for LIVI's

## What it cannot do

No vc4/DSI panel, no bcm2835 codec, no brcmfmac AP, no BlueZ dongle, no MFi helper. Anything
that touches those stays on the board: the compositor claiming DRM, hardware H.264, the 2.4 GHz
access point, the Bluetooth route.

## Bring it up

```sh
brew install lima
limactl start --name=pi-lab --vm-type=vz --cpus=4 --memory=4 template:debian
limactl shell pi-lab -- sudo apt-get install -y network-manager netplan.io
```

Host files reach the VM read-only under `/Users/$USER`; copy them in with `sudo cp`.

## Container or VM?

The two are not interchangeable for this work, and the split is worth stating because it looks
like duplication otherwise.

| Job | Use | Why |
| --- | --- | --- |
| Boot ordering, unit graph, drop-ins, `systemd-analyze` | the **VM** | a container has no boot: no kernel phase, no udev coldplug, no device bring-up — the very things being measured |
| Running the repo's scripts across distros, CI | a **container** | disposable, fast, arm64-native, no systemd needed |

On a Mac a container still runs inside a VM (Docker Desktop, colima, OrbStack), so "docker instead
of a VM" saves nothing here — it adds a layer. If a container runtime is already present, the
script checks are one command:

```sh
tools/pi-lab/run-checks.sh                 # docker or podman
RUNNER=nerdctl tools/pi-lab/run-checks.sh  # inside the Lima VM
```

Verified inside the Lima VM with `nerdctl` (the default Lima image ships it; `nerdctl build`
additionally needs `buildkitd` running):

```
$ sudo nerdctl run --rm -v $PWD:/lab:ro debian:trixie-slim bash -lc '…'
ok     no-mfi/wired      exit=5 want=5
6/6 fixtures match
ok   junk is not invented
all checks passed
```

## The experiment that mattered

The Pi took 57 s to show the UI. `systemd-analyze` blamed `NetworkManager` (34.7 s) and the
chain was `NetworkManager → network.target → systemd-user-sessions.service → livi-kiosk`.

Reproduced here with a 20 s `slow-net.service` ordered `Before=network.target`, and a kiosk
stand-in that starts from `multi-user.target`:

| Variant | network.target | kiosk started |
| --- | --- | --- |
| NM + a slow unit before network.target | 22.8 s | 22.2 s |
| kiosk drop-in `After=basic.target` (attempt to skip the wait) | 22.8 s | 22.8 s |
| kiosk moved to `basic.target.wants` | 22.1 s | 22.2 s |
| **NetworkManager masked** | **3.1 s** | **3.2 s** |

Two findings worth keeping:

1. **A drop-in cannot remove an ordering inherited from the main unit.** `After=` (empty) and
   `After=basic.target` both left `network.target` in `systemctl show -p After`, and the unit
   still waited. That is why the same edit did nothing on the Pi.
2. **Moving the kiosk earlier does not help either**, because `livi-kiosk` is ordered after
   `systemd-user-sessions.service`, and *that* is ordered after `network.target`. The only
   lever is `network.target` itself — i.e. NetworkManager.

## The fix this produced

On a head unit NetworkManager has nothing to manage: the access point is hostapd started by
LIVI, and the bench link only needs a link-local address.

```sh
sudo systemctl mask NetworkManager
sudo cp bench-link.service /etc/systemd/system/
sudo mkdir -p /etc/systemd/system/livi-kiosk.service.d
sudo cp livi-kiosk-settle.conf /etc/systemd/system/livi-kiosk.service.d/20-drm-settle.conf
sudo systemctl daemon-reload
sudo systemctl enable bench-link.service
```

`bench-link.service` brings `eth0` up at `sysinit.target` so the bench SSH over IPv6
link-local survives without NetworkManager; `livi-kiosk-settle.conf` gives DRM a moment,
because the kiosk now starts roughly 50 s earlier than it used to and could otherwise win the
race against the vc4 driver.

Expected result: `network.target` at ~3 s, kiosk at ~4 s, and the AP a moment later, versus
57 s before. If the board ever needs DHCP again, `sudo systemctl unmask NetworkManager` at the
console undoes it.
