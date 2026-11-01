#!/usr/bin/env bash
# Apply image/provision.sh to a Raspberry Pi OS (64-bit) image that has already
# booted once — i.e. the user exists, LIVI is installed, ~/LIVI/LIVI.AppImage is
# there. A virgin download has no user account and no LIVI, so flash that one
# first, run image/provision.sh on the device, and capture the card afterwards
# (see README.md, "Which image do I flash?").
#
# Run it on an arm64 Linux host (the Lima VM is one): the image is arm64, so a
# chroot needs a matching kernel, and "qemu-user" would only make a slow job
# slower.
#
#   limactl shell pi-lab -- sudo /Users/$USER/Documents/GitHub/MockMFI/image/build-image.sh \
#       /Users/$USER/Downloads/2026-10-29-raspios-trixie-arm64-lite.img
#
# The image is edited in place; keep a copy of the download. Nothing here shrinks
# the filesystem or fakes the first boot — Raspberry Pi OS resizes itself once,
# on the device.
set -euo pipefail

IMG="${1:?usage: build-image.sh IMG}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

[[ -f "$IMG" ]] || { echo "no such image: $IMG" >&2; exit 2; }
[[ "$(uname -m)" == "aarch64" ]] || { echo "run this on arm64 (the Lima VM); the image is arm64" >&2; exit 2; }
command -v losetup >/dev/null || { echo "losetup missing" >&2; exit 2; }

LOOP="$(losetup --find --show --partscan "$IMG")"
cleanup() {
  set +e
  for m in "$MNT/proc" "$MNT/sys" "$MNT/dev/pts" "$MNT/dev" "$MNT"; do
    mountpoint -q "$m" && umount "$m"
  done
  losetup -d "$LOOP"
}
MNT="$(mktemp -d)"
trap cleanup EXIT

# The root filesystem is partition 2 on Raspberry Pi OS; partition 1 is the
# firmware/boot FAT and is not modified.
ROOT="${LOOP}p2"
[[ -b "$ROOT" ]] || { echo "expected $ROOT; not a Raspberry Pi OS layout" >&2; exit 2; }
mount "$ROOT" "$MNT"

echo "→ staging the lab into the image"
mkdir -p "$MNT/tmp/lab"
cp -a "$REPO/image" "$REPO/tools" "$MNT/tmp/lab/"

echo "→ entering the chroot"
mount -t proc proc "$MNT/proc"
mount --rbind /sys "$MNT/sys"
mount --rbind /dev "$MNT/dev"
cp /etc/resolv.conf "$MNT/etc/resolv.conf" 2>/dev/null || true

chroot "$MNT" /bin/bash -lc 'cd /tmp/lab && DEBIAN_FRONTEND=noninteractive ./image/provision.sh --image'

echo "→ cleaning up"
rm -rf "$MNT/tmp/lab"
echo "done. flash $IMG as usual; the first boot resizes the filesystem."
