#!/usr/bin/env bash
# Capture the running card as a flashable image. Run this ON the Pi.
#
# The reliable way to get "one image with everything in it" is to capture a card
# that already works: the OS, LIVI, the identity, the trimming and the car config
# are all in place by definition. Nothing has to be reimplemented offline.
#
#   sudo image/capture.sh --to /media/usb        # write to an attached stick
#   sudo image/capture.sh --to /media/usb --shrink
#
# The target must be somewhere other than the card being read. `--shrink` uses
# pishrink.sh when it is on PATH (https://github.com/Drewsif/PiShrink); without
# it the image is the full card size and gzip still helps a lot.
set -euo pipefail

TO=""
SHRINK=0
DEV="${DEV:-/dev/mmcblk0}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --to) TO="${2:-}"; shift 2 ;;
    --shrink) SHRINK=1; shift ;;
    --device) DEV="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[[ "$(id -u)" -eq 0 ]] || { echo "run as root (it reads the block device)" >&2; exit 2; }
[[ -b "$DEV" ]] || { echo "$DEV is not a block device" >&2; exit 2; }
[[ -n "$TO" && -d "$TO" ]] || { echo "--to needs an existing directory on another filesystem" >&2; exit 2; }

# Refuse to write onto the card we are reading (a USB stick is normally /dev/sda).
TO_SRC="$(findmnt -no SOURCE --target "$TO" 2>/dev/null || true)"
if [[ -n "$TO_SRC" && "$TO_SRC" == "$DEV"* ]]; then
  echo "refusing: $TO is on $DEV, the card being captured" >&2
  exit 2
fi

STAMP="$(date +%Y%m%d-%H%M)"
OUT="$TO/jimny-$STAMP.img"
echo "→ reading $DEV (this takes as long as the card is big)"
dd if="$DEV" of="$OUT" bs=4M conv=fsync status=progress

if (( SHRINK )); then
  if command -v pishrink.sh >/dev/null; then
    echo "→ shrinking with pishrink.sh"
    pishrink.sh -z "$OUT"          # replaces $OUT with a smaller .img.gz
    OUT="$OUT.gz"
  else
    echo "! pishrink.sh not found; leaving the full-size image" >&2
  fi
fi

if [[ "$OUT" != *.gz ]]; then
  echo "→ compressing"
  gzip -9 "$OUT"
  OUT="$OUT.gz"
fi

echo "→ hashing"
sha256sum "$OUT" | tee "$OUT.sha256"
ls -lh "$OUT"
echo
echo "Flash $OUT with Raspberry Pi Imager (it accepts .img.gz), or:"
echo "  gunzip -c $(basename "$OUT") | sudo dd of=/dev/rdiskN bs=4m"
