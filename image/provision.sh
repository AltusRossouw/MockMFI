#!/usr/bin/env bash
# Turn a stock Raspberry Pi OS Lite (64-bit) into the Jimny head unit, with as
# little running as possible.
#
# Everything here is "state the machine should be in", not "steps to perform":
# run it as often as you like on a live system, or inside a chroot while
# building an image.
#
#   sudo image/provision.sh --dry-run     # print every change, touch nothing
#   sudo image/provision.sh               # apply
#   sudo image/provision.sh --image       # same, but skip runtime-only steps
#
# What it does NOT do: install the kernel or firmware (that stays the distro's
# job), and it does not touch /boot/firmware beyond the two lines noted below.
set -euo pipefail

DRY=0
IMAGE=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY=1 ;;
    --image) IMAGE=1 ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

say()  { printf '\n== %s\n' "$*"; }
# Write a file only when applying; a dry run just names it.
write_file() {
  local path="$1"
  if (( DRY )); then printf '   would write: %s\n' "$path"; cat >/dev/null; else
    mkdir -p "$(dirname "$path")" && cat > "$path"; fi
}
run()  { if (( DRY )); then printf '   would run: %s\n' "$*"; else printf '   %s\n' "$*"; "$@"; fi; }
# Purge a package only if it is installed; Raspberry Pi OS versions differ.
purge_if() {
  local p="$1"
  if dpkg -s "$p" >/dev/null 2>&1; then run apt-get purge -y "$p"; else printf '   skip (absent): %s\n' "$p"; fi
}
mask_if() {
  local u="$1"
  if systemctl list-unit-files "$u" >/dev/null 2>&1 && [[ -n "$(systemctl list-unit-files "$u" --no-legend 2>/dev/null)" ]]; then
    run systemctl mask "$u"
  else
    printf '   skip (no such unit): %s\n' "$u"
  fi
}
disable_if() {
  local u="$1"
  if [[ -n "$(systemctl list-unit-files "$u" --no-legend 2>/dev/null)" ]]; then
    run systemctl disable "$u"
  else
    printf '   skip (no such unit): %s\n' "$u"
  fi
}

say "network: no manager for a head unit"
# The access point is hostapd started by LIVI; the bench link only needs a
# link-local address. NetworkManager is what made the boot take 57 s.
mask_if NetworkManager.service
mask_if NetworkManager-wait-online.service
mask_if systemd-networkd-wait-online.service
mask_if wpa_supplicant.service
run install -m 0644 "$(dirname "$0")/../tools/pi-lab/bench-link.service" /etc/systemd/system/bench-link.service
run systemctl enable bench-link.service

say "clock, logs, swap: keep the SD card quiet"
printf '[Journal]\nStorage=volatile\nRuntimeMaxUse=32M\n' | write_file /etc/systemd/journald.conf.d/00-volatile.conf
run systemctl mask dphys-swapfile.service
run systemctl mask rpi-resize-swap-file.service
run systemctl mask rpi-zram-writeback.timer

say "boot: fewer moving parts before the kiosk"
for u in cloud-init-local.service cloud-config.service cloud-final.service \
         cloud-init-main.service ModemManager.service cups.service cups-browsed.service \
         triggerhappy.service rpi-eeprom-update.service apt-daily.timer \
         apt-daily-upgrade.timer man-db.timer e2scrub_reap.service \
         rp1-test.service keyboard-setup.service; do
  mask_if "$u"
done
run systemctl set-default multi-user.target

say "kiosk: give DRM a moment, then own the screen"
run mkdir -p /etc/systemd/system/livi-kiosk.service.d
run install -m 0644 "$(dirname "$0")/../tools/pi-lab/livi-kiosk-settle.conf" \
  /etc/systemd/system/livi-kiosk.service.d/20-drm-settle.conf

say "packages: remove what a head unit never runs"
(( IMAGE )) || say "(runtime packages are unchanged on a live system)"
for p in cloud-init modemmanager cups cups-daemon cups-browsed avahi-utils man-db \
         triggerhappy rpi-eeprom wireless-regdb-pentest exim4-base nfs-common rpcbind \
         ntfs-3g exfat-fuse; do
  purge_if "$p"
done

say "the pieces LIVI and the car need"
NEEDED=(bluez hostapd dnsmasq-base iw rfkill avahi-daemon seatd libinput10 libseat1
        libgbm1 libegl1 libgles2 libdrm2 libfontconfig1 fonts-dejavu-core
        pipewire pipewire-pulse wireplumber alsa-utils python3)
missing=()
for p in "${NEEDED[@]}"; do dpkg -s "$p" >/dev/null 2>&1 || missing+=("$p"); done
if (( ${#missing[@]} )); then run apt-get install -y --no-install-recommends "${missing[@]}"; else echo "   all present"; fi

say "LIVI from a fixed tree: the intermittent-black-screen fix"
APP=/opt/livi/app
if [[ -x /home/jimnt/LIVI/LIVI.AppImage ]]; then
  if (( DRY )); then
    echo "   would extract /home/jimnt/LIVI/LIVI.AppImage to $APP (if absent)"
  elif [[ ! -x "$APP/AppRun" ]]; then
    mkdir -p /opt/livi
    ( cd /opt/livi && /home/jimnt/LIVI/LIVI.AppImage --appimage-extract >/dev/null       && rm -rf app && mv squashfs-root app && chmod -R a+rX app )
  fi
  printf '[Service]\nExecStart=\nExecStart=%s/AppRun\n' "$APP" \
    | write_file /etc/systemd/system/livi-kiosk.service.d/30-extracted-app.conf
  printf '[Service]\nExecStartPre=-/usr/local/lib/livi/gst-warm.sh\n' \
    | write_file /etc/systemd/system/livi-kiosk.service.d/40-gst-warm.conf
  run install -m 0755 "$(dirname "$0")/../tools/pi-lab/gst-warm.sh" /usr/local/lib/livi/gst-warm.sh
  # core launches the helper from the tree, so the installer's rule is not enough
  printf 'Cmnd_Alias LIVI_HELPER_APP = %s/resources/driver/livi-helperd\njimnt ALL=(root) NOPASSWD: SETENV: LIVI_HELPER_APP\n' "$APP" \
    | write_file /etc/sudoers.d/99-LIVI-helper-extracted
  run chmod 0440 /etc/sudoers.d/99-LIVI-helper-extracted
else
  echo "   ~/LIVI/LIVI.AppImage not there; install LIVI first"
fi

say "CarPlay icon (published from ~/.config/LIVI/carplay-images/livi.png)"
if [[ -f "$(dirname "$0")/assets/carplay-icon.png" ]]; then
  run mkdir -p /home/jimnt/.config/LIVI/carplay-images
  run install -m 0644 "$(dirname "$0")/assets/carplay-icon.png" /home/jimnt/.config/LIVI/carplay-images/livi.png
  run chown jimnt:jimnt /home/jimnt/.config/LIVI/carplay-images/livi.png
else
  echo "   no image/assets/carplay-icon.png"
fi

say "boot splash (Plymouth, until LIVI takes the display)"
if [[ -f /usr/share/plymouth/themes/jimny/jimny.plymouth ]]; then
  echo "   jimny theme already installed"
else
  run "$(dirname "$0")/../tools/pi-lab/install-splash.sh"
fi

say "identity, if one is staged next to this script"
if [[ -f "$(dirname "$0")/identity/identity.pk8" ]]; then
  run mkdir -p /home/jimnt/.config/LIVI/mfi
  run install -m 0600 "$(dirname "$0")/identity/identity.pk8" /home/jimnt/.config/LIVI/mfi/identity.pk8
  run install -m 0600 "$(dirname "$0")/identity/certificate.p7b" /home/jimnt/.config/LIVI/mfi/certificate.p7b
  run chown -R jimnt:jimnt /home/jimnt/.config/LIVI
  run chmod 700 /home/jimnt/.config/LIVI/mfi
else
  echo "   no image/identity/ directory; stage it on the device instead"
fi

say "car config"
CFG=/home/jimnt/.config/LIVI/config.json
if [[ -f "$CFG" ]] && command -v jq >/dev/null; then
  if (( DRY )); then
    echo "   would set carName/oemName/hand/GPS/BT in $CFG"
  else
    jq '.carName="Jimny" | .oemName="Suzuki" | .hand=1 | .carType=1
        | .gpsEnabled=true | .gpsBaudRate=9600 | .btAdapter="hci1"
        | .maxSpeedKph=140 | .maxRpm=7000 | .redlineRpm=6000' "$CFG" > "$CFG.tmp"
    mv "$CFG.tmp" "$CFG"
  fi
else
  echo "   $CFG not there yet (install LIVI first, then re-run)"
fi

say "done"
(( DRY )) && echo "dry run: nothing was changed"
