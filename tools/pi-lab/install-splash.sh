#!/usr/bin/env bash
# Install the Jimny boot splash on Raspberry Pi OS (Plymouth, KMS).
# Run as root on the Pi.  Re-runnable.
#
#   sudo tools/pi-lab/install-splash.sh [logo.png]
#
# Default logo: image/assets/jimny-splash.png (800x480, the panel's mode).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOGO="${1:-$HERE/../../image/assets/jimny-splash.png}"
THEME=jimny
DIR=/usr/share/plymouth/themes/$THEME
CONFIG=/boot/firmware/config.txt
CMDLINE=/boot/firmware/cmdline.txt

[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 2; }
[[ -f "$LOGO" ]] || { echo "no logo at $LOGO" >&2; exit 2; }
[[ -f "$CONFIG" && -f "$CMDLINE" ]] || { echo "not a Pi OS boot tree" >&2; exit 2; }

echo "→ plymouth"
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq plymouth plymouth-themes >/dev/null

echo "→ theme $THEME"
install -d -m 0755 "$DIR"
install -m 0644 "$LOGO" "$DIR/logo.png"

cat > "$DIR/$THEME.plymouth" <<EOF
[Plymouth Theme]
Name=Jimny
Description=Jimny boot splash
ModuleName=script

[script]
ImageDir=$DIR
ScriptFile=$DIR/$THEME.script
EOF

cat > "$DIR/$THEME.script" <<'EOF'
Window.SetBackgroundTopColor(0.0, 0.0, 0.0);
Window.SetBackgroundBottomColor(0.0, 0.0, 0.0);

logo = Image("logo.png");
sprite = Sprite();
last_w = -1;

fun refresh() {
  w = Window.GetWidth();
  h = Window.GetHeight();
  if (w <= 0) return;
  if (h <= 0) return;
  if (w == last_w) return;

  sx = w / logo.GetWidth();
  sy = h / logo.GetHeight();
  s = sx;
  if (sy > sx) s = sy;

  nw = Math.Int(logo.GetWidth() * s);
  nh = Math.Int(logo.GetHeight() * s);
  sprite.SetImage(logo.Scale(nw, nh));
  sprite.SetPosition(Math.Int((w - nw) / 2), Math.Int((h - nh) / 2), 10);
  last_w = w;
}

Plymouth.SetRefreshFunction(refresh);
EOF

echo "→ default theme + initramfs (takes a moment)"
plymouth-set-default-theme "$THEME" -R

install -d -m 0755 /etc/plymouth
cat > /etc/plymouth/plymouthd.conf <<EOF
[Daemon]
Theme=$THEME
ShowDelay=0
DeviceTimeout=30
EOF

echo "→ config.txt"
if ! grep -qE '^\s*disable_splash=1' "$CONFIG"; then
  echo "disable_splash=1" >> "$CONFIG"
fi
# early firmware modeset: without it plymouth can render into an offline output
sed -i -E 's/^disable_fw_kms_setup=1/# disable_fw_kms_setup=1   # disabled for the boot splash/' "$CONFIG"

echo "→ cmdline.txt"
cp -a "$CMDLINE" "$CMDLINE.bak.$(date +%s)"
LINE="$(tr -d '\n' < "$CMDLINE")"
add() { case " $LINE " in *" $1 "*) ;; *) LINE="$LINE $1" ;; esac; }
add quiet; add splash; add plymouth.ignore-serial-consoles
add loglevel=0; add logo.nologo; add vt.global_cursor_default=0
# keep exactly one video= pin, and put it last so plymouth uses the panel mode
VIDEO="$(grep -o 'video=[^ ]*' <<< "$LINE" | head -n1 || true)"
if [[ -n "$VIDEO" ]]; then
  LINE="$(sed -E 's/[[:space:]]*video=[^ ]+//g' <<< "$LINE") $VIDEO"
fi
printf '%s\n' "$LINE" > "$CMDLINE"

echo
echo "splash installed; reboot to see it"
echo "  theme: $(plymouth-set-default-theme)"
echo "  cmdline: $(cat "$CMDLINE")"
