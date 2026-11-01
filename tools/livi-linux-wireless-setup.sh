#!/usr/bin/env bash
# Configure a Linux head unit for CarPlay with LIVI, wired (USB) or wireless.
#
# Wired CarPlay needs no radios at all: the phone is on the cable, LIVI claims it
# over usbfs, and MFi comes from the identity directory.  Wireless adds BlueZ
# (pairing + HFP handover) and a hostapd access point the phone joins on 5 GHz.
# In both modes MFi comes from the same identity directory (or an I2C
# coprocessor, or a LIVI Link).
#
# This script only edits configuration and the identity directory; it does not
# touch Bluetooth/Wi-Fi stacks.  Run it on the head unit, as the user that runs
# LIVI.
#
#   tools/livi-linux-wireless-setup.sh --wired --identity /path/to/identity
#       -> wired CarPlay, 800x480@30 for a 7" panel
#
#   tools/livi-linux-wireless-setup.sh \
#       --ssid "My Car" --password "secret123" --iface wlan1 --dedicated \
#       --identity /path/to/identity
#       -> wireless CarPlay on a 5 GHz access point
#
#   --wired               wired/USB mode: no radio keys, no password required
#   --resolution WxH      projectionWidth/Height (wired default 800x480)
#   --fps N               projectionFps (wired default 30)
#   --dpi N               projectionDpi
#   --dedicated           wifiDedicatedInterface=true (AP on its own adapter)
#   --rhd | --lhd         hand=1 (right-hand drive) or hand=0; CarPlay mirrors its dock
#   --dock auto|side|bottom   carPlayDockPosition
#   --check               run tools/livi-pi-preflight.sh first; stop on blocking
#                         failures (2/4/5), warn and continue on 3
#   --print-config FILE   write the resulting config.json to FILE and exit
#                         (works on any OS, for validation)
set -euo pipefail

MODE="wireless"
SSID=""
PASSWORD=""
IFACE="wlan0"
BAND="5ghz"
CHANNEL="36"
WIDTH=""
COUNTRY=""
BT="hci0"
IDENTITY=""
DEDICATED=0
HAND=""
DOCK=""
CHECK=0
RES=""
FPS=""
DPI=""
PRINT=""

usage() { sed -n '2,29p' "$0"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --wired) MODE="wired"; shift ;;
    --ssid) SSID="$2"; shift 2 ;;
    --password) PASSWORD="$2"; shift 2 ;;
    --iface) IFACE="$2"; shift 2 ;;
    --band) BAND="$2"; shift 2 ;;
    --channel) CHANNEL="$2"; shift 2 ;;
    --width) WIDTH="$2"; shift 2 ;;
    --country) COUNTRY="$2"; shift 2 ;;
    --bt) BT="$2"; shift 2 ;;
    --identity) IDENTITY="$2"; shift 2 ;;
    --dedicated) DEDICATED=1; shift ;;
    --rhd) HAND=1; shift ;;
    --lhd) HAND=0; shift ;;
    --dock) DOCK="$2"; shift 2 ;;
    --check) CHECK=1; shift ;;
    --resolution) RES="$2"; shift 2 ;;
    --fps) FPS="$2"; shift 2 ;;
    --dpi) DPI="$2"; shift 2 ;;
    --print-config) PRINT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ "$(uname -s)" != "Linux" && -z "$PRINT" ]]; then
  echo "This configures a Linux head unit. On macOS use --print-config, or a LIVI Link dongle." >&2
  exit 2
fi

RES_W=""; RES_H=""
if [[ -n "$RES" ]]; then
  if [[ ! "$RES" =~ ^([0-9]+)x([0-9]+)$ ]]; then
    echo "--resolution must look like 800x480" >&2; exit 2
  fi
  RES_W="${BASH_REMATCH[1]}"; RES_H="${BASH_REMATCH[2]}"
elif [[ "$MODE" == "wired" ]]; then
  RES_W=800; RES_H=480
fi
if [[ -n "$FPS" ]]; then
  [[ "$FPS" =~ ^[0-9]+$ ]] || { echo "--fps must be a number" >&2; exit 2; }
elif [[ "$MODE" == "wired" ]]; then
  FPS=30
fi
if [[ -n "$DPI" && ! "$DPI" =~ ^[0-9]+$ ]]; then
  echo "--dpi must be a number" >&2; exit 2
fi
case "$DOCK" in ''|auto|side|bottom) ;; *) echo "--dock must be auto, side or bottom" >&2; exit 2 ;; esac

if [[ "$MODE" == "wireless" ]]; then
  if [[ -z "$PASSWORD" ]]; then
    if [[ -n "$PRINT" ]]; then
      PASSWORD="changeme123"
    else
      echo "--password is required (WPA2, 8..63 characters)" >&2
      exit 2
    fi
  fi
  case "$BAND" in 2.4ghz|5ghz|6ghz) ;; *) echo "--band must be 2.4ghz, 5ghz or 6ghz" >&2; exit 2 ;; esac
  if [[ -z "$WIDTH" ]]; then
    [[ "$BAND" == "2.4ghz" ]] && WIDTH=20 || WIDTH=40
  fi
  if (( ${#PASSWORD} < 8 || ${#PASSWORD} > 63 )); then
    echo "the Wi-Fi password must be 8..63 characters" >&2
    exit 2
  fi
fi

CONFIG="${LIVI_CONFIG:-$HOME/.config/LIVI/config.json}"
[[ -n "$PRINT" ]] && CONFIG="$PRINT"

SEED="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/livi-default-config.json"

# Identity first: the preflight judges what the helper will actually read.
if [[ -n "$IDENTITY" && -z "$PRINT" ]]; then
  MFI_DIR="$HOME/.config/LIVI/mfi"
  mkdir -p "$MFI_DIR"
  install -m 600 "$IDENTITY/identity.pk8" "$MFI_DIR/identity.pk8"
  install -m 600 "$IDENTITY/certificate.p7b" "$MFI_DIR/certificate.p7b"
  echo "installed identity into $MFI_DIR"
fi

if (( CHECK )) && [[ -z "$PRINT" ]]; then
  PREFLIGHT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/livi-pi-preflight.sh"
  if [[ ! -x "$PREFLIGHT" ]]; then
    echo "preflight missing: $PREFLIGHT" >&2
    exit 2
  fi
  preflight_args=(--mode "$MODE")
  [[ -n "$IDENTITY" ]] && preflight_args+=(--identity "$HOME/.config/LIVI/mfi")
  set +e
  "$PREFLIGHT" "${preflight_args[@]}"
  rc=$?
  set -e
  case "$rc" in
    0) ;;
    3) echo "preflight: fixable issues above; writing the config anyway" >&2 ;;
    *) echo "preflight stopped with exit $rc; config.json was not touched" >&2; exit 1 ;;
  esac
fi

python3 - "$CONFIG" "$MODE" "$SSID" "$PASSWORD" "$IFACE" "$BAND" "$CHANNEL" "$WIDTH" \
  "$COUNTRY" "$BT" "$SEED" "$RES_W" "$RES_H" "$FPS" "$DPI" "$DEDICATED" "$HAND" "$DOCK" <<'PY'
import json, os, sys

(path, mode, ssid, password, iface, band, channel, width, country, bt,
 seed, res_w, res_h, fps, dpi, dedicated, hand, dock) = sys.argv[1:19]

# LIVI's Config requires every field, so always start from its own defaults and
# overlay whatever the machine already has (an older or partial file included).
with open(seed) as f:
    config = json.load(f)
if os.path.exists(path):
    with open(path) as f:
        text = f.read().strip()
    if text:
        config.update(json.loads(text))

if not ssid:
    ssid = config.get("carName") or "LIVI"
config["carName"] = ssid

if mode == "wireless":
    config.update(
        {
            "wirelessCpEnabled": True,
            "wifiPassword": password,
            "wifiInterface": iface,
            "wifiType": band,
            "wifiChannel": int(channel),
            "wifiChannelWidth": int(width),
            "btAdapter": bt,
            "wifiDedicatedInterface": bool(int(dedicated))
            or config.get("wifiDedicatedInterface", False),
        }
    )
    if country:
        config["country"] = country
elif mode == "wired":
    # Wired CarPlay reads none of the wifi*/bt* keys; leave whatever is there
    # untouched and make sure LIVI does not bring an access point up.
    config["wirelessCpEnabled"] = False

if res_w:
    config["projectionWidth"] = int(res_w)
    config["projectionHeight"] = int(res_h)
if fps:
    config["projectionFps"] = int(fps)
if dpi:
    config["projectionDpi"] = int(dpi)
if hand != "":
    config["hand"] = int(hand)          # 0 = left-hand drive, 1 = right-hand drive
if dock:
    config["carPlayDockPosition"] = dock

os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
tmp = path + ".tmp"
with open(tmp, "w") as f:
    json.dump(config, f, indent=2, sort_keys=True)
    f.write("\n")
os.replace(tmp, path)
print(f"wrote {path}")
PY

if [[ -n "$PRINT" ]]; then
  echo "config written to $PRINT (no identity copied)"
  exit 0
fi

if [[ "$MODE" == "wired" ]]; then
  cat <<EOF

Wired CarPlay is configured. Check these host prerequisites on the head unit:

  USB        the iPhone on a USB-A port; LIVI's helper claims it as root, so the
             99-LIVI.rules from the installer must be in place
  Display    projection ${RES_W}x${RES_H}@${FPS:-?} against the panel's own mode
  MFi        $HOME/.config/LIVI/mfi/{identity.pk8,certificate.p7b}
              or an I2C coprocessor at 0x10/0x11 (carPlayMfiI2cBus)
  Audio      a PipeWire/PulseAudio sink, and a microphone for calls and Siri

Plug the phone in, unlock it, accept "Trust" and "Allow CarPlay".  The helper
logs "[wired] ... usbmuxd carkit up" followed by "[cp] wired: MFi auth succeeded".

tools/livi-pi-preflight.sh answers "what is still missing" at any point.
EOF
else
  cat <<EOF

Wireless CarPlay is configured. Check these host prerequisites on the head unit:

  Bluetooth   bluetoothd running, adapter "$BT" present
              (LIVI adds a Hands-Free + CarPlay service record; the phone pairs here)
  Wi-Fi       "$IFACE" not managed by NetworkManager while the AP runs, unless
              wifiDedicatedInterface is true; 5 GHz needs a regulatory domain
              (country) that allows channels $CHANNEL
  MFi         $HOME/.config/LIVI/mfi/{identity.pk8,certificate.p7b}
              or an I2C coprocessor at 0x10/0x11 (carPlayMfiI2cBus)

Start LIVI (or its compositor service) and open Settings -> General -> Connections
to confirm the access point and adapter.  On the phone: Settings -> General ->
CarPlay, pick the car while it is in range.

Wireless CarPlay is not available on macOS without a LIVI Link dongle: LIVI's
macOS helper has no Bluetooth stack of its own and talks to the dongle instead.
EOF
fi
