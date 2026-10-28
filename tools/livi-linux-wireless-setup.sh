#!/usr/bin/env bash
# Configure a Linux head unit for wireless CarPlay with LIVI.
#
# LIVI drives wireless CarPlay natively on Linux: BlueZ hosts the Bluetooth side
# (pairing + HFP handover) and hostapd supplies the Wi-Fi access point the phone
# joins.  MFi comes from an identity directory (or an I2C coprocessor, or a LIVI
# Link), exactly like on macOS.
#
# This script only edits configuration and the identity directory; it does not
# touch Bluetooth/Wi-Fi stacks.  Run it on the head unit, as the user that runs
# LIVI.
#
#   tools/livi-linux-wireless-setup.sh \
#       --ssid "My Car" --password "secret123" --iface wlan0 \
#       --identity /path/to/identity
#
#   --print-config FILE   write the resulting config.json to FILE and exit
#                         (works on any OS, for validation)
set -euo pipefail

SSID=""
PASSWORD=""
IFACE="wlan0"
BAND="5ghz"
CHANNEL="36"
WIDTH=""
COUNTRY=""
BT="hci0"
IDENTITY=""
PRINT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ssid) SSID="$2"; shift 2 ;;
    --password) PASSWORD="$2"; shift 2 ;;
    --iface) IFACE="$2"; shift 2 ;;
    --band) BAND="$2"; shift 2 ;;
    --channel) CHANNEL="$2"; shift 2 ;;
    --width) WIDTH="$2"; shift 2 ;;
    --country) COUNTRY="$2"; shift 2 ;;
    --bt) BT="$2"; shift 2 ;;
    --identity) IDENTITY="$2"; shift 2 ;;
    --print-config) PRINT="$2"; shift 2 ;;
    -h|--help) sed -n '1,24p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ "$(uname -s)" != "Linux" && -z "$PRINT" ]]; then
  echo "This configures a Linux head unit. On macOS use --print-config, or a LIVI Link dongle." >&2
  exit 2
fi

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

CONFIG="${LIVI_CONFIG:-$HOME/.config/LIVI/config.json}"
[[ -n "$PRINT" ]] && CONFIG="$PRINT"

SEED="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/livi-default-config.json"

python3 - "$CONFIG" "$SSID" "$PASSWORD" "$IFACE" "$BAND" "$CHANNEL" "$WIDTH" "$COUNTRY" "$BT" "$SEED" <<'PY'
import json, os, sys

path, ssid, password, iface, band, channel, width, country, bt, seed = sys.argv[1:11]
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

config.update(
    {
        "carName": ssid,
        "wirelessCpEnabled": True,
        "wifiPassword": password,
        "wifiInterface": iface,
        "wifiType": band,
        "wifiChannel": int(channel),
        "wifiChannelWidth": int(width),
        "btAdapter": bt,
        "wifiDedicatedInterface": config.get("wifiDedicatedInterface", False),
    }
)
if country:
    config["country"] = country

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

# Identity: the same two files libmfi and LIVI both use.
if [[ -n "$IDENTITY" ]]; then
  MFI_DIR="$HOME/.config/LIVI/mfi"
  mkdir -p "$MFI_DIR"
  install -m 600 "$IDENTITY/identity.pk8" "$MFI_DIR/identity.pk8"
  install -m 600 "$IDENTITY/certificate.p7b" "$MFI_DIR/certificate.p7b"
  echo "installed identity into $MFI_DIR"
fi

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
