#!/usr/bin/env bash
# Report which MFi path a HUDIY installation is using.
#
# HUDIY does not authenticate to the iPhone itself: CarPlay runs through a
# CarlinKit CPC200-CCPA / CPC200-Autokit ("Autobox") dongle, which is the MFi
# accessory. This script shows whether such a dongle is attached, what HUDIY's
# autobox configuration expects, and therefore whether libmfi is involved at all
# (it is not, unless you replace HUDIY's CarPlay stack).
#
#   tools/hudiy-autobox-check.sh [HUDIY_HOME]
set -uo pipefail

HUDIY_HOME="${1:-${HUDIY_HOME:-$HOME/.hudiy}}"
CONFIG="$HUDIY_HOME/config/main_configuration.json"
fail=0

echo "HUDIY home: $HUDIY_HOME"
if [[ -d "$HUDIY_HOME" ]]; then
  echo "  installed: yes"
else
  echo "  installed: no (HUDIY is Linux-only; nothing to check here)"
fi

if [[ -f "$CONFIG" ]]; then
  python3 - "$CONFIG" <<'PY'
import json, sys
cfg = json.load(open(sys.argv[1]))
ab = cfg.get("autobox", {})
print(f"  oemName: {ab.get('oemName', '?')}")
print(f"  autoWirelessConnection: {ab.get('autoWirelessConnection', '?')}")
for dev in ab.get("allowedDevices", []):
    print(f"  allowed dongle: usb {dev.get('vendorId'):#06x}:{dev.get('productId'):#06x}")
PY
else
  echo "  config: not found at $CONFIG"
fi

echo
echo "attached Autobox dongles:"
if [[ "$(uname -s)" == "Linux" ]] && command -v lsusb >/dev/null 2>&1; then
  found="$(lsusb | grep -iE "1314:(1520|1521)" || true)"
elif [[ "$(uname -s)" == "Darwin" ]]; then
  found="$(system_profiler SPUSBDataType 2>/dev/null | grep -iE "Vendor ID: 0x1314|Product ID: 0x1520|Product ID: 0x1521|Autokit|Carlinkit" || true)"
else
  found=""
fi
if [[ -n "$found" ]]; then
  echo "$found" | sed 's/^/  /'
  echo
  echo "MFi path: the dongle. Its firmware holds the accessory identity and answers"
  echo "iAP2 AccAuthentication itself; HUDIY only renders the stream."
  echo "Profile that identity with: tools/dongle-mfi-profile.py <dongle image or dump>"
else
  echo "  none (vendor 0x1314, products 0x1520/0x1521)"
  echo
  echo "MFi path: none right now. Without the dongle HUDIY has no CarPlay; libmfi cannot"
  echo "stand in for it, because HUDIY speaks the dongle protocol, not iAP2."
fi

echo
echo "For a native CarPlay accessory (no dongle), libmfi serves iAP2 AccAuthentication,"
echo "MFiSAP v1 and the coprocessor protocol today; CarPlay also needs MFi4 and the"
echo "AirPlay session, which LIVI implements (see spec/06)."

exit "$fail"
