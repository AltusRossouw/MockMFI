#!/usr/bin/env bash
# Read-only preflight for a Raspberry Pi CarPlay head unit running LIVI.
#
# Answers one question: can this board, with this display and this identity, run
# CarPlay through LIVI - and if not, exactly what is missing.  It changes
# nothing, needs no root, and works on a machine that is not a Pi at all (it then
# reports what it could not see, instead of guessing).
#
#   tools/livi-pi-preflight.sh                     # wired (USB) CarPlay, the first target
#   tools/livi-pi-preflight.sh --mode wireless     # adds the 5 GHz AP / Bluetooth checks
#   tools/livi-pi-preflight.sh --json              # machine-readable, consumed by the setup script
#   tools/livi-pi-preflight.sh --selftest          # run the three fixtures below, no hardware
#
# Exit codes
#   0  ready for the selected mode
#   1  usage error
#   2  wireless only: no AP-capable radio at all (wired CarPlay still works)
#   3  fixable on this board: config, codec or device state
#   4  missing package, unit or udev rule
#   5  identity, display or touch is wrong
#
# Options
#   --mode wired|wireless   default: wired
#   --identity DIR          identity directory, default ~/.config/LIVI/mfi
#   --interface NAME        wireless: interface to judge, default: every phy found
#   --json                  emit one JSON object and nothing else
#   --selftest              run the embedded fixtures
#
# Environment (used by the fixtures and by tests, not needed on a head unit)
#   LIVI_PREFLIGHT_ROOT     read every file below this prefix instead of /; a test
#                           root also supplies command output from $ROOT/cmd/
set -uo pipefail
# iw, hostapd and rfkill live in sbin; an ssh user session often has neither in PATH.
export PATH="${PATH}:/usr/sbin:/sbin"

MODE="wired"
IDENTITY="${HOME}/.config/LIVI/mfi"
WANT_IFACE=""
JSON=0
SELFTEST=0
ROOT="${LIVI_PREFLIGHT_ROOT:-}"
[[ "$ROOT" == "/" ]] && ROOT=""

usage() {
  cat <<'USAGE'
Read-only preflight for a Raspberry Pi CarPlay head unit running LIVI.

  --mode wired|wireless   default: wired
  --identity DIR          identity directory, default ~/.config/LIVI/mfi
  --interface NAME        wireless: interface to judge, default: every phy found
  --json                  emit one JSON object and nothing else
  --selftest              run the embedded fixtures

Exit codes: 0 ready, 1 usage, 2 no AP-capable radio, 3 fixable,
            4 missing package/unit/udev rule, 5 identity/display/touch.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="${2:-}"; shift 2 ;;
    --identity) IDENTITY="${2:-}"; shift 2 ;;
    --interface) WANT_IFACE="${2:-}"; shift 2 ;;
    --json) JSON=1; shift ;;
    --selftest) SELFTEST=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done
case "$MODE" in wired|wireless) ;; *) echo "--mode must be wired or wireless" >&2; exit 1 ;; esac

# ---------------------------------------------------------------- primitives

P() { printf '%s%s' "$ROOT" "$1"; }

# Read a file below the root prefix; empty when it is not there.
read_file() { [[ -f "$1" ]] && cat "$1" 2>/dev/null; }

# Command output. A test root never touches the host: it answers only from
# $ROOT/cmd/<name>, and says so when there is no fixture for a command.
cmd_out() {
  local name="$1"; shift
  if [[ -n "$ROOT" ]]; then
    [[ -f "$(P "/cmd/$name")" ]] || return 127
    cat "$(P "/cmd/$name")"
    return 0
  fi
  command -v "$name" >/dev/null 2>&1 || return 127
  "$name" "$@" 2>/dev/null
}

have_cmd() {
  if [[ -n "$ROOT" && -e "$(P "/cmd/$1")" ]]; then return 0; fi
  command -v "$1" >/dev/null 2>&1
}

mode_of() { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null; }

# ---------------------------------------------------------------- registry

declare -a CH_ID=() CH_ST=() CH_DETAIL=() CH_FIX=()
FAIL_CONFIG=0 FAIL_DEPS=0 FAIL_UNIT=0 FAIL_RADIO=0 WIFI24_ONLY=0

# record <id> <ok|warn|fail|info|skip> <detail> [fix]
record() {
  CH_ID+=("$1"); CH_ST+=("$2"); CH_DETAIL+=("$3"); CH_FIX+=("${4:-}")
  [[ "$2" == "fail" ]] || return 0
  case "$1" in
    wifi.5ghz_ap) : ;;                  # check_wifi sets the verdict flag itself
    wifi.*|bt.*|deps.*|usb.*) FAIL_DEPS=1 ;;
    display.*|mfi.*) FAIL_UNIT=1 ;;
    *) FAIL_CONFIG=1 ;;
  esac
}

# ---------------------------------------------------------------- host

check_host() {
  local model arch ram_mb codename
  model="$(read_file "$(P /proc/device-tree/model)" | tr -d '\0')"
  if [[ -n "$model" ]]; then
    case "$model" in
      *"Raspberry Pi 3 Model B"*)
        record host.model ok "$model (2.4 GHz-only radio, BT 4.1)" ;;
      *"Raspberry Pi"*)
        record host.model ok "$model" ;;
      *)
        record host.model warn "$model (not a Raspberry Pi)" ;;
    esac
  else
    record host.model warn "no /proc/device-tree/model: not a Raspberry Pi, or no device tree"
  fi

  arch="$(cmd_out uname -m)"
  if [[ -z "$arch" ]]; then
    record host.arch skip "uname unavailable"
  elif [[ "$arch" == "aarch64" || "$arch" == "arm64" || "$arch" == "x86_64" || "$arch" == "amd64" ]]; then
    record host.arch ok "$arch (LIVI AppImage available)"
  else
    record host.arch fail "$arch: LIVI ships arm64 and x86_64 only" \
      "use a 64-bit OS; the installer refuses armhf"
  fi

  ram_mb="$(awk '/^MemTotal:/ {print int($2/1024)}' "$(P /proc/meminfo)" 2>/dev/null)"
  if [[ -z "$ram_mb" ]]; then
    record host.ram skip "no /proc/meminfo"
  elif (( ram_mb >= 1500 )); then
    record host.ram ok "${ram_mb} MB"
  else
    record host.ram warn "${ram_mb} MB: enough for 800x480@30, not for 720p60" \
      "keep projectionFps at 30 and avoid a cluster stream"
  fi

  codename="$(awk -F= '/^VERSION_CODENAME=/ {gsub(/"/, "", $2); print $2}' "$(P /etc/os-release)" 2>/dev/null)"
  case "$codename" in
    trixie) record os.release ok "trixie" ;;
    "") record os.release skip "no /etc/os-release" ;;
    *) record os.release warn "$codename: LIVI asks for Trixie (Debian 13) on a Pi 3" \
         "reflash with Raspberry Pi OS Trixie 64-bit" ;;
  esac
}

# ---------------------------------------------------------------- display/touch

check_display() {
  local dir status mode seen=""
  shopt -s nullglob
  for dir in "$(P /sys/class/drm)"/card*-*; do
    [[ -f "$dir/status" ]] || continue
    status="$(read_file "$dir/status")"
    [[ "$status" == "connected" ]] || continue
    mode="$(head -n 1 "$dir/modes" 2>/dev/null)"
    seen="${seen:+$seen, }${dir##*/} ${mode:-no-mode}"
  done
  shopt -u nullglob

  if [[ -z "$seen" ]]; then
    record display.drm fail "no connected DRM connector" \
      "check the DSI/HDMI cable and dtoverlay=vc4-kms-v3d"
  else
    record display.drm ok "$seen"
    case "$seen" in
      *800x480*) ;;
      *) record display.mode warn "no 800x480 mode on the connected output" \
           "set projectionWidth/Height to the panel's own mode, not the other way round" ;;
    esac
  fi

  local f word val name_file dev
  local found=""
  shopt -s nullglob
  for f in "$(P /sys/class/input)"/event*/device/capabilities/abs; do
    word="$(awk '{print $NF}' "$f" 2>/dev/null)"
    [[ "$word" =~ ^[0-9a-fA-F]{1,16}$ ]] || continue
    if [[ ${#word} -eq 16 ]]; then
      case "${word:0:1}" in [89a-fA-F]) continue ;; esac   # would overflow bash arithmetic
    fi
    val=$((0x$word))
    (( (val >> 53) & 1 )) || continue          # ABS_MT_POSITION_X
    dev="$(dirname "$(dirname "$f")")"
    name_file="$dev/name"
    found="${found:+$found, }$(read_file "$name_file" 2>/dev/null)"
  done
  shopt -u nullglob

  if [[ -n "$found" ]]; then
    record display.touch ok "multitouch: $found"
  elif [[ -n "$ROOT" ]]; then
    record display.touch fail "no ABS_MT_POSITION_X device under the fixture root" \
      "attach the touch panel or fix the fixture"
  elif have_cmd libinput && libinput list-devices 2>/dev/null | grep -qi "capabilities:.*touch"; then
    record display.touch ok "libinput reports a touch device"
  else
    record display.touch fail "no touch digitizer found" \
      "the official 7\" panel needs its I2C touch overlay; other panels need libinput support"
  fi
}

# ---------------------------------------------------------------- video

check_video() {
  local names="" n
  shopt -s nullglob
  for n in "$(P /sys/class/video4linux)"/*/name; do
    names="${names:+$names, }$(read_file "$n")"
  done
  shopt -u nullglob

  local tool=0 elem=0 bcm=0
  case "$names" in *bcm2835*|*h264*) bcm=1 ;; esac
  if [[ -n "$ROOT" ]]; then
    if [[ -e "$(P /cmd/gst-inspect-1.0)" ]]; then
      tool=1
      grep -q v4l2h264dec "$(P /cmd/gst-inspect-1.0)" 2>/dev/null && elem=1
    fi
  elif command -v gst-inspect-1.0 >/dev/null 2>&1; then
    tool=1
    gst-inspect-1.0 v4l2h264dec >/dev/null 2>&1 && elem=1
  fi

  if (( tool && elem && bcm )); then
    record video.decoder ok "v4l2h264dec + $names"
  elif (( tool && bcm )); then
    record video.decoder fail "$names present, but GStreamer has no v4l2h264dec" \
      "the AppImage bundle carries it; a distro build needs gstreamer1.0-plugins-good"
  elif (( tool && elem )); then
    record video.decoder warn "v4l2h264dec present, no bcm2835 codec node ($names)" \
      "decode will most likely land on avdec_h264; measure before trusting it"
  elif (( tool )); then
    record video.decoder fail "no H.264 hardware decoder visible ($names)" \
      "check dtoverlay=vc4-kms-v3d and that bcm2835-codec is loaded"
  elif (( bcm )); then
    record video.decoder warn "$names present, gst-inspect-1.0 not installed" \
      "apt install gstreamer1.0-tools for a definitive row; otherwise the session log decides"
  else
    record video.decoder warn "no codec node and no gst-inspect-1.0" \
      "check dtoverlay=vc4-kms-v3d, then read the session log's codec= line"
  fi

  if [[ -n "$ROOT" ]]; then
    record video.avdec skip "fixture: not checked"
  elif ! have_cmd gst-inspect-1.0; then
    record video.avdec skip "gst-inspect-1.0 not installed on this host"
  elif gst-inspect-1.0 avdec_h264 >/dev/null 2>&1; then
    record video.avdec ok "software fallback available (LIVI_GST_SWDEC=1 forces it)"
  else
    record video.avdec warn "avdec_h264 missing: no software fallback" \
      "install gstreamer1.0-libav or use the AppImage bundle"
  fi

  local cma
  cma="$(awk '/^CmaTotal:/ {print int($2/1024)}' "$(P /proc/meminfo)" 2>/dev/null)"
  if [[ -z "$cma" ]]; then
    record video.cma skip "no CmaTotal"
  elif (( cma >= 64 )); then
    record video.cma ok "${cma} MB CMA"
  else
    record video.cma warn "${cma} MB CMA: 720p decode buffers may not fit" \
      "raise cma in config.txt (cma-256)"
  fi
}

# ---------------------------------------------------------------- LIVI install

check_livi() {
  local rule kiosk wants helper
  rule="$(P /etc/udev/rules.d/99-LIVI.rules)"
  if [[ -f "$rule" ]]; then
    record usb.rule ok "$(awk -F= '/LIVI-RULE-VERSION/ {print "version " $2}' "$rule" | head -n1)"
  else
    record usb.rule fail "missing $rule" \
      "run LIVI's install.sh; the rule keeps gphoto2/udisks off the iPhone"
  fi

  kiosk="$(P /etc/systemd/system/livi-kiosk.service)"
  wants="$(P /etc/systemd/system/multi-user.target.wants/livi-kiosk.service)"
  if [[ -f "$kiosk" && -e "$wants" ]]; then
    record usb.kiosk ok "livi-kiosk.service enabled"
  elif [[ -f "$kiosk" ]]; then
    record usb.kiosk fail "livi-kiosk.service present but not enabled" \
      "systemctl enable --now livi-kiosk.service"
  else
    record usb.kiosk fail "no livi-kiosk.service" \
      "install.sh --headless installs the kiosk unit"
  fi

  helper="$(P /etc/sudoers.d/99-LIVI-helper)"
  if [[ -f "$helper" ]]; then
    record usb.helper ok "helper sudoers drop-in present (USB is claimed as root)"
  else
    record usb.helper fail "no sudoers drop-in for livi-helperd" \
      "re-run install.sh; without it the helper cannot claim the iPhone"
  fi
}

# ---------------------------------------------------------------- USB / phone

check_usb() {
  local dev vid cfg pid=""
  shopt -s nullglob
  for dev in "$(P /sys/bus/usb/devices)"/*/idVendor; do
    vid="$(read_file "$dev")"
    [[ "$vid" == "05ac" ]] || continue
    cfg="$(read_file "$(dirname "$dev")/bConfigurationValue")"
    pid="${dev%/idVendor}"
    pid="${pid##*/}"
    record usb.phone info "Apple device $pid, bConfigurationValue=${cfg:-?} (6 = CarPlay config)"
  done
  shopt -u nullglob
  [[ -n "$pid" ]] || record usb.phone info "no iPhone attached right now"
}

# ---------------------------------------------------------------- MFi identity

check_mfi() {
  local key cert dmode kmode cmode
  if [[ ! -d "$IDENTITY" ]]; then
    record mfi.files fail "no identity directory at $IDENTITY" \
      "stage identity.pk8 and certificate.p7b there (mode 600, dir 700)"
    return
  fi
  key="$IDENTITY/identity.pk8"
  cert="$IDENTITY/certificate.p7b"
  if [[ ! -f "$key" || ! -f "$cert" ]]; then
    local missing=""
    [[ -f "$key" ]] || missing="identity.pk8"
    [[ -f "$cert" ]] || missing="${missing:+$missing and }certificate.p7b"
    record mfi.files fail "$IDENTITY is missing $missing" \
      "LIVI's helper reads these two files before it looks for an I2C chip"
    return
  fi
  dmode="$(mode_of "$IDENTITY")"; kmode="$(mode_of "$key")"; cmode="$(mode_of "$cert")"
  if [[ "$dmode" == "700" && "$kmode" == "600" && "$cmode" == "600" ]]; then
    record mfi.files ok "$IDENTITY (700/600)"
  else
    record mfi.files warn "$IDENTITY is ${dmode:-?}, files ${kmode:-?}/${cmode:-?}" \
      "chmod 700 the directory and 600 the two files"
  fi
}

# ---------------------------------------------------------------- audio/thermal

check_audio() {
  local sink
  sink="$(cmd_out pactl info | awk -F': ' '/^Default Sink:/ {print $2}')"
  if [[ -z "$sink" ]]; then
    record audio.sink skip "pactl unavailable or no PipeWire/PulseAudio session"
  else
    record audio.sink info "default sink: $sink"
  fi
}

check_thermal() {
  local t
  t="$(read_file "$(P /sys/class/thermal/thermal_zone0/temp)")"
  if [[ ! "$t" =~ ^[0-9]+$ ]]; then
    record thermal skip "no thermal zone"
  elif (( t > 70000 )); then
    record thermal warn "$((t / 1000)) C right now" \
      "add a heatsink; the Pi 3 throttles at 80 C"
  else
    record thermal ok "$((t / 1000)) C"
  fi
}

# ---------------------------------------------------------------- Wi-Fi (wireless mode)

iw_phy_info() {
  local phy="$1"
  if [[ -n "$ROOT" ]]; then
    if [[ -f "$(P "/cmd/iw/$phy.txt")" ]]; then cat "$(P "/cmd/iw/$phy.txt")"; return 0; fi
    if [[ -f "$(P /cmd/iw)" ]]; then cat "$(P /cmd/iw)"; return 0; fi
    return 127
  fi
  iw phy "$phy" info 2>/dev/null
}

# -> "ap=0|1 g24=0|1 g5=0|1 chans=36,40 std=802.11ac"
parse_iw_phy() {
  awk '
    /\* AP[ ]*$/ { ap = 1 }
    /HT20\/HT40/ { ht40 = 1; ht = 1 }
    /^[ \t]*HT20[ \t]*$/ { ht = 1 }
    /VHT Capabilities/ { vht = 1 }
    /HE MAC Capabilities/ { he = 1 }
    /^[ \t]*\* [0-9]+(\.[0-9]+)? MHz \[[0-9]+\]/ {
      freq = $2 + 0; ch = $4; gsub(/[\[\]]/, "", ch)
      if (freq >= 2400 && freq <= 2500) g24 = 1
      if (freq >= 5000 && freq <= 5895) {
        g5 = 1
        if ($0 !~ /no IR/) { chans = chans (chans == "" ? "" : ",") ch }
      }
    }
    END {
      std = he ? "802.11ax" : (vht ? "802.11ac" : (ht ? "802.11n" : "802.11"))
      printf "ap=%d g24=%d g5=%d chans=%s std=%s\n", ap, g24, g5, (chans == "" ? "-" : chans), std
    }'
}

check_wifi() {
  local link phy iface out ap g24 g5 chans std
  local best_iface="" best_phy="" best_chans="" best_std=""
  local any5=0 anyap=0 any24ap=0

  shopt -s nullglob
  for link in "$(P /sys/class/net)"/*/phy80211; do
    iface="$(basename "$(dirname "$link")")"
    phy="$(basename "$(readlink "$link" 2>/dev/null || printf '%s' "$link")")"
    out="$(iw_phy_info "$phy" | parse_iw_phy)"
    if [[ ! "$out" =~ ^ap=[01]\ g24=[01]\ g5=[01]\ chans=[0-9,-]+\ std=[0-9a-z.]+$ ]]; then
      record "wifi.radio.$iface" skip "$phy: no iw output"
      continue
    fi
    eval "$out"
    if (( ap )); then anyap=1; fi
    if (( g5 )); then any5=1; fi
    if (( ap && g24 )); then any24ap=1; fi
    record "wifi.radio.$iface" info "$iface ($phy): 2.4GHz=$([[ $g24 == 1 ]] && echo yes || echo no), 5GHz=$([[ $g5 == 1 ]] && echo yes || echo no), AP=$([[ $ap == 1 ]] && echo yes || echo no), 5GHz-AP=$chans, $std"
    if (( g5 && ap )); then
      if [[ -z "$WANT_IFACE" || "$WANT_IFACE" == "$iface" ]]; then
        best_iface="$iface"; best_phy="$phy"; best_chans="$chans"; best_std="$std"
      fi
    fi
  done
  shopt -u nullglob

  if [[ -z "$best_iface" ]]; then
    if (( any5 && ! anyap )); then
      record wifi.5ghz_ap fail "a 5 GHz radio exists but offers no AP mode" \
        "pick an adapter whose phy lists '* AP' (mt7612u, mt7921au)"
      FAIL_RADIO=1
    elif (( any5 )); then
      record wifi.5ghz_ap fail "${WANT_IFACE:-no interface} has no 5 GHz AP" \
        "point --interface at the 5 GHz adapter"
      FAIL_CONFIG=1
    elif (( any24ap )); then
      record wifi.5ghz_ap warn "2.4 GHz AP only: CarPlay has run on this (spec/10 §12)" \
        "works, but the radio is shared with Bluetooth; 5 GHz is the headroom path"
      WIFI24_ONLY=1
    else
      record wifi.5ghz_ap fail "no AP-capable radio at all" \
        "add a 2.4 or 5 GHz AP-capable adapter, or use wired CarPlay"
      FAIL_RADIO=1
    fi
  else
    record wifi.5ghz_ap ok "$best_iface ($best_phy): 5 GHz AP on $best_chans, $best_std"
  fi

  local country
  country="$(cmd_out iw reg get | awk -F': ' '/^country/ {print $2; exit}')"
  if [[ -n "$country" ]]; then
    record wifi.reg ok "regulatory domain: $country"
  else
    record wifi.reg warn "no regulatory domain set" "set country in config.json; 5 GHz AP needs it"
  fi

  local hci=""
  shopt -s nullglob
  for hci in "$(P /sys/class/bluetooth)"/*; do :; done
  shopt -u nullglob
  if [[ -n "$hci" ]]; then
    record bt.adapter ok "$(basename "$hci")"
  else
    record bt.adapter fail "no Bluetooth adapter" "wireless CarPlay pairs over Bluetooth first"
  fi

  local missing=""
  for tool in hostapd dnsmasq iw rfkill; do
    have_cmd "$tool" || missing="$missing $tool"
  done
  if [[ -n "$missing" ]]; then
    record deps.wifi fail "missing:$missing" "apt install hostapd dnsmasq-base iw rfkill"
  else
    record deps.wifi ok "hostapd, dnsmasq, iw, rfkill"
  fi
}

# ---------------------------------------------------------------- run

run_checks() {
  check_host
  check_display
  check_video
  check_livi
  check_usb
  check_mfi
  check_audio
  check_thermal
  [[ "$MODE" == "wireless" ]] && check_wifi
  return 0
}

verdict_code() {
  if [[ "$MODE" == "wireless" ]] && (( FAIL_RADIO )); then echo 2; return; fi
  if (( FAIL_DEPS )); then echo 4; return; fi
  if (( FAIL_UNIT )); then echo 5; return; fi
  if (( FAIL_CONFIG )); then echo 3; return; fi
  echo 0
}

verdict_name() {
  case "$1" in
    0) echo ready ;;
    2) echo "wired-only" ;;
    3) echo "needs-fixes" ;;
    4) echo "needs-install" ;;
    5) echo "needs-identity-or-display" ;;
  esac
}

json_escape() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\t/ /g'; }

emit_json() {
  local code="$1" i
  printf '{"mode":"%s","verdict":"%s","exit":%d,"identity":"%s","checks":[' \
    "$MODE" "$(verdict_name "$code")" "$code" "$(json_escape "$IDENTITY")"
  for i in "${!CH_ID[@]}"; do
    [[ "$i" -gt 0 ]] && printf ','
    printf '{"id":"%s","status":"%s","detail":"%s","fix":"%s"}' \
      "$(json_escape "${CH_ID[$i]}")" "${CH_ST[$i]}" \
      "$(json_escape "${CH_DETAIL[$i]}")" "$(json_escape "${CH_FIX[$i]}")"
  done
  printf ']}\n'
}

emit_human() {
  local code="$1" i
  local label="CarPlay over USB (wired)"
  [[ "$MODE" == "wireless" ]] && label="CarPlay wireless"
  printf '%s preflight\n\n' "$label"
  printf '%-20s %-5s %s\n' "check" "state" "detail"
  for i in "${!CH_ID[@]}"; do
    printf '%-20s %-5s %s\n' "${CH_ID[$i]}" "${CH_ST[$i]}" "${CH_DETAIL[$i]}"
    [[ -n "${CH_FIX[$i]}" ]] && printf '%-20s %-5s -> %s\n' "" "" "${CH_FIX[$i]}"
  done
  printf '\nverdict: %s (exit %s)\n' "$(verdict_name "$code")" "$code"
  if (( WIFI24_ONLY )); then
    printf '2.4 GHz AP: a session has run on this board, with little headroom (spec/10 §12).\n'
  fi
  if [[ "$code" == "2" ]]; then
    printf 'wired CarPlay is unaffected: the phone on the cable needs no radio.\n'
  fi
}

# ---------------------------------------------------------------- selftest

ST_TMP=""

fixture_root() {
  local root="$1" kind="$2"
  mkdir -p "$root"/proc/device-tree \
           "$root"/etc/udev/rules.d \
           "$root"/etc/sudoers.d \
           "$root"/etc/systemd/system/multi-user.target.wants \
           "$root"/sys/class/drm \
           "$root"/sys/class/net/wlan0 \
           "$root"/sys/class/input/event0/device/capabilities \
           "$root"/sys/class/video4linux/video10 \
           "$root"/sys/class/thermal/thermal_zone0 \
           "$root"/sys/class/bluetooth \
           "$root"/sys/class/ieee80211/phy0 \
           "$root"/sys/bus/usb/devices \
           "$root"/cmd \
           "$root"/home/pi/.config/LIVI/mfi

  printf 'Raspberry Pi 4 Model B Rev 1.5\0' > "$root/proc/device-tree/model"
  printf 'MemTotal:        4000000 kB\nCmaTotal:          65536 kB\n' > "$root/proc/meminfo"
  printf 'VERSION_CODENAME=trixie\n' > "$root/etc/os-release"
  printf 'aarch64\n' > "$root/cmd/uname"
  printf 'LIVI-RULE-VERSION=6\n' > "$root/etc/udev/rules.d/99-LIVI.rules"
  printf '[Unit]\n' > "$root/etc/systemd/system/livi-kiosk.service"
  ln -sfn ../livi-kiosk.service "$root/etc/systemd/system/multi-user.target.wants/livi-kiosk.service"
  printf 'Cmnd_Alias LIVI_HELPER = /x\n' > "$root/etc/sudoers.d/99-LIVI-helper"

  mkdir -p "$root/sys/class/drm/card1-DSI-1"
  printf 'connected\n' > "$root/sys/class/drm/card1-DSI-1/status"
  printf '800x480\n' > "$root/sys/class/drm/card1-DSI-1/modes"

  printf 'Panel Touch\n' > "$root/sys/class/input/event0/device/name"
  printf '3 0260800000000003\n' > "$root/sys/class/input/event0/device/capabilities/abs"

  printf 'bcm2835-codec-decode\n' > "$root/sys/class/video4linux/video10/name"
  printf '45000\n' > "$root/sys/class/thermal/thermal_zone0/temp"
  mkdir -p "$root/sys/class/bluetooth/hci0"

  printf 'v4l2h264dec\n' > "$root/cmd/gst-inspect-1.0"
  : > "$root/cmd/hostapd"; : > "$root/cmd/dnsmasq"; : > "$root/cmd/rfkill"

  printf '52\n' > "$root/home/pi/.config/LIVI/mfi/identity.pk8"
  printf '52\n' > "$root/home/pi/.config/LIVI/mfi/certificate.p7b"
  chmod 600 "$root/home/pi/.config/LIVI/mfi/identity.pk8" "$root/home/pi/.config/LIVI/mfi/certificate.p7b"
  chmod 700 "$root/home/pi/.config/LIVI/mfi"

  ln -sfn ../../ieee80211/phy0 "$root/sys/class/net/wlan0/phy80211"
  mkdir -p "$root/cmd/iw"

  case "$kind" in
    pi4-dual)
      cat > "$root/cmd/iw/phy0.txt" <<'IW'
Wiphy phy0
	Supported interface modes:
		 * IBSS
		 * managed
		 * AP
	Band 1:
		Frequencies:
			* 2412 MHz [1] (20.0 dBm)
			* 2437 MHz [6] (20.0 dBm)
	Band 2:
		Capabilities: 0x19ef
			HT20/HT40
		VHT Capabilities (0x339b79fa):
		Frequencies:
			* 5180 MHz [36] (20.0 dBm)
			* 5200 MHz [40] (20.0 dBm)
			* 5220 MHz [44] (20.0 dBm)
IW
      ;;
    pi3-24)
      printf 'Raspberry Pi 3 Model B Rev 1.2\0' > "$root/proc/device-tree/model"
      printf 'MemTotal:         949000 kB\nCmaTotal:          32768 kB\n' > "$root/proc/meminfo"
      : > "$root/cmd/gst-inspect-1.0"        # tool present, element missing
      cat > "$root/cmd/iw/phy0.txt" <<'IW'
Wiphy phy0
	Supported interface modes:
		 * managed
		 * AP
	Band 1:
		Frequencies:
			* 2412 MHz [1] (20.0 dBm)
			* 2437 MHz [6] (20.0 dBm)
IW
      ;;
    noap5)
      cat > "$root/cmd/iw/phy0.txt" <<'IW'
Wiphy phy0
	Supported interface modes:
		 * managed
	Band 1:
		Frequencies:
			* 2412 MHz [1] (20.0 dBm)
	Band 2:
		Frequencies:
			* 5180 MHz [36] (20.0 dBm)
IW
      ;;
    no-mfi)
      rm -f "$root/home/pi/.config/LIVI/mfi/identity.pk8" "$root/home/pi/.config/LIVI/mfi/certificate.p7b"
      cat > "$root/cmd/iw/phy0.txt" <<'IW'
Wiphy phy0
	Supported interface modes:
		 * AP
	Band 1:
		Frequencies:
			* 2412 MHz [1] (20.0 dBm)
IW
      ;;
  esac
  return 0
}

st_cleanup() { [[ -n "$ST_TMP" ]] && rm -rf "$ST_TMP"; }

st_case() { # <kind> <mode> <want-exit> <want-id> <want-status>
  local kind="$1" mode="$2" want="$3" wid="$4" wst="$5" out got mark="ok"
  local root="$ST_TMP/$kind"
  fixture_root "$root" "$kind"
  out="$(LIVI_PREFLIGHT_ROOT="$root" HOME="$root/home/pi" \
    bash "$0" --mode "$mode" --identity "$root/home/pi/.config/LIVI/mfi" --json)"
  got=$?
  [[ "$got" == "$want" ]] || mark="FAIL"
  if [[ -n "$wid" ]] && ! printf '%s' "$out" | grep -q "\"id\":\"$wid\",\"status\":\"$wst\""; then
    mark="FAIL"
  fi
  [ "$mark" = ok ] || ST_FAILS=$((ST_FAILS + 1))
  printf '%-6s %-16s exit=%s want=%s %s\n' "$mark" "$kind/$mode" "$got" "$want" \
    "$([ "$mark" = ok ] || printf '%s' "$out")"
}

selftest() {
  ST_FAILS=0
  ST_TMP="$(mktemp -d)"
  trap st_cleanup EXIT

  echo "preflight selftest"
  st_case pi4-dual wired 0 mfi.files ok
  st_case pi4-dual wireless 0 wifi.5ghz_ap ok
  st_case pi3-24 wired 3 video.decoder fail
  st_case pi3-24 wireless 3 wifi.5ghz_ap warn
  st_case noap5 wireless 2 wifi.5ghz_ap fail
  st_case no-mfi wired 5 mfi.files fail

  if (( ST_FAILS == 0 )); then
    echo "6/6 fixtures match"
    return 0
  fi
  echo "$ST_FAILS assertion(s) failed"
  return 1
}

if (( SELFTEST )); then
  selftest
  exit $?
fi

run_checks
CODE="$(verdict_code)"
if (( JSON )); then emit_json "$CODE"; else emit_human "$CODE"; fi
exit "$CODE"
