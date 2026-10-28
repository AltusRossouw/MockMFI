#!/usr/bin/env bash
# Wire libmfi into LIVI and test the integration.
#
#   1. `mfid net` speaks LIVI's mfid TCP coprocessor protocol; the bundled
#      Python client mirrors native/crates/iap2-mfi/src/ncm.rs.
#   2. With a LIVI checkout, LIVI's own FileCoprocessor and NcmCoprocessor are
#      built into a throw-away probe crate and run against that service.
#   3. On macOS, with --stage-files, the identity is copied into LIVI's import
#      folder and livi-helperd is started headless to confirm it picks it up.
#
# Usage: tools/livi-integration.sh [--stage-files]
#   LIVI_DIR=/path/to/LIVI        (default ~/tools/LIVI)
#   LIVI_APP=/path/to/LIVI.app    (default ~/Applications/LIVI.app)
#   IDENTITY=/path/to/identity    (default mfi-linux/build/test-identity)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIVI_DIR="${LIVI_DIR:-$HOME/tools/LIVI}"
LIVI_APP="${LIVI_APP:-$HOME/Applications/LIVI.app}"
IDENTITY="${IDENTITY:-$ROOT/mfi-linux/build/test-identity}"
PORT="${PORT:-$(python3 - <<'EOF'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
EOF
)}"
STAGE=0
[[ "${1:-}" == "--stage-files" ]] && STAGE=1

fail=0
note() { printf '\n== %s ==\n' "$1"; }
ok()   { printf 'ok   %s\n' "$1"; }
bad()  { printf 'FAIL %s\n' "$1"; fail=1; }

cleanup() {
  [[ -n "${SERVER_PID:-}" ]] && kill "$SERVER_PID" 2>/dev/null || true
  [[ -n "${HELPER_PID:-}" ]] && kill "$HELPER_PID" 2>/dev/null || true
}
trap cleanup EXIT

note "build libmfi"
make -C "$ROOT/mfi-linux" >/dev/null
make -C "$ROOT/mfi-linux" "$(realpath --relative-to="$ROOT/mfi-linux" "$IDENTITY" 2>/dev/null || echo build/test-identity)" >/dev/null 2>&1 || true
MFID="$ROOT/mfi-linux/build/mfid"
[[ -x "$MFID" ]] && ok "mfid built" || { bad "mfid missing"; exit 1; }
[[ -f "$IDENTITY/identity.pk8" ]] || { bad "identity missing at $IDENTITY"; exit 1; }

start_server() {
  "$MFID" --identity "$IDENTITY" net --bind 127.0.0.1 --port "$PORT" -v >/tmp/mfid-net.log 2>&1 &
  SERVER_PID=$!
  sleep 0.2
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "mfid net exited:"
    cat /tmp/mfid-net.log
    return 1
  fi
  for _ in $(seq 1 50); do
    if python3 - "$PORT" <<'EOF' 2>/dev/null
import socket, sys
socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=0.2).close()
EOF
    then return 0; fi
    sleep 0.1
  done
  return 1
}

stop_server() {
  [[ -n "${SERVER_PID:-}" ]] && kill "$SERVER_PID" 2>/dev/null || true
  wait "$SERVER_PID" 2>/dev/null || true
  SERVER_PID=""
}

note "mfid protocol (client mirroring LIVI ncm.rs)"
start_server && ok "mfid net listening on $PORT" || bad "mfid net did not start"
python3 "$ROOT/tools/livi-mfid-client.py" 127.0.0.1 "$PORT" \
  --verify-bin "$MFID" --identity "$IDENTITY" || fail=1
stop_server

if [[ -d "$LIVI_DIR/native" ]] && command -v cargo >/dev/null 2>&1; then
  note "LIVI's own coprocessor code against mfid net"
  mkdir -p "$LIVI_DIR/native/crates/mfi-probe"
  cp "$ROOT/tools/livi-probe/Cargo.toml" "$LIVI_DIR/native/crates/mfi-probe/Cargo.toml"
  cp "$ROOT/tools/livi-probe/src/main.rs" "$LIVI_DIR/native/crates/mfi-probe/src/main.rs"

  if (cd "$LIVI_DIR/native" && RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-stable}" cargo build -q -p mfi-probe); then
    ok "LIVI iap2-mfi probe built"
    start_server || bad "mfid net did not start"
    probe_out="$(cd "$LIVI_DIR/native" && RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-stable}" \
      cargo run -q -p mfi-probe --bin mfi-probe -- "$IDENTITY" "127.0.0.1:$PORT")"
    stop_server
    echo "$probe_out"
    [[ "$(sed -n 's/^cert_equal=//p' <<<"$probe_out")" == "true" ]] \
      && ok "LIVI and libmfi serve the same certificate" \
      || bad "certificate mismatch"
    digest="$(sed -n 's/^digest=//p' <<<"$probe_out")"
    for key in file_sig ncm_sig; do
      sig="$(sed -n "s/^$key=//p" <<<"$probe_out")"
      if [[ -n "$sig" ]] && "$MFID" --identity "$IDENTITY" verify "$digest" "$sig" >/dev/null; then
        ok "LIVI $key verifies with libmfi"
      else
        bad "LIVI $key did not verify"
      fi
    done
  else
    bad "could not build LIVI's iap2-mfi probe (needs a Rust toolchain)"
  fi
else
  note "LIVI checkout not found — skipping the iap2-mfi probe"
  echo "set LIVI_DIR to a LIVI clone to run it (git clone --depth 1 https://github.com/f-io/LIVI.git)"
fi

if [[ "$STAGE" == "1" ]]; then
  note "stage the identity into LIVI and start livi-helperd headless"
  HELPERD="$LIVI_APP/Contents/Resources/driver/livi-helperd"
  MFI_DIR="$HOME/Library/Application Support/LIVI/mfi"
  if [[ -x "$HELPERD" ]]; then
    mkdir -p "$MFI_DIR"
    cp "$IDENTITY/identity.pk8" "$IDENTITY/certificate.p7b" "$MFI_DIR/"
    ok "identity copied to $MFI_DIR"
    DEBUG=1 LIVI_CP_DEBUG=1 LIVI_CP_AIRPLAY_PORT=7011 LIVI_CP_NAME=LIVI-TEST \
      "$HELPERD" >/tmp/livi-helperd.log 2>&1 &
    HELPER_PID=$!
    for _ in $(seq 1 80); do
      grep -q "MFi from the imported files" /tmp/livi-helperd.log && break
      sleep 0.1
    done
    kill "$HELPER_PID" 2>/dev/null || true
    HELPER_PID=""
    if grep -q "MFi from the imported files" /tmp/livi-helperd.log; then
      ok "livi-helperd loaded the identity"
    else
      bad "livi-helperd did not report the imported files"
    fi
    grep -E "MFi|CarPlay" /tmp/livi-helperd.log | tail -5
  else
    echo "LIVI.app not found at $LIVI_APP — skipping helperd"
  fi
fi

printf '\n%s\n' "$([[ $fail == 0 ]] && echo 'PASS' || echo 'FAILED')"
exit "$fail"
