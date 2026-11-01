#!/usr/bin/env python3
"""Poll an ELM327 (USB) and push the readings into LIVI's telemetry.

LIVI has no OBD backend of its own: it accepts telemetry on
``POST http://127.0.0.1:4000/telemetry`` as a JSON object and merges it into its
store, which is what its dashboards, the cluster and the phone adapters read.
This bridge is that missing half for a car whose only data source is the OBD-II
port.

    tools/livi-obd-elm327.py                       # run as a service
    tools/livi-obd-elm327.py --once                # one poll, print, exit
    tools/livi-obd-elm327.py --selftest            # fake ELM327 over a pty
    tools/livi-obd-elm327.py --device /dev/ttyUSB0 --baud 38400

Supported PIDs (whatever the car answers; the rest are skipped):

    01 0C rpm            01 0D speed            01 05 coolant
    01 11 throttle       01 0B intake MAP       01 0F intake air
    01 2F fuel level     01 33 baro             01 42 battery
    01 46 ambient        01 01 MIL + DTC count  03    stored DTCs

Fields map onto LIVI's telemetry schema (``rpm``, ``speedKph``, ``coolantC``,
``throttlePct``, ``mapKpa``, ``iatC``, ``fuelPct``, ``baroKpa``, ``batteryV``,
``ambientC``). ``gear``/``reverse`` are not inferred: a 2009 Jimny does not
report them over OBD, and guessing from speed alone would be wrong.

Exit codes: 0 ok, 1 usage/IO error, 2 the adapter never answered, 3 selftest
failure.
"""

from __future__ import annotations

import argparse
import json
import os
import select
import sys
import termios
import threading
import time
import tty
import urllib.error
import urllib.request

DEFAULT_DEVICE = "/dev/serial/by-id/usb-1a86_USB2.0-Serial-if00-port0"
DEFAULT_ENDPOINT = "http://127.0.0.1:4000/telemetry"
DEFAULT_BAUD = 38400

BAUDS = {
    9600: termios.B9600,
    19200: termios.B19200,
    38400: termios.B38400,
    57600: termios.B57600,
    115200: termios.B115200,
}


# --------------------------------------------------------------------------- link

class Elm:
    """One ELM327 on a serial port, line oriented, prompt terminated."""

    def __init__(self, device: str, baud: int = DEFAULT_BAUD, timeout: float = 2.0):
        self.device = device
        self.baud = baud
        self.timeout = timeout
        self.fd = -1

    def open(self) -> None:
        fd = os.open(self.device, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        attrs = termios.tcgetattr(fd)
        attrs[0] = 0                                        # iflag: raw
        attrs[1] = 0                                        # oflag: raw
        attrs[2] &= ~(termios.PARENB | termios.CSTOPB | termios.CSIZE | termios.CRTSCTS)
        attrs[2] |= termios.CS8 | termios.CREAD | termios.CLOCAL
        attrs[3] = 0                                        # lflag: no echo/canon
        attrs[4] = attrs[5] = BAUDS[self.baud]
        termios.tcsetattr(fd, termios.TCSANOW, attrs)
        termios.tcflush(fd, termios.TCIOFLUSH)
        self.fd = fd

    def close(self) -> None:
        if self.fd >= 0:
            try:
                os.close(self.fd)
            finally:
                self.fd = -1

    def __enter__(self) -> "Elm":
        self.open()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _read_until_prompt(self, deadline: float) -> bytes:
        out = b""
        while time.monotonic() < deadline:
            r, _, _ = select.select([self.fd], [], [], 0.1)
            if not r:
                continue
            try:
                chunk = os.read(self.fd, 256)
            except BlockingIOError:
                continue
            if not chunk:
                continue
            out += chunk
            if b">" in out:
                break
        return out

    def command(self, text: str, timeout: float | None = None, match=None) -> str:
        """Send one command, return the cleaned response lines.

        The flush matters: a clone ELM327 answers late enough that an unread reply
        from the previous request would otherwise be taken for this one's, which
        silently shifts every value by one PID.
        """
        deadline = time.monotonic() + (timeout or self.timeout)
        termios.tcflush(self.fd, termios.TCIFLUSH)
        os.write(self.fd, (text + "\r").encode())
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return ""
            raw = self._read_until_prompt(time.monotonic() + remaining)
            cleaned = raw.replace(b"\r", b"\n").decode("ascii", "replace")
            lines = []
            for line in cleaned.split("\n"):
                line = line.strip().replace(" ", "").upper()
                if not line or line == ">":
                    continue
                if line in {"SEARCHING...", "SEARCHING", "BUSINIT...", "BUSINIT:...OK"}:
                    continue
                if line == text.replace(" ", "").upper():      # echo
                    continue
                lines.append(line)
            terminal = {"NODATA", "NOCONNECTION", "NOSUPPORTED", "?", "STOPPED", "CANERROR", "BUSERROR"}
            if match is None or any(match(line) for line in lines) or any(l in terminal for l in lines):
                return "\n".join(lines)
            # a late reply from an earlier request: drop it and wait for ours

    def init(self) -> str:
        """Reset and quieten the adapter; returns the reported version string."""
        version = ""
        for attempt in range(3):
            os.write(self.fd, b"\r")
            time.sleep(0.2)
            termios.tcflush(self.fd, termios.TCIOFLUSH)
            version = self.command("ATZ") or version
            if "ELM" in version:
                break
            time.sleep(0.4)
        for cmd in ("ATE0", "ATL0", "ATS0", "ATH0", "ATSP0"):
            self.command(cmd)
        # The first OBD request on a KWP car pays for the protocol search, which
        # takes several seconds; absorb it here so the poll loop starts aligned.
        self.command("0100", timeout=20.0)
        termios.tcflush(self.fd, termios.TCIFLUSH)
        return version

    def query(self, pid: str) -> list[int]:
        """Send a mode-01 PID and return the data bytes, or [] when unsupported."""
        for _attempt in range(2):                 # one retry covers a late reply
            out = self._query_once(pid)
            if out:
                return out
        return []

    def _query_once(self, pid: str) -> list[int]:
        reply = self.command(
            "01" + pid,
            match=lambda line: line.startswith("41" + pid) or line.startswith("7F01"),
        )
        out: list[int] = []
        for line in reply.split("\n"):
            if not line or line in {"NODATA", "UNABLETOCONNECT", "CANERROR", "?"}:
                continue
            if ":" in line:                                  # multi-frame with headers
                line = line.split(":", 1)[1]
            if not all(c in "0123456789ABCDEF" for c in line) or len(line) < 6:
                continue
            data = bytes.fromhex(line)
            if data[0] != 0x41 or data[1] != int(pid, 16):
                continue
            out.extend(data[2:])
        return out


# --------------------------------------------------------------------------- decode

def _u16(a: int, b: int) -> int:
    return (a << 8) | b


def decode_rpm(v: list[int]) -> float | None:
    return round(_u16(v[0], v[1]) / 4.0, 0) if len(v) >= 2 else None


def decode_speed(v: list[int]) -> float | None:
    return float(v[0]) if v else None


def decode_coolant(v: list[int]) -> float | None:
    return float(v[0] - 40) if v else None


def decode_pct(v: list[int]) -> float | None:
    return round(v[0] * 100.0 / 255.0, 1) if v else None


def decode_maf(v: list[int]) -> float | None:
    """PID 10: grams of air per second."""
    return round(_u16(v[0], v[1]) / 100.0, 2) if len(v) >= 2 else None


def decode_baro(v: list[int]) -> float | None:
    return float(v[0]) if v else None


def decode_battery(v: list[int]) -> float | None:
    return round(_u16(v[0], v[1]) / 1000.0, 2) if len(v) >= 2 else None


def decode_dtc_count(v: list[int]) -> int | None:
    return v[0] & 0x7F if v else None


def parse_supported(base: int, payload) -> set[int]:
    """Mode 01 PID 00/20/40 bitmap (four bytes) -> the PIDs the car answers."""
    if not isinstance(payload, (list, tuple)) or len(payload) < 4:
        return set()
    supported: set[int] = set()
    for byte_index in range(4):
        value = int(payload[byte_index]) & 0xFF
        for bit in range(8):
            if value & (1 << (7 - bit)):
                supported.add(base + byte_index * 8 + bit + 1)
    return supported


def supported_pids(elm: Elm) -> set[int] | None:
    """Ask the ECU which PIDs exist, so the loop never waits on absent ones."""
    found: set[int] = set()
    for base, request in ((0x00, "00"), (0x20, "20"), (0x40, "40"), (0x60, "60")):
        reply = elm.query(request)
        if not reply:
            if base == 0x00:
                return None                      # adapter cannot enumerate
            break
        found |= parse_supported(base, reply)
        if (base + 0x20) not in found:           # no further range advertised
            break
    return found or None


AFR_STOICH = 14.7
PETROL_G_PER_L = 730.0


class Trip:
    """Distance, fuel burned and averages, plus what the dashboard needs right now."""

    def __init__(self, tank_l: float = 40.0, path: str | None = None):
        self.tank_l = tank_l
        self.path = path
        self.km = 0.0
        self.litres = 0.0
        self.seconds = 0.0
        self._save_at = 0.0
        self.load()

    def load(self) -> None:
        if not self.path:
            return
        try:
            with open(self.path) as f:
                d = json.load(f)
            self.km = float(d.get("km", 0.0))
            self.litres = float(d.get("litres", 0.0))
            self.seconds = float(d.get("seconds", 0.0))
        except (OSError, ValueError, TypeError):
            pass

    def save(self, now: float, force: bool = False) -> None:
        if not self.path or (not force and now - self._save_at < 10.0):
            return
        self._save_at = now
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            with open(self.path, "w") as f:
                json.dump({"km": round(self.km, 3), "litres": round(self.litres, 4),
                           "seconds": round(self.seconds, 1)}, f)
        except OSError:
            pass

    def reset(self) -> None:
        self.km = self.litres = self.seconds = 0.0

    def update(self, dt: float, speed_kph: float | None, maf_gps: float | None) -> dict:
        """Advance the trip and return the derived telemetry fields."""
        self.seconds += dt
        speed = speed_kph or 0.0
        self.km += speed * dt / 3600.0
        out: dict[str, float] = {}
        if maf_gps is None:
            return out
        gps = maf_gps / AFR_STOICH
        lph = gps * 3600.0 / PETROL_G_PER_L
        self.litres += lph * dt / 3600.0
        out["fuelRateLph"] = round(lph, 2)
        out["afr"] = AFR_STOICH
        if speed >= 3.0:
            out["consumptionLPer100Km"] = round(lph / speed * 100.0, 1)
        if self.km >= 0.2:
            avg = self.litres / self.km * 100.0
            if 0.0 < avg < 99.0:
                out["consumptionAvgLPer100Km"] = round(avg, 1)
                left = max(0.0, self.tank_l - self.litres)
                out["rangeKm"] = round(left / avg * 100.0, 0)
        if self.km > 0:
            out["odometerTripKm"] = round(self.km, 2)
        # the tank level this car cannot report: counted down from the last reset
        left = max(0.0, self.tank_l - self.litres)
        out["fuelPct"] = round(left / self.tank_l * 100.0, 1)
        return out


def read_vehicle(elm: Elm, supported: set[int] | None = None, want_slow: bool = True) -> dict:
    """One pass over the fast PIDs; returns telemetry fields that were answered."""
    readings: dict[str, float] = {}
    for pid, field, fn, slow in (
        ("0C", "rpm", decode_rpm, False),
        ("0D", "speedKph", decode_speed, False),
        ("11", "throttlePct", decode_pct, True),
        ("0B", "mapKpa", decode_baro, True),
        ("10", "mafGps", decode_maf, False),
        ("05", "coolantC", decode_coolant, True),
        ("0F", "iatC", decode_coolant, True),
        ("2F", "fuelPct", decode_pct, True),
        ("33", "baroKpa", decode_baro, True),
        ("46", "ambientC", decode_coolant, True),
    ):
        if slow and not want_slow:
            continue
        if supported is not None and int(pid, 16) not in supported:
            continue
        value = fn(elm.query(pid))
        if value is not None:
            readings[field] = value
    if want_slow and (supported is None or 0x42 in supported):
        volts = decode_battery(elm.query("42"))
        if volts is not None:
            readings["batteryV"] = volts
    return readings


def parse_dtcs(blob: bytes) -> str:
    """Mode 03 payload -> codes. CAN sends 43 <pairs>; KWP prefixes a length byte."""
    if not blob:
        return "no stored DTCs (adapter answered NO DATA)"
    at = blob.find(b"\x43")
    if at < 0:
        return f"DTC response not understood: {blob.hex(' ').upper()}"
    data = blob[at + 1:]
    codes = []
    for i in range(0, len(data) - 1, 2):
        first, second = data[i], data[i + 1]
        if first == 0 and second == 0:
            continue
        letter = "PCBU"[first >> 6]
        number = ((first & 0x3F) << 8) | second
        if number == 0:
            continue
        codes.append(f"{letter}{number:04X}")
    return ", ".join(codes) if codes else "no stored DTCs"


def read_dtcs(elm: Elm) -> str:
    reply = elm.command("03", match=lambda line: line.startswith("43") or line.startswith("7F"))
    blob = b""
    for line in reply.split("\n"):
        line = line.split(":", 1)[-1]
        if not line or line in {"NODATA", "?"} or not all(c in "0123456789ABCDEF" for c in line):
            continue
        if len(line) % 2:
            line += "0"
        blob += bytes.fromhex(line)
    return parse_dtcs(blob)


LAST_PUSH_WARNING = 0.0


def push(endpoint: str, fields: dict) -> bool:
    body = json.dumps(fields).encode()
    req = urllib.request.Request(endpoint, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            return 200 <= resp.status < 300
    except (urllib.error.URLError, OSError):
        return False


# --------------------------------------------------------------------------- selftest

def selftest() -> int:
    """Fake ELM327 behind a pty, fake endpoint behind a socket; assert the numbers."""
    import http.server
    import pty
    import threading

    master, slave = pty.openpty()
    tty.setraw(slave)
    slave_name = os.ttyname(slave)

    replies = {
        "ATZ": b"ELM327 v1.5\r\r>",
        "010C": b"41 0C 1A F8\r\r>",     # 1726 rpm
        "010D": b"41 0D 37\r\r>",        # 55 km/h
        "0105": b"41 05 7B\r\r>",        # 83 C
        "0111": b"41 11 80\r\r>",        # 50.2 %
        "010B": b"41 0B 64\r\r>",        # 100 kPa
        "010F": b"41 0F 50\r\r>",        # 40 C
        "012F": b"41 2F 80\r\r>",        # 50.2 %
        "0133": b"41 33 65\r\r>",        # 101 kPa
        "0146": b"41 46 55\r\r>",        # 45 C
        "0142": b"41 42 30 39\r\r>",     # 12.345 V
        "03": b"43 01 33 00 00 00 00\r\r>",
    }

    def elm_thread() -> None:
        buf = b""
        while True:
            r, _, _ = select.select([master], [], [], 0.5)
            if not r:
                continue
            try:
                buf += os.read(master, 64)
            except OSError:
                return
            while b"\r" in buf:
                line, buf = buf.split(b"\r", 1)
                cmd = line.decode("ascii", "ignore").strip().upper().replace(" ", "")
                os.write(master, replies.get(cmd, b"NO DATA\r\r>"))

    got: list[dict] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):                                  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            got.append(json.loads(self.rfile.read(length)))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *a):                          # silence
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    threading.Thread(target=elm_thread, daemon=True).start()
    endpoint = f"http://127.0.0.1:{server.server_port}/telemetry"

    failures = 0

    def check(name: str, ok: bool, detail: str = "") -> None:
        nonlocal failures
        if not ok:
            failures += 1
        print(f"{'ok  ' if ok else 'FAIL'} {name}{(' ' + detail) if detail else ''}")

    with Elm(slave_name, DEFAULT_BAUD) as elm:
        version = elm.init()
        check("adapter answers ATZ", "ELM327" in version, version)
        fields = read_vehicle(elm)
        expect = {
            "rpm": 1726.0, "speedKph": 55.0, "coolantC": 83.0, "throttlePct": 50.2,
            "mapKpa": 100.0, "iatC": 40.0, "fuelPct": 50.2, "baroKpa": 101.0,
            "ambientC": 45.0, "batteryV": 12.35,   # two decimals, as decoded
        }
        for key, want in expect.items():
            check(f"decode {key}", fields.get(key) == want, f"got {fields.get(key)!r}")
        check("push to endpoint", push(endpoint, fields) and got and got[-1]["rpm"] == 1726.0)
        dtcs = read_dtcs(elm)
        check("decode DTCs", dtcs == "P0133", dtcs)
        check("CAN form", parse_dtcs(bytes.fromhex("430133000000")) == "P0133")
        check("KWP length-prefixed form", parse_dtcs(bytes.fromhex("0343013300000000")) == "P0133")
        check("junk is not invented", parse_dtcs(bytes.fromhex("FFFF00")) .startswith("DTC response not understood"))

    server.shutdown()
    print(f"{'all checks passed' if failures == 0 else str(failures) + ' check(s) failed'}")
    return 0 if failures == 0 else 3


# --------------------------------------------------------------------------- main

def run(args) -> int:
    last_slow = 0.0
    cached: dict[str, float] = {}
    every = max(1, args.slow_every)
    pending: list[dict] = []
    stop = False
    trip = Trip(args.tank, args.trip_state)
    if args.trip_reset:
        trip.reset()
        trip.save(time.monotonic(), force=True)
        print("[obd] trip reset", flush=True)
    last = time.monotonic()

    warned = 0.0

    def pusher():
        nonlocal warned
        while not stop:
            if not pending:
                time.sleep(0.02)
                continue
            fields = pending[-1]
            pending.clear()
            if not push(args.endpoint, fields) and args.verbose:
                now = time.monotonic()
                if now - warned > 30:                 # LIVI not listening yet
                    print("[obd] telemetry endpoint is not up yet", flush=True)
                    warned = now

    threading.Thread(target=pusher, daemon=True).start()
    while True:
        try:
            with Elm(args.device, args.baud) as elm:
                version = elm.init()
                if "ELM" not in version:
                    print(f"[obd] {args.device} did not answer as an ELM327 ({version!r})", flush=True)
                    return 2
                print(f"[obd] {args.device} @ {args.baud}: {version.splitlines()[0]}", flush=True)
                print(f"[obd] {read_dtcs(elm)}", flush=True)
                supported = supported_pids(elm)
                if supported is not None:
                    print(f"[obd] {len(supported)} PIDs advertised by the car", flush=True)
                passes = 0
                while True:
                    slow_turn = (passes % every == 0)
                    passes += 1
                    fields = read_vehicle(elm, supported, want_slow=slow_turn)
                    if slow_turn:
                        cached.update(fields)
                        fields = dict(cached)
                    else:
                        fields = {**cached, **fields}
                    now = time.monotonic()
                    maf = fields.pop("mafGps", None)
                    fields.update(trip.update(max(0.0, now - last), fields.get("speedKph"), maf))
                    last = now
                    trip.save(now)
                    if args.once:
                        print(json.dumps(fields, sort_keys=True))
                        return 0 if fields else 2
                    if fields:
                        pending.append(dict(fields))
                        if args.verbose:
                            print(f"[obd] {fields}", flush=True)
                    time.sleep(args.interval)
                    _ = last_slow
        except (OSError, termios.error) as exc:
            if args.once:
                print(f"[obd] {args.device}: {exc}", flush=True)
                return 2
            print(f"[obd] {exc}; retrying in 3 s", flush=True)
            time.sleep(3)


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="ELM327 -> LIVI telemetry bridge")
    p.add_argument("--device", default=os.environ.get("OBD_DEVICE", DEFAULT_DEVICE))
    p.add_argument("--baud", type=int, default=int(os.environ.get("OBD_BAUD", DEFAULT_BAUD)))
    p.add_argument("--endpoint", default=os.environ.get("LIVI_TELEMETRY", DEFAULT_ENDPOINT))
    p.add_argument("--interval", type=float, default=0.0,
                   help="extra seconds between polls (default 0: the adapter paces the loop)")
    p.add_argument("--tank", type=float, default=40.0, help="tank size in litres (Jimny: 40)")
    p.add_argument("--trip-state", default=os.path.expanduser("~/.local/state/livi-obd/trip.json"),
                   help="where the trip computer remembers its totals")
    p.add_argument("--trip-reset", action="store_true", help="start a fresh trip (do this at a fill-up)")
    p.add_argument("--slow-every", type=int, default=4,
                   help="poll slow PIDs (coolant, intake, fuel, volts) every N passes (default 4)")
    p.add_argument("--once", action="store_true", help="one poll, print JSON, exit")
    p.add_argument("--selftest", action="store_true")
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args(argv)

    if args.baud not in BAUDS:
        print(f"--baud must be one of {sorted(BAUDS)}", file=sys.stderr)
        return 1
    if args.selftest:
        return selftest()
    return run(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
