#!/usr/bin/env python3
"""Dim the panel when the car's lights are on.

The car cannot tell us this over OBD: the Jimny advertises 19 mode-01 PIDs and
none of them is a lighting state, and a 2009 K-line car has no broadcast frames
to sniff. So the input is a wire: the illumination circuit through an optocoupler
into a GPIO (see tools/livi-lights.md), or a plain ambient-light module.

Whatever the source, the output is the same two things:
  * /sys/class/backlight/<device>/brightness — the panel backlight
  * POST {"nightMode": true|false} to LIVI's telemetry, which forwards it to
    Android Auto as the night-mode sensor

    tools/livi-lights.py --gpio 17                      # real use
    tools/livi-lights.py --gpio 17 --fake /tmp/light    # testing, no wiring
    tools/livi-lights.py --selftest                     # offline checks
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.request

TELEMETRY = "http://127.0.0.1:4000/telemetry"
BACKLIGHT = "/sys/class/backlight/10-0045/brightness"
BACKLIGHT_MAX = "/sys/class/backlight/10-0045/max_brightness"
SYSFS_GPIO = "/sys/class/gpio/gpio{}/value"


def backlight_max() -> int:
    try:
        with open(BACKLIGHT_MAX) as f:
            return max(1, int(f.read().strip()))
    except OSError:
        return 255


def set_brightness(percent: float) -> int:
    value = round(backlight_max() * max(0.0, min(100.0, percent)) / 100.0)
    with open(BACKLIGHT, "w") as f:
        f.write(str(value))
    return value


def read_gpio(pin: int, fake: str | None) -> bool:
    path = fake or SYSFS_GPIO.format(pin)
    with open(path) as f:
        return f.read().strip() == "1"


def post_night(night: bool, endpoint: str) -> bool:
    body = json.dumps({"nightMode": night}).encode()
    req = urllib.request.Request(
        endpoint, data=body, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=1.0):
            return True
    except (urllib.error.URLError, OSError):
        return False


class Debounce:
    """Lights flicker on a dirty tap; require N samples before believing a change."""

    def __init__(self, samples: int = 3):
        self.samples = max(1, samples)
        self.seen = 0
        self.state: bool | None = None

    def feed(self, value: bool) -> bool | None:
        """Returns the new state when it changes, else None."""
        if self.state is None:
            self.state = value
            self.seen = self.samples
            return value
        if value == self.state:
            self.seen = self.samples
            return None
        self.seen -= 1
        if self.seen <= 0:
            self.state = value
            self.seen = self.samples
            return value
        return None


def run(args) -> int:
    night = Debounce(args.samples)
    applied: bool | None = None
    print(f"[lights] gpio {args.gpio} → day {args.day} % / night {args.night} %", flush=True)
    while True:
        try:
            state = read_gpio(args.gpio, args.fake)
        except OSError as exc:
            print(f"[lights] cannot read the input ({exc}); retrying", flush=True)
            time.sleep(2)
            continue
        change = night.feed(state)
        if change is not None and change != applied:
            applied = change
            target = args.night if change else args.day
            try:
                written = set_brightness(target)
                print(f"[lights] {'lights on' if change else 'lights off'} → {target} % ({written})", flush=True)
            except OSError as exc:
                print(f"[lights] backlight write failed: {exc}", flush=True)
            post_night(change, args.telemetry)
        time.sleep(args.poll)


def selftest() -> int:
    failures = 0

    def check(name: str, ok: bool) -> None:
        nonlocal failures
        print(f"{'ok  ' if ok else 'FAIL'} {name}")
        failures += 0 if ok else 1

    d = Debounce(3)
    check("first sample latches", d.feed(False) is False)
    check("stable state is silent", d.feed(False) is None)
    check("one outlier is ignored", d.feed(True) is None)
    check("second sample still ignored", d.feed(True) is None)
    check("third sample flips", d.feed(True) is True)
    check("flip is latched", d.feed(True) is None)
    check("back down after 3", [d.feed(False) for _ in range(3)][-1] is False)

    # brightness maths
    check("0 % → 0", round(255 * 0 / 100) == 0)
    check("25 % → 64", round(255 * 25 / 100) == 64)
    check("100 % → 255", round(255 * 100 / 100) == 255)
    return 0 if failures == 0 else 3


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="dim the panel when the car's lights are on")
    p.add_argument("--gpio", type=int, default=17, help="BCM GPIO number (default 17)")
    p.add_argument("--fake", help="read the input from this file instead of a GPIO")
    p.add_argument("--day", type=float, default=100.0, help="brightness %% with lights off")
    p.add_argument("--night", type=float, default=25.0, help="brightness %% with lights on")
    p.add_argument("--samples", type=int, default=3, help="samples needed to accept a change")
    p.add_argument("--poll", type=float, default=0.3, help="seconds between samples")
    p.add_argument("--telemetry", default=TELEMETRY)
    p.add_argument("--selftest", action="store_true")
    args = p.parse_args(argv)
    if args.selftest:
        return selftest()
    return run(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
