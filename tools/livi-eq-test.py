#!/usr/bin/env python3
"""Signal generator and 1/3-octave analyser for tuning LIVI's EQ in a car.

No dependencies beyond python3 and PipeWire/PulseAudio tools. It exists because
the head unit has no microphone: the usual rig is this script playing pink noise
on the Pi while a phone RTA sits at the driver's seat. If a USB measurement mic
is attached later, --measure does the analysis on the Pi itself.

    tools/livi-eq-test.py --make /tmp                  # pink.wav + sweep.wav
    tools/livi-eq-test.py --play /tmp/pink.wav         # loop for the RTA
    tools/livi-eq-test.py --sweep /tmp/sweep.wav       # 20 Hz .. 20 kHz chirp
    tools/livi-eq-test.py --measure 8                  # needs a capture device
    tools/livi-eq-test.py --analyze /tmp/rec.wav       # offline band levels

Band levels are printed relative to the 1 kHz band, which is what a phone RTA
shows; the advice line at the end is a starting point, not a target curve.
"""

from __future__ import annotations

import argparse
import math
import os
import random
import shutil
import subprocess
import sys
import wave

RATE = 48000
CENTRES = [25, 31.5, 40, 50, 63, 80, 100, 125, 160, 200, 250, 315, 400, 500, 630,
           800, 1000, 1250, 1600, 2000, 2500, 3150, 4000, 5000, 6300, 8000,
           10000, 12500, 16000]


def write_wav(path: str, samples: list[float]) -> None:
    with wave.open(path, "wb") as w:
        w.setnchannels(2)
        w.setsampwidth(2)
        w.setframerate(RATE)
        frames = bytearray()
        for s in samples:
            v = max(-1.0, min(1.0, s))
            i = int(v * 32767)
            frames += i.to_bytes(2, "little", signed=True) * 2
        w.writeframes(bytes(frames))
    print(f"wrote {path} ({len(samples) / RATE:.1f} s)")


def pink(seconds: float, amplitude: float = 0.25) -> list[float]:
    """Voss-McCartney pink noise: flat per octave, the right stimulus for an RTA."""
    seconds = seconds
    rows = 16
    rand = random.Random(1)
    counters = [rand.uniform(-1.0, 1.0) for _ in range(rows)]
    total = sum(counters)
    out: list[float] = []
    for i in range(int(seconds * RATE)):
        for row in range(rows):
            if i % (1 << (row + 1)) == 0:
                total -= counters[row]
                counters[row] = rand.uniform(-1.0, 1.0)
                total += counters[row]
        out.append(total / rows * 3.0 * amplitude)
    peak = max(1e-9, max(abs(x) for x in out))
    scale = min(1.0, amplitude * 4 / peak)
    return [x * scale for x in out]


def sweep(seconds: float, f0: float = 20.0, f1: float = 20000.0, amplitude: float = 0.25) -> list[float]:
    """Exponential chirp, phase-integrated so the instantaneous frequency is exact."""
    n = int(seconds * RATE)
    k = math.log(f1 / f0) / seconds
    out: list[float] = []
    phase = 0.0
    for i in range(n):
        t = i / RATE
        f = f0 * math.exp(k * t)
        phase += 2 * math.pi * f / RATE
        fade = min(1.0, t / 0.05) * min(1.0, (seconds - t) / 0.15)
        out.append(math.sin(phase) * amplitude * fade)
    return out


def read_mono(path: str) -> list[float]:
    with wave.open(path, "rb") as w:
        if w.getsampwidth() != 2:
            raise SystemExit("expected 16-bit PCM")
        channels = w.getnchannels()
        rate = w.getframerate()
        raw = w.readframes(w.getnframes())
    data = memoryview(raw).cast("h")
    mono = [(data[i] / 32768.0) for i in range(0, len(data), channels)]
    if rate != RATE:
        print(f"note: {path} is {rate} Hz, bands assume {RATE} Hz", file=sys.stderr)
    return mono


def _fft(a: list[complex]) -> None:
    """In-place iterative radix-2 FFT."""
    n = len(a)
    j = 0
    for i in range(1, n):
        bit = n >> 1
        while j & bit:
            j ^= bit
            bit >>= 1
        j |= bit
        if i < j:
            a[i], a[j] = a[j], a[i]
    length = 2
    while length <= n:
        ang = -2 * math.pi / length
        wl = [complex(math.cos(ang * i), math.sin(ang * i)) for i in range(length // 2)]
        for i in range(0, n, length):
            for k in range(length // 2):
                u = a[i + k]
                v = a[i + k + length // 2] * wl[k]
                a[i + k] = u + v
                a[i + k + length // 2] = u - v
        length <<= 1


def _segment_power(seg: list[float], rate: int) -> list[float]:
    """One Hann-windowed segment, returns power per bin up to Nyquist."""
    n = len(seg)
    windowed = [
        seg[i] * (0.5 - 0.5 * math.cos(2 * math.pi * i / (n - 1))) for i in range(n)
    ]
    buf = [complex(v, 0.0) for v in windowed] + [0j] * 0
    _fft(buf)
    return [(c.real * c.real + c.imag * c.imag) for c in buf[: n // 2]]


def analyse(samples: list[float], seconds: float = 2.7) -> list[tuple[float, float]]:
    """1/3-octave band power relative to the 1 kHz band.

    Pink noise carries equal power per octave, so band power *is* the response — no
    slope correction. Averaging several overlapping FFT segments is what makes this
    repeatable: a single bin of noise varies by about 6 dB, a band average by 1-2 dB.
    """
    n = 1 << 16
    rate = RATE
    stride = n // 2
    if len(samples) < n:
        samples = samples + [0.0] * (n - len(samples))
    segments = 0
    acc: list[float] = [0.0] * (n // 2)
    pos = 0
    while pos + n <= len(samples) and segments < 8:
        power = _segment_power(samples[pos:pos + n], rate)
        for i, v in enumerate(power):
            acc[i] += v
        segments += 1
        pos += stride
    if segments == 0:
        return []
    band_db: list[tuple[float, float]] = []
    for centre in CENTRES:
        lo = centre * 2 ** (-1 / 6)
        hi = centre * 2 ** (1 / 6)
        lo_bin = max(1, int(lo * n / rate))
        hi_bin = max(lo_bin + 1, int(hi * n / rate))
        total = sum(acc[lo_bin:hi_bin]) / segments
        band_db.append((float(centre), 10 * math.log10(max(total, 1e-30))))
    ref = dict(band_db)[1000.0]
    return [(f, round(level - ref, 1)) for f, level in band_db]


def _unused_goertzel(x: list[float], freq: float, rate: int = RATE) -> float:
    """Energy at one frequency, cheap enough for 29 bands in pure Python."""
    w = 2 * math.pi * freq / rate
    coeff = 2 * math.cos(w)
    s0 = s1 = s2 = 0.0
    for v in x:
        s0 = v + coeff * s1 - s2
        s2, s1 = s1, s0
    power = s1 * s1 + s2 * s2 - coeff * s1 * s2
    return max(power, 1e-20)


def print_table(levels: list[tuple[float, float]]) -> None:
    print("  band      level vs 1 kHz")
    for f, level in levels:
        bar = "+" * int(max(0, level + 20) / 1.5) if level >= 0 else "-" * int(max(0, -level) / 1.5)
        print(f"{f:8.0f} Hz  {level:+6.1f} dB  {bar}")


def advice(levels: list[tuple[float, float]]) -> None:
    """Crude but honest: compare broad regions and suggest small moves."""
    def region(lo: float, hi: float) -> float:
        vals = [l for f, l in levels if lo <= f < hi]
        return sum(vals) / len(vals) if vals else 0.0

    low, mid, high = region(40, 250), region(250, 3000), region(3000, 16000)
    print()
    print(f"  low {low:+.1f} dB   mid {mid:+.1f} dB   high {high:+.1f} dB")
    print("  suggested moves (one step, then re-measure):")
    for name, level in (("bass", low), ("treble", high)):
        if level > 3.0:
            print(f"    {name}: -{min(6.0, round((level - 1.5) / 2) * 0.5):.1f} dB")
        elif level < -3.0:
            print(f"    {name}: +{min(6.0, round((-level - 1.5) / 2) * 0.5):.1f} dB")
    if abs(mid) > 3.0:
        print(f"    mid:  {-mid / 2:+.1f} dB (cabin dip or peak around the midrange)")


def play(path: str) -> int:
    for tool, args in (("pw-play", [path]), ("paplay", [path]), ("aplay", ["-q", path])):
        if shutil.which(tool):
            print(f"playing with {tool}; Ctrl+C to stop")
            return subprocess.call([tool, *args])
    print("no pw-play/paplay/aplay found", file=sys.stderr)
    return 1


def record(seconds: float, out: str) -> int:
    for tool, args in (
        ("pw-record", ["--rate", str(RATE), "--channels", "1", out]),
        ("parecord", ["--rate", str(RATE), "--channels", "1", "--file-format=wav", out]),
        ("arecord", ["-q", "-f", "S16_LE", "-r", str(RATE), "-c", "1", "-d", str(int(seconds)), out]),
    ):
        if shutil.which(tool):
            print(f"recording {seconds:.0f} s with {tool}")
            cmd = [tool, *args]
            if tool != "arecord":
                proc = subprocess.Popen(cmd)
                try:
                    proc.wait(timeout=seconds)
                except subprocess.TimeoutExpired:
                    proc.terminate()
            else:
                subprocess.call(cmd)
            return 0
    print("no pw-record/parecord/arecord found", file=sys.stderr)
    return 1


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="EQ test signals and 1/3-octave analysis")
    p.add_argument("--make", metavar="DIR", help="write pink.wav and sweep.wav")
    p.add_argument("--play", metavar="FILE")
    p.add_argument("--sweep", metavar="FILE", nargs="?", const="", help="play a swept sine")
    p.add_argument("--measure", type=float, metavar="SECONDS")
    p.add_argument("--analyze", metavar="FILE")
    p.add_argument("--out", default="/tmp/eq-measure.wav")
    args = p.parse_args(argv)

    if args.make:
        os.makedirs(args.make, exist_ok=True)
        write_wav(os.path.join(args.make, "pink.wav"), pink(60))
        write_wav(os.path.join(args.make, "sweep.wav"), sweep(30))
        return 0

    if args.play:
        return play(args.play)

    if args.sweep is not None:
        path = args.sweep or "/tmp/sweep.wav"
        if not os.path.exists(path):
            write_wav(path, sweep(30))
        return play(path)

    if args.measure:
        rc = record(args.measure, args.out)
        if rc:
            return rc
        print_table(analyse(read_mono(args.out)))
        return 0

    if args.analyze:
        levels = analyse(read_mono(args.analyze))
        print_table(levels)
        advice(levels)
        return 0

    print(__doc__)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
