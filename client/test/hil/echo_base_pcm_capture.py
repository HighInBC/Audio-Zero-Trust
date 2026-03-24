#!/usr/bin/env python3
from __future__ import annotations

import argparse
import array
import cmath
import math
import re
import time
import wave
from pathlib import Path

import serial


def rms_dbfs(samples: list[int]) -> tuple[float, float]:
    if not samples:
        return 0.0, -120.0
    s2 = 0.0
    for v in samples:
        s2 += float(v) * float(v)
    rms = math.sqrt(s2 / len(samples))
    dbfs = 20.0 * math.log10(max(rms, 1e-9) / 32768.0)
    return rms, dbfs


def window_db_std(samples: list[int], win: int = 1024, hop: int = 512) -> float:
    vals: list[float] = []
    i = 0
    while i + win <= len(samples):
        _, db = rms_dbfs(samples[i : i + win])
        vals.append(db)
        i += hop
    if not vals:
        return 0.0
    mean = sum(vals) / len(vals)
    var = sum((v - mean) ** 2 for v in vals) / len(vals)
    return math.sqrt(var)


def top_fft_peaks(samples: list[int], sample_rate: int, nfft: int = 2048, topn: int = 5) -> list[float]:
    if len(samples) < nfft:
        nfft = 1024 if len(samples) >= 1024 else len(samples)
    if nfft < 64:
        return []

    win = [0.5 - 0.5 * math.cos(2.0 * math.pi * i / (nfft - 1)) for i in range(nfft)]
    x = [samples[i] * win[i] for i in range(nfft)]

    mags: list[tuple[float, int]] = []
    half = nfft // 2
    for k in range(1, half):
        acc = 0j
        for n in range(nfft):
            acc += x[n] * cmath.exp(-2j * math.pi * k * n / nfft)
        mags.append((abs(acc), k))

    mags.sort(reverse=True, key=lambda t: t[0])
    peaks = []
    used_bins: set[int] = set()
    for _, k in mags:
        if any(abs(k - b) <= 2 for b in used_bins):
            continue
        used_bins.add(k)
        peaks.append(k * sample_rate / nfft)
        if len(peaks) >= topn:
            break
    return peaks


def read_line(ser: serial.Serial, timeout_s: float = 30.0) -> str:
    end = time.time() + timeout_s
    while time.time() < end:
        b = ser.readline()
        if b:
            return b.decode("utf-8", errors="ignore").strip()
    raise TimeoutError("timeout waiting for serial line")


def main() -> int:
    ap = argparse.ArgumentParser(description="Capture PCM probe stream and produce WAV + quick stats")
    ap.add_argument("--port", default="/dev/ttyUSB0")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--out", default="/tmp/echo_base_probe.wav")
    ap.add_argument("--micgain", type=int, default=None)
    ap.add_argument("--adcgain", type=int, default=None)
    args = ap.parse_args()

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    source = "unknown"
    sample_rate = 16000
    bits = 16
    channels = 1
    nbytes = None

    ser = serial.Serial(args.port, args.baud, timeout=0.3)
    ser.reset_input_buffer()
    try:
        if args.micgain is not None:
            ser.write(f"MICGAIN {args.micgain}\n".encode())
            time.sleep(0.05)
        if args.adcgain is not None:
            ser.write(f"ADCGAIN {args.adcgain}\n".encode())
            time.sleep(0.05)

        ser.write(b"CAPTURE\n")

        deadline = time.time() + 40.0
        while time.time() < deadline:
            line = read_line(ser, timeout_s=5.0)
            if line.startswith("PCM_META"):
                m_meta = re.search(r"source=(\S+)\s+sample_rate=(\d+)\s+bits=(\d+)\s+channels=(\d+)\s+bytes=(\d+)", line)
                if m_meta:
                    source = m_meta.group(1)
                    sample_rate = int(m_meta.group(2))
                    bits = int(m_meta.group(3))
                    channels = int(m_meta.group(4))
            elif line.startswith("PCM_START"):
                m = re.search(r"PCM_START\s+(\d+)", line)
                if m:
                    nbytes = int(m.group(1))
                    break

        if nbytes is None:
            raise RuntimeError("did not observe PCM_START")

        pcm = bytearray()
        while len(pcm) < nbytes:
            chunk = ser.read(min(4096, nbytes - len(pcm)))
            if chunk:
                pcm.extend(chunk)

        # consume trailing PCM_END line
        _ = read_line(ser, timeout_s=5.0)
    finally:
        ser.close()

    samples_arr = array.array("h")
    samples_arr.frombytes(bytes(pcm))
    samples = list(samples_arr)
    if not samples:
        raise RuntimeError("no PCM samples captured")

    with wave.open(str(out_path), "wb") as wf:
        wf.setnchannels(channels)
        wf.setsampwidth(bits // 8)
        wf.setframerate(sample_rate)
        wf.writeframes(samples_arr.tobytes())

    rms, dbfs = rms_dbfs(samples)
    db_std = window_db_std(samples)
    peaks = top_fft_peaks(samples, sample_rate=sample_rate, nfft=2048, topn=5)

    print(f"source={source} samples={len(samples)} sample_rate={sample_rate} wav={out_path}")
    print(f"rms={rms:.2f} dBFS={dbfs:.2f} window_dB_std={db_std:.2f}")
    print("fft_peaks_hz=" + ", ".join(f"{p:.1f}" for p in peaks))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
