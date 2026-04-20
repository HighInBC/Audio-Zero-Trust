#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import tempfile
import wave
from pathlib import Path

from tools.azt_client.stream import decode_azt1_stream_to_wav


def decode_pcm(bin_path: Path, key_path: Path) -> bytes:
    data = bin_path.read_bytes()
    key_raw = key_path.read_bytes()
    with tempfile.NamedTemporaryFile(suffix=".wav", delete=True) as tf:
        decode_azt1_stream_to_wav(
            data=data,
            out_wav_path=Path(tf.name),
            admin_private_key_pem=key_raw,
            apply_gain=False,
            gain=None,
            preserve_tail=False,
        )
        with wave.open(tf.name, "rb") as wf:
            return wf.readframes(wf.getnframes())


def pcm16_iter(pcm: bytes):
    n = len(pcm) // 2
    for i in range(n):
        lo = pcm[i * 2]
        hi = pcm[i * 2 + 1]
        v = int.from_bytes(bytes([lo, hi]), "little", signed=True)
        yield v


def metrics(pcm: bytes, sr: int = 16000) -> dict:
    s = list(pcm16_iter(pcm))
    if not s:
        return {"samples": 0}

    n = len(s)
    mean = sum(s) / n
    rms = math.sqrt(sum(x * x for x in s) / n)
    zc = sum(1 for i in range(1, n) if (s[i - 1] < 0 <= s[i]) or (s[i - 1] > 0 >= s[i]))
    zcr = zc / max(1, n - 1)
    clip_count = sum(1 for x in s if x >= 32767 or x <= -32768)
    clip_ratio = clip_count / n

    best_corr = 0.0
    for lag in range(int(sr / 400), int(sr / 30)):
        if lag >= n:
            break
        num = den1 = den2 = 0.0
        for i in range(n - lag):
            a = s[i] - mean
            b = s[i + lag] - mean
            num += a * b
            den1 += a * a
            den2 += b * b
        if den1 > 0 and den2 > 0:
            c = num / math.sqrt(den1 * den2)
            if c > best_corr:
                best_corr = c

    return {
        "samples": n,
        "duration_s": n / sr,
        "mean": mean,
        "rms": rms,
        "zcr": zcr,
        "clip_ratio": clip_ratio,
        "best_periodic_corr": best_corr,
    }


def compare(cur: dict, base: dict) -> tuple[bool, list[str]]:
    notes: list[str] = []
    ok = True

    def check(name: str, low: float, high: float):
        nonlocal ok
        v = float(cur[name])
        if v < low or v > high:
            ok = False
            notes.append(f"{name} out of range: {v:.6f} not in [{low:.6f}, {high:.6f}]")

    check("rms", base["rms"] * 0.25, base["rms"] * 2.5)
    check("zcr", max(0.0, base["zcr"] * 0.4), min(1.0, base["zcr"] * 1.8 + 0.02))
    check("best_periodic_corr", max(0.02, base["best_periodic_corr"] * 0.4), 1.0)

    if float(cur["clip_ratio"]) > 0.02:
        ok = False
        notes.append(f"clip_ratio too high: {cur['clip_ratio']:.6f}")

    mean_delta = abs(float(cur["mean"]) - float(base.get("mean", 0.0)))
    if mean_delta > max(500.0, abs(float(base.get("mean", 0.0))) * 0.25):
        ok = False
        notes.append(f"dc offset drift too high: delta_mean={mean_delta:.2f}")

    if abs(float(cur["mean"])) > 4000:
        notes.append(f"warning: large absolute DC offset present: mean={cur['mean']:.2f}")

    return ok, notes


def main() -> int:
    ap = argparse.ArgumentParser(description="Baseline/compare check for AZT1 mic audio")
    ap.add_argument("--in", dest="infile", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--baseline", required=True)
    ap.add_argument("--mode", choices=["create", "check"], default="check")
    args = ap.parse_args()

    pcm = decode_pcm(Path(args.infile), Path(args.key))
    m = metrics(pcm)

    bpath = Path(args.baseline)
    if args.mode == "create":
        bpath.parent.mkdir(parents=True, exist_ok=True)
        bpath.write_text(json.dumps(m, indent=2))
        print(json.dumps({"ok": True, "mode": "create", "baseline": str(bpath), "metrics": m}))
        return 0

    base = json.loads(bpath.read_text())
    ok, notes = compare(m, base)
    print(json.dumps({"ok": ok, "mode": "check", "metrics": m, "baseline": base, "notes": notes}, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
