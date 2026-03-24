#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path


def run_capture(port: str, baud: int, out_path: Path, mic: int, adc: int) -> None:
    py = Path(__file__).with_name("echo_base_pcm_capture.py")
    cmd = [
        "python3",
        str(py),
        "--port",
        port,
        "--baud",
        str(baud),
        "--out",
        str(out_path),
        "--micgain",
        str(mic),
        "--adcgain",
        str(adc),
    ]
    subprocess.run(cmd, check=True)


def main() -> int:
    ap = argparse.ArgumentParser(description="Capture Echo Base WAVs across gain settings")
    ap.add_argument("--port", default="/dev/ttyUSB0")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--out-dir", default="/tmp/echo-base-gain-sweep")
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    combos = [
        (0, 96),
        (1, 128),
        (1, 160),
        (2, 192),
        (3, 224),
        (4, 255),
    ]

    for mic, adc in combos:
        out = out_dir / f"echo_base_mic{mic:03d}_adc{adc:03d}.wav"
        print(f"capturing {out.name} ...")
        run_capture(args.port, args.baud, out, mic, adc)

    print(f"done: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
