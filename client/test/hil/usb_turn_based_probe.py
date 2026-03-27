#!/usr/bin/env python3
from __future__ import annotations
import argparse, serial, time, zlib

MAGIC = b"AZT1"


def u32be(v: int) -> bytes:
    return bytes([(v >> 24) & 0xFF, (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF])


def read_exact(ser: serial.Serial, n: int, timeout: float) -> bytes | None:
    end = time.time() + timeout
    out = bytearray()
    while len(out) < n and time.time() < end:
        chunk = ser.read(n - len(out))
        if chunk:
            out.extend(chunk)
    return bytes(out) if len(out) == n else None


def read_frame(ser: serial.Serial, timeout: float) -> tuple[bool, str]:
    hdr = read_exact(ser, 8, timeout)
    if hdr is None:
        return False, "timeout_hdr"
    if hdr[:4] != MAGIC:
        return False, f"bad_magic:{hdr[:4]!r}"
    ln = int.from_bytes(hdr[4:8], "big")
    payload = read_exact(ser, ln, timeout)
    if payload is None:
        return False, "timeout_payload"
    crc_raw = read_exact(ser, 4, timeout)
    if crc_raw is None:
        return False, "timeout_crc"
    got_crc = int.from_bytes(crc_raw, "big")
    calc_crc = zlib.crc32(payload) & 0xFFFFFFFF
    if got_crc != calc_crc:
        return False, f"bad_crc:{got_crc:08x}!={calc_crc:08x}"
    return True, payload.decode("utf-8", errors="replace")


def write_frame(ser: serial.Serial, payload: bytes) -> tuple[bool, str]:
    frame = bytearray()
    frame += MAGIC
    frame += u32be(len(payload))
    frame += payload
    frame += u32be(zlib.crc32(payload) & 0xFFFFFFFF)
    try:
        ser.write(frame)
        ser.flush()
        return True, "ok"
    except Exception as e:
        return False, f"write_failed:{type(e).__name__}:{e}"


def run_once(port: str, size: int, timeout: float) -> tuple[bool, str]:
    payload = b"A" * size
    with serial.Serial(port, 115200, timeout=0.2, write_timeout=5, dsrdtr=False, rtscts=False, xonxoff=False) as ser:
        ser.dtr = True
        ser.rts = False
        time.sleep(0.15)
        ser.reset_input_buffer()
        ser.reset_output_buffer()

        ok, msg = read_frame(ser, 2.5)
        if not ok:
            return False, f"ready_missing:{msg}"
        if msg != "READY":
            return False, f"unexpected_ready:{msg}"

        ok, msg = write_frame(ser, payload)
        if not ok:
            return False, msg

        ok, msg = read_frame(ser, timeout)
        if not ok:
            return False, f"resp:{msg}"
        return (msg == f"OK:{size}"), f"resp:{msg}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", default="/dev/ttyACM0")
    ap.add_argument("--size", type=int, default=3033)
    ap.add_argument("--trials", type=int, default=10)
    ap.add_argument("--timeout", type=float, default=8.0)
    args = ap.parse_args()

    passed = 0
    for i in range(args.trials):
        ok, detail = run_once(args.port, args.size, args.timeout)
        print({"trial": i + 1, "ok": ok, "detail": detail})
        if ok:
            passed += 1
        time.sleep(0.2)
    print({"passed": passed, "trials": args.trials, "size": args.size})
    return 0 if passed == args.trials else 1


if __name__ == "__main__":
    raise SystemExit(main())
