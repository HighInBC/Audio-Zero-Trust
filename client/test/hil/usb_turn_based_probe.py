#!/usr/bin/env python3
from __future__ import annotations
import argparse, serial, time, re, sys


def run_once(port: str, size: int, timeout: float) -> tuple[bool, str]:
    payload = (b"A" * size)
    with serial.Serial(port, 115200, timeout=0.2, write_timeout=5, dsrdtr=False, rtscts=False, xonxoff=False) as ser:
        ser.dtr = True
        ser.rts = False
        time.sleep(0.1)
        ser.reset_input_buffer()
        ser.reset_output_buffer()

        # Wait for any line from device so we know link is alive.
        alive_deadline = time.time() + 3
        while time.time() < alive_deadline:
            b = ser.read(256)
            if b:
                break

        try:
            ser.write(f"LEN {size}\n".encode())
            ser.flush()
        except Exception as e:
            return False, f"begin_write_failed:{type(e).__name__}:{e}"

        # Wait for begin ack before sending bulk payload.
        begin_ok = False
        begin_deadline = time.time() + 3
        buf = ""
        while time.time() < begin_deadline:
            b = ser.read(256)
            if not b:
                continue
            txt = b.decode("utf-8", errors="replace")
            buf += txt
            if "[USBJTAG_PROBE] begin" in buf:
                begin_ok = True
                break
        if not begin_ok:
            return False, "begin_ack_missing"

        try:
            # Strict turn: host sends entire payload, then waits for response.
            ser.write(payload)
            ser.flush()
        except Exception as e:
            return False, f"payload_write_failed:{type(e).__name__}:{e}"

        complete_pat = re.compile(r"\[USBJTAG_PROBE\] complete (\d+)/(\d+)")
        deadline = time.time() + timeout
        out = ""
        while time.time() < deadline:
            b = ser.read(512)
            if not b:
                continue
            txt = b.decode("utf-8", errors="replace")
            out += txt
            m = complete_pat.search(out)
            if m:
                got = int(m.group(1)); exp = int(m.group(2))
                return (got == size and exp == size), f"complete:{got}/{exp}"

        return False, "complete_timeout"


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
