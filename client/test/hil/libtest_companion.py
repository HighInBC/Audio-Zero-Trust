#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import sys
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes


def jdump(x: dict) -> str:
    return json.dumps(x, separators=(",", ":"))


def main() -> int:
    ap = argparse.ArgumentParser(description="Companion app for on-device library test firmware")
    ap.add_argument("--port", default="/dev/ttyUSB0")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--timeout", type=int, default=60)
    args = ap.parse_args()

    try:
        import serial  # type: ignore
    except Exception as e:
        print("pyserial required: pip install pyserial", file=sys.stderr)
        raise SystemExit(2) from e

    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with serial.Serial(args.port, baudrate=args.baud, timeout=0.25) as ser:
        ser.dtr = False
        ser.rts = False
        time.sleep(0.05)
        ser.reset_input_buffer()

        def send(obj: dict):
            line = jdump(obj) + "\n"
            ser.write(line.encode("utf-8"))

        send({"cmd": "PING"})

        deadline = time.time() + args.timeout
        sent_pub = False
        started = False

        while time.time() < deadline:
            raw = ser.readline().decode("utf-8", errors="replace").strip()
            if not raw:
                continue
            print(raw)

            try:
                msg = json.loads(raw)
            except Exception:
                continue

            ev = msg.get("event")
            if ev == "PONG":
                if not sent_pub:
                    send({"cmd": "PUBKEY_SET", "pem_b64": base64.b64encode(pub_pem).decode("ascii")})
                    sent_pub = True
                continue

            if ev == "PUBKEY_SET_OK" and not started:
                send({"cmd": "RUN_ALL"})
                started = True
                continue

            if ev == "RSA_WRAP_AES_REQ":
                wrapped = base64.b64decode(msg["wrapped_b64"])
                plain = priv.decrypt(
                    wrapped,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )

                scenario = msg.get("scenario", "normal")
                resp_id = int(msg["id"])
                resp_plain_b64 = base64.b64encode(plain).decode("ascii")

                if scenario == "bad_id":
                    resp_id += 1
                elif scenario == "bad_b64":
                    resp_plain_b64 = "!!not_b64!!"
                elif scenario == "bad_plain":
                    bad = bytearray(plain)
                    if bad:
                        bad[0] ^= 0x01
                    resp_plain_b64 = base64.b64encode(bytes(bad)).decode("ascii")
                elif scenario == "no_response":
                    # Intentionally do not respond (timeout path test).
                    continue

                send({
                    "cmd": "RSA_WRAP_AES_RESP",
                    "id": resp_id,
                    "plain_b64": resp_plain_b64,
                })

                if scenario == "duplicate":
                    # send a duplicate late reply to ensure firmware handles unexpected extra response
                    time.sleep(0.05)
                    send({
                        "cmd": "RSA_WRAP_AES_RESP",
                        "id": resp_id,
                        "plain_b64": resp_plain_b64,
                    })
                continue

            if ev == "TEST_SUMMARY":
                ok = bool(msg.get("ok", False))
                print(jdump({"companion_ok": ok, **msg}))
                return 0 if ok else 1

        print(jdump({"error": "timeout", "sent_pub": sent_pub, "started": started}))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
