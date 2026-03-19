#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import math
import struct
from pathlib import Path

from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def decrypt_azt1(bin_path: Path, key_path: Path) -> bytes:
    data = bin_path.read_bytes()
    if not data.startswith(b"AZT1\n"):
        raise ValueError("not AZT1")

    i = data.find(b"\n", 5)
    if i < 0:
        raise ValueError("missing header line")

    plain = json.loads(data[5:i].decode("utf-8"))
    enc_len = int.from_bytes(data[i + 1 : i + 3], "big")
    enc_header_ct = data[i + 3 : i + 3 + enc_len]

    priv = serialization.load_pem_private_key(key_path.read_bytes(), password=None)

    wrapped = b64d(plain["wrapped_header_key_b64"])
    header_key = priv.decrypt(
        wrapped,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    header_nonce = b64d(plain["header_nonce_b64"])
    header_tag = b64d(plain["header_tag_b64"])
    header_pt = AESGCM(header_key).decrypt(header_nonce, enc_header_ct + header_tag, None)
    dec = json.loads(header_pt.decode("utf-8"))

    audio_key = b64d(dec["audio_key_b64"])
    nonce_prefix = b64d(dec["audio_nonce_prefix_b64"])
    chain_key = b64d(dec["chain_key_b64"])
    v_prev = b64d(dec["chain_seed_b64"])

    pos = i + 3 + enc_len
    pcm = bytearray()

    while pos + 9 <= len(data):
        seq = int.from_bytes(data[pos : pos + 4], "big")
        ct_len = int.from_bytes(data[pos + 4 : pos + 8], "big")
        tag_len = data[pos + 8]
        pos += 9

        need = ct_len + tag_len + 32
        if pos + need > len(data):
            break

        ct = data[pos : pos + ct_len]
        tag = data[pos + ct_len : pos + ct_len + tag_len]
        chain_v = data[pos + ct_len + tag_len : pos + need]
        pos += need

        hm = hmac.HMAC(chain_key, hashes.SHA256())
        hm.update(seq.to_bytes(4, "big"))
        hm.update(ct_len.to_bytes(4, "big"))
        hm.update(ct)
        hm.update(tag)
        hm.update(v_prev)
        if hm.finalize() != chain_v:
            break
        v_prev = chain_v

        nonce = nonce_prefix + seq.to_bytes(4, "big") + b"\x00\x00\x00\x00"
        pt = AESGCM(audio_key).decrypt(nonce, ct + tag, None)
        pcm.extend(pt)

    return bytes(pcm)


def pcm16_iter(pcm: bytes):
    n = len(pcm) // 2
    for i in range(n):
        yield struct.unpack_from("<h", pcm, i * 2)[0]


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

    # crude periodicity proxy: lagged autocorr at plausible fan lags
    best_corr = 0.0
    for lag in range(int(sr / 400), int(sr / 30)):  # ~30..400 Hz
        if lag >= n:
            break
        num = 0.0
        den1 = 0.0
        den2 = 0.0
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

    # tolerant envelopes around baseline
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

    pcm = decrypt_azt1(Path(args.infile), Path(args.key))
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
