from __future__ import annotations

import base64
import json
from cryptography.hazmat.primitives import serialization


def make_unsigned_config(identity: str, admin_pub_b64: str, admin_fp: str, wifi_ssid: str, wifi_password: str) -> dict:
    return {
        "config_version": 1,
        "device_label": identity,
        "admin_key": {
            "alg": "ed25519",
            "public_key_b64": admin_pub_b64,
            "fingerprint_alg": "sha256-raw-ed25519-pub",
            "fingerprint_hex": admin_fp,
        },
        "wifi": {"ssid": wifi_ssid, "password": wifi_password},
        "time": {"server": "pool.ntp.org"},
        "audio": {"sample_rate_hz": 16000, "channels": 1, "sample_width_bytes": 2, "preamp_gain": 2, "adc_gain": 248},
    }


def make_signed_config(unsigned_cfg: dict, priv_pem: bytes, fp: str) -> dict:
    payload = json.dumps(unsigned_cfg, separators=(",", ":")).encode("utf-8")
    priv = serialization.load_pem_private_key(priv_pem, password=None)
    sig = priv.sign(payload)
    out = dict(unsigned_cfg)
    out["signature"] = {
        "alg": "ed25519",
        "signed_payload_b64": base64.b64encode(payload).decode("ascii"),
        "sig_b64": base64.b64encode(sig).decode("ascii"),
        "signer_fingerprint_hex": fp,
    }
    return out
