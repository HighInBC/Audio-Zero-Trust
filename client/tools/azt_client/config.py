from __future__ import annotations

import base64
import json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def make_unsigned_config(identity: str, pub_pem: str, fp: str, wifi_ssid: str, wifi_password: str) -> dict:
    return {
        "config_version": 1,
        "device_label": identity,
        "admin_key": {
            "alg": "rsa-oaep-sha256",
            "public_key_pem": pub_pem,
            "fingerprint_alg": "sha256-spki-der",
            "fingerprint_hex": fp,
        },
        "wifi": {"ssid": wifi_ssid, "password": wifi_password},
        "time": {"server": "pool.ntp.org"},
        "audio": {"sample_rate_hz": 16000, "channels": 1, "sample_width_bytes": 2},
    }


def make_signed_config(unsigned_cfg: dict, priv_pem: bytes, fp: str) -> dict:
    payload = json.dumps(unsigned_cfg, separators=(",", ":")).encode("utf-8")
    priv = serialization.load_pem_private_key(priv_pem, password=None)
    sig = priv.sign(payload, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256().digest_size), hashes.SHA256())
    out = dict(unsigned_cfg)
    out["signature"] = {
        "alg": "rsa-pss-sha256",
        "signed_payload_b64": base64.b64encode(payload).decode("ascii"),
        "sig_b64": base64.b64encode(sig).decode("ascii"),
        "signer_fingerprint_hex": fp,
    }
    return out
