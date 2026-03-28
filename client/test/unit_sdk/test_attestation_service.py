from __future__ import annotations

import base64
import json

from cryptography.hazmat.primitives.asymmetric import ed25519

from tools.azt_sdk.services import attestation_service


def test_nonce_matches_exact_and_suffix_forms():
    assert attestation_service._nonce_matches("abc", "abc") is True
    assert attestation_service._nonce_matches("abc?nonce=abc", "abc") is True
    assert attestation_service._nonce_matches("xyz", "abc") is False


def test_verify_attestation_success(monkeypatch):
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pub_b64 = base64.b64encode(pub.public_bytes_raw()).decode("ascii")

    payload = {
        "attestation_version": 1,
        "attestation_type": "device_key_ownership",
        "nonce": "n-1",
        "device_sign_public_key_b64": pub_b64,
        "device_sign_fingerprint_hex": "d" * 64,
        "device_chip_id_hex": "chip1",
    }
    payload_raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    sig_b64 = base64.b64encode(priv.sign(payload_raw)).decode("ascii")

    state = {
        "ok": True,
        "device_sign_public_key_b64": pub_b64,
        "device_sign_fingerprint_hex": "d" * 64,
        "device_chip_id_hex": "chip1",
        "admin_fingerprint_hex": "a" * 64,
    }

    def fake_get_json(url: str, timeout: int):
        if url.endswith("/api/v0/config/state"):
            return state
        return {
            "ok": True,
            "payload": payload,
            "signature_algorithm": "ed25519",
            "signature_b64": sig_b64,
        }

    monkeypatch.setattr(attestation_service, "base_url", lambda **k: "http://h:8080")
    monkeypatch.setattr(attestation_service, "get_json", fake_get_json)

    ok, out = attestation_service.verify_attestation(host="h", port=8080, nonce="n-1", timeout=1)
    assert ok is True
    assert out["schema_ok"] is True
    assert out["sig_ok"] is True


def test_verify_attestation_schema_fail(monkeypatch):
    def fake_get_json(url: str, timeout: int):
        if url.endswith("/api/v0/config/state"):
            return {"ok": True, "device_sign_public_key_b64": "x", "device_sign_fingerprint_hex": "f", "device_chip_id_hex": "c"}
        return {"ok": False}

    monkeypatch.setattr(attestation_service, "base_url", lambda **k: "http://h:8080")
    monkeypatch.setattr(attestation_service, "get_json", fake_get_json)

    ok, out = attestation_service.verify_attestation(host="h", port=8080, nonce="n-1", timeout=1)
    assert ok is False
    assert out["schema_ok"] is False
