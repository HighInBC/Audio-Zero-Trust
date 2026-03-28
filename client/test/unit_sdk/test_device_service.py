from __future__ import annotations

import base64
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from tools.azt_sdk.services import device_service


def test_state_get_returns_major_mismatch_when_v1_legacy_present(monkeypatch):
    monkeypatch.setattr(device_service, "_state_get_v0", lambda **k: {"ok": False, "error": "STATE_GET_V0_FAILED"})
    monkeypatch.setattr(device_service, "_state_get_v1_legacy", lambda **k: {"ok": True, "state": "legacy"})

    out = device_service.state_get(host="h", port=8080, timeout=1)
    assert out["ok"] is False
    assert out["error"] == "ERR_API_MAJOR_MISMATCH"


def test_get_json_safe_wraps_exceptions(monkeypatch):
    monkeypatch.setattr(device_service, "get_json", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    out = device_service._get_json_safe(url="http://x", timeout=1, where="w", error="E")
    assert out["ok"] is False
    assert out["error"] == "E"
    assert out["detail"]["where"] == "w"


def test_stream_redirect_check_request_failure(monkeypatch):
    monkeypatch.setattr(device_service, "base_url", lambda **k: "http://h:8080")
    monkeypatch.setattr(device_service.requests, "get", lambda *a, **k: (_ for _ in ()).throw(TimeoutError("t")))
    ok, payload = device_service.stream_redirect_check(host="h", port=8080, seconds=1, stream_port=8081, timeout=1)
    assert ok is False
    assert payload["error"] == "STREAM_REDIRECT_CHECK_REQUEST_FAILED"


def test_stream_redirect_check_success(monkeypatch):
    class Resp:
        status_code = 307
        headers = {"Location": "http://h:8081/stream?x=1"}

    monkeypatch.setattr(device_service, "base_url", lambda **k: "http://h:8080")
    monkeypatch.setattr(device_service.requests, "get", lambda *a, **k: Resp())
    ok, payload = device_service.stream_redirect_check(host="h", port=8080, seconds=1, stream_port=8081, timeout=1)
    assert ok is True
    assert payload["status"] == 307


def test_stream_read_probe_reads_bytes(monkeypatch):
    class Resp:
        def __init__(self):
            self._chunks = [b"abc", b"def"]

        def iter_content(self, chunk_size=4096):
            yield from self._chunks

        def close(self):
            pass

    monkeypatch.setattr(device_service, "base_url", lambda **k: "http://h:8080")
    monkeypatch.setattr(device_service.requests, "get", lambda *a, **k: Resp())

    ok, payload = device_service.stream_read(host="h", port=8080, seconds=0.01, timeout=1, out_path=None, probe=True)
    assert ok is True
    assert payload["bytes"] >= 3


def test_mdns_fqdn_get_fallback_from_device_label(monkeypatch):
    monkeypatch.setattr(device_service, "state_get", lambda **k: {"ok": True, "device_label": "My Device"})
    ok, payload = device_service.mdns_fqdn_get(host="h", port=8080, timeout=1)
    assert ok is True
    assert payload["mdns_fqdn"].endswith(".local")


def test_ip_detect_passthrough(monkeypatch):
    monkeypatch.setattr(device_service, "detect_device_ip_from_serial", lambda **k: "192.168.1.9")
    ok, payload = device_service.ip_detect(port="/dev/ttyUSB0", baud=115200, timeout=7)
    assert ok is True
    assert payload["ip"] == "192.168.1.9"


def test_reboot_device_missing_nonce(monkeypatch, tmp_path):
    monkeypatch.setattr(device_service, "base_url", lambda **k: "http://h:8080")
    monkeypatch.setattr(device_service, "_get_json_safe", lambda **k: {"ok": True})
    out = device_service.reboot_device(host="h", port=8080, timeout=1, key_path=str(tmp_path / "missing.pem"))
    assert out["ok"] is False
    assert out["error"] == "ERR_REBOOT_CHALLENGE"


def test_reboot_device_success(monkeypatch, tmp_path):
    priv = ed25519.Ed25519PrivateKey.generate()
    pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path = tmp_path / "admin.pem"
    key_path.write_bytes(pem)

    monkeypatch.setattr(device_service, "base_url", lambda **k: "http://h:8080")
    monkeypatch.setattr(device_service, "_get_json_safe", lambda **k: {"ok": True, "nonce": "abc"})
    monkeypatch.setattr(device_service, "load_private_key_auto", lambda p, purpose=None: priv)
    monkeypatch.setattr(device_service, "ed25519_fp_hex_from_private_key", lambda p: "f" * 64)
    monkeypatch.setattr(device_service, "http_json", lambda *a, **k: {"ok": True, "done": True})

    out = device_service.reboot_device(host="h", port=8080, timeout=1, key_path=str(key_path))
    assert out["ok"] is True


def test_signing_key_check_success(monkeypatch):
    class FakeResp:
        def __init__(self, body: str, content_type: str = "application/x-pem-file"):
            self._body = body.encode()
            self.headers = {"Content-Type": content_type}

        def read(self):
            return self._body

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    responses = iter([
        FakeResp("-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----\n"),
        FakeResp("-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----\n"),
    ])

    monkeypatch.setattr(device_service, "base_url", lambda **k: "http://h:8080")
    monkeypatch.setattr(device_service, "urlopen_with_tls", lambda req, timeout=1: next(responses))

    ok, payload = device_service.signing_key_check(host="h", port=8080, timeout=1)
    assert ok is True
    assert payload["alias_matches"] is True
