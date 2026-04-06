from __future__ import annotations

import base64
import json
import time
from pathlib import Path

from tools.azt_sdk.services import certificate_service


def test_validate_attestation_stale():
    ok, err, detail = certificate_service._validate_attestation(
        att={"issued_at_epoch_s": int(time.time()) - 9999},
        state={},
        host="h",
        port=8080,
        attestation_max_age_s=10,
    )
    assert ok is False
    assert err == "ATTESTATION_STALE"


def test_validate_attestation_chip_mismatch():
    now = int(time.time())
    att = {
        "issued_at_epoch_s": now,
        "host": "h",
        "port": 8080,
        "schema_ok": True,
        "sig_ok": True,
        "admin_fingerprint_hex": "a" * 64,
        "device_chip_id_hex": "chipA",
    }
    state = {"admin_fingerprint_hex": "a" * 64, "device_chip_id_hex": "chipB"}
    ok, err, _ = certificate_service._validate_attestation(att=att, state=state, host="h", port=8080, attestation_max_age_s=60)
    assert ok is False
    assert err == "ATTESTATION_CHIP_ID_MISMATCH"


def test_issue_certificate_state_get_failure(monkeypatch):
    monkeypatch.setattr(certificate_service, "base_url", lambda **k: "http://h:8080")
    monkeypatch.setattr(certificate_service, "get_json", lambda *a, **k: {"ok": False, "error": "x"})

    ok, err, detail = certificate_service.issue_certificate(
        host="h",
        port=8080,
        timeout=1,
        key_path="/tmp/key",
        attestation_path=None,
        attestation_max_age_s=120,
        cert_serial="c1",
        valid_until_utc="2027-01-01T00:00:00Z",
    )
    assert ok is False and err == "STATE_GET_FAILED"


def test_issue_certificate_auto_attestation_failure(monkeypatch):
    monkeypatch.setattr(certificate_service, "base_url", lambda **k: "http://h:8080")
    monkeypatch.setattr(certificate_service, "get_json", lambda *a, **k: {"ok": True, "admin_fingerprint_hex": "a" * 64})
    monkeypatch.setattr(certificate_service, "verify_attestation", lambda **k: (False, {"why": "bad"}))

    ok, err, detail = certificate_service.issue_certificate(
        host="h",
        port=8080,
        timeout=1,
        key_path="/tmp/key",
        attestation_path=None,
        attestation_max_age_s=120,
        cert_serial="c1",
        valid_until_utc="2027-01-01T00:00:00Z",
    )
    assert ok is False and err == "ATTESTATION_VERIFY_FAILED"


def test_issue_certificate_success_without_post_when_out_path_set(monkeypatch, tmp_path):
    att_file = tmp_path / "att.json"
    now = int(time.time())
    att_file.write_text(json.dumps({
        "issued_at_epoch_s": now,
        "host": "h",
        "port": 8080,
        "schema_ok": True,
        "sig_ok": True,
        "admin_fingerprint_hex": "f" * 64,
        "device_chip_id_hex": "chip1",
    }))

    monkeypatch.setattr(certificate_service, "base_url", lambda **k: "http://h:8080")
    monkeypatch.setattr(certificate_service, "get_json", lambda *a, **k: {
        "ok": True,
        "admin_fingerprint_hex": "f" * 64,
        "device_sign_public_key_b64": "pub",
        "device_sign_fingerprint_hex": "dfp",
        "device_chip_id_hex": "chip1",
    })
    monkeypatch.setattr(certificate_service, "ed25519_fp_hex_from_private_key", lambda p: "f" * 64)

    class FakePriv:
        def sign(self, payload: bytes) -> bytes:
            return b"sig"

    monkeypatch.setattr(certificate_service, "load_private_key_auto", lambda p, purpose=None: FakePriv())

    ok, err, payload = certificate_service.issue_certificate(
        host="h",
        port=8080,
        timeout=1,
        key_path=str(tmp_path / "admin.pem"),
        attestation_path=str(att_file),
        attestation_max_age_s=120,
        cert_serial="c1",
        valid_until_utc="2027-01-01T00:00:00Z",
        out_path=str(tmp_path / "cert.json"),
    )

    assert ok is True
    assert err is None
    assert payload["post_response"] is None


def test_issue_certificate_auto_attestation_missing_artifact(monkeypatch, tmp_path):
    monkeypatch.setattr(certificate_service, "base_url", lambda **k: "http://h:8080")
    monkeypatch.setattr(certificate_service, "get_json", lambda *a, **k: {
        "ok": True,
        "admin_fingerprint_hex": "a" * 64,
        "device_sign_public_key_b64": "pub",
        "device_sign_fingerprint_hex": "dfp",
        "device_chip_id_hex": "chip1",
    })
    # verify_attestation ok=True but missing attestation_artifact triggers line 58 fallback to {}
    monkeypatch.setattr(certificate_service, "verify_attestation", lambda **k: (True, {"schema_ok": True, "sig_ok": True}))

    ok, err, detail = certificate_service.issue_certificate(
        host="h",
        port=8080,
        timeout=1,
        key_path=str(tmp_path / "admin.pem"),
        attestation_path=None,
        attestation_max_age_s=120,
        cert_serial="c1",
        valid_until_utc="2027-01-01T00:00:00Z",
    )
    assert ok is False
    assert err == "ATTESTATION_STALE"


def test_issue_certificate_returns_validate_attestation_error(monkeypatch, tmp_path):
    monkeypatch.setattr(certificate_service, "base_url", lambda **k: "http://h:8080")
    monkeypatch.setattr(certificate_service, "get_json", lambda *a, **k: {
        "ok": True,
        "admin_fingerprint_hex": "a" * 64,
        "device_sign_public_key_b64": "pub",
        "device_sign_fingerprint_hex": "dfp",
        "device_chip_id_hex": "chip1",
    })

    now = int(time.time())
    att_file = tmp_path / "bad-att.json"
    att_file.write_text(json.dumps({
        "issued_at_epoch_s": now,
        "host": "other",
        "port": 8080,
        "schema_ok": True,
        "sig_ok": True,
        "admin_fingerprint_hex": "a" * 64,
        "device_chip_id_hex": "chip1",
    }))

    ok, err, detail = certificate_service.issue_certificate(
        host="h",
        port=8080,
        timeout=1,
        key_path=str(tmp_path / "admin.pem"),
        attestation_path=str(att_file),
        attestation_max_age_s=120,
        cert_serial="c1",
        valid_until_utc="2027-01-01T00:00:00Z",
    )
    assert ok is False
    assert err == "ATTESTATION_TARGET_MISMATCH"


def test_validate_attestation_target_mismatch():
    now = int(time.time())
    att = {
        "issued_at_epoch_s": now,
        "host": "other-host",
        "port": 8080,
        "schema_ok": True,
        "sig_ok": True,
        "admin_fingerprint_hex": "a" * 64,
        "device_chip_id_hex": "chipA",
    }
    state = {"admin_fingerprint_hex": "a" * 64, "device_chip_id_hex": "chipA"}
    ok, err, _ = certificate_service._validate_attestation(att=att, state=state, host="h", port=8080, attestation_max_age_s=60)
    assert ok is False
    assert err == "ATTESTATION_TARGET_MISMATCH"


def test_validate_attestation_not_verified():
    now = int(time.time())
    att = {
        "issued_at_epoch_s": now,
        "host": "h",
        "port": 8080,
        "schema_ok": False,
        "sig_ok": True,
        "admin_fingerprint_hex": "a" * 64,
        "device_chip_id_hex": "chipA",
    }
    state = {"admin_fingerprint_hex": "a" * 64, "device_chip_id_hex": "chipA"}
    ok, err, _ = certificate_service._validate_attestation(att=att, state=state, host="h", port=8080, attestation_max_age_s=60)
    assert ok is False
    assert err == "ATTESTATION_NOT_VERIFIED"


def test_validate_attestation_state_mismatch():
    now = int(time.time())
    att = {
        "issued_at_epoch_s": now,
        "host": "h",
        "port": 8080,
        "schema_ok": True,
        "sig_ok": True,
        "admin_fingerprint_hex": "a" * 64,
        "device_chip_id_hex": "chipA",
    }
    state = {"admin_fingerprint_hex": "b" * 64, "device_chip_id_hex": "chipA"}
    ok, err, _ = certificate_service._validate_attestation(att=att, state=state, host="h", port=8080, attestation_max_age_s=60)
    assert ok is False
    assert err == "ATTESTATION_STATE_MISMATCH"


def test_issue_certificate_key_ownership_mismatch(monkeypatch, tmp_path):
    att_file = tmp_path / "att.json"
    now = int(time.time())
    att_file.write_text(json.dumps({
        "issued_at_epoch_s": now,
        "host": "h",
        "port": 8080,
        "schema_ok": True,
        "sig_ok": True,
        "admin_fingerprint_hex": "f" * 64,
        "device_chip_id_hex": "chip1",
    }))

    monkeypatch.setattr(certificate_service, "base_url", lambda **k: "http://h:8080")
    monkeypatch.setattr(certificate_service, "get_json", lambda *a, **k: {
        "ok": True,
        "admin_fingerprint_hex": "f" * 64,
        "device_sign_public_key_b64": "pub",
        "device_sign_fingerprint_hex": "dfp",
        "device_chip_id_hex": "chip1",
    })
    monkeypatch.setattr(certificate_service, "ed25519_fp_hex_from_private_key", lambda p: "e" * 64)

    ok, err, detail = certificate_service.issue_certificate(
        host="h",
        port=8080,
        timeout=1,
        key_path=str(tmp_path / "admin.pem"),
        attestation_path=str(att_file),
        attestation_max_age_s=120,
        cert_serial="c1",
        valid_until_utc="2027-01-01T00:00:00Z",
    )

    assert ok is False
    assert err == "KEY_OWNERSHIP_MISMATCH"


def test_issue_certificate_post_failure(monkeypatch, tmp_path):
    att_file = tmp_path / "att.json"
    now = int(time.time())
    att_file.write_text(json.dumps({
        "issued_at_epoch_s": now,
        "host": "h",
        "port": 8080,
        "schema_ok": True,
        "sig_ok": True,
        "admin_fingerprint_hex": "f" * 64,
        "device_chip_id_hex": "chip1",
    }))

    monkeypatch.setattr(certificate_service, "base_url", lambda **k: "http://h:8080")
    monkeypatch.setattr(certificate_service, "get_json", lambda *a, **k: {
        "ok": True,
        "admin_fingerprint_hex": "f" * 64,
        "device_sign_public_key_b64": "pub",
        "device_sign_fingerprint_hex": "dfp",
        "device_chip_id_hex": "chip1",
    })
    monkeypatch.setattr(certificate_service, "ed25519_fp_hex_from_private_key", lambda p: "f" * 64)

    class FakePriv:
        def sign(self, payload: bytes) -> bytes:
            return b"sig"

    monkeypatch.setattr(certificate_service, "load_private_key_auto", lambda p, purpose=None: FakePriv())
    monkeypatch.setattr(certificate_service, "certificate_post", lambda **k: {"ok": False, "error": "POST_FAIL"})

    ok, err, detail = certificate_service.issue_certificate(
        host="h",
        port=8080,
        timeout=1,
        key_path=str(tmp_path / "admin.pem"),
        attestation_path=str(att_file),
        attestation_max_age_s=120,
        cert_serial="c1",
        valid_until_utc="2027-01-01T00:00:00Z",
        out_path=None,
    )

    assert ok is False
    assert err == "CERTIFICATE_POST_FAILED"


def test_issue_certificate_authorized_consumers_flags(monkeypatch, tmp_path):
    att_file = tmp_path / "att.json"
    now = int(time.time())
    att_file.write_text(json.dumps({
        "issued_at_epoch_s": now,
        "host": "h",
        "port": 8080,
        "schema_ok": True,
        "sig_ok": True,
        "admin_fingerprint_hex": "f" * 64,
        "device_chip_id_hex": "chip1",
    }))

    monkeypatch.setattr(certificate_service, "base_url", lambda **k: "http://h:8080")
    monkeypatch.setattr(certificate_service, "get_json", lambda *a, **k: {
        "ok": True,
        "admin_fingerprint_hex": "f" * 64,
        "device_sign_public_key_b64": "pub",
        "device_sign_fingerprint_hex": "dfp",
        "device_chip_id_hex": "chip1",
    })
    monkeypatch.setattr(certificate_service, "ed25519_fp_hex_from_private_key", lambda p: "f" * 64)

    class FakePriv:
        def sign(self, payload: bytes) -> bytes:
            return b"sig"

    monkeypatch.setattr(certificate_service, "load_private_key_auto", lambda p, purpose=None: FakePriv())

    ok, err, payload = certificate_service.issue_certificate(
        host="h",
        port=8080,
        timeout=1,
        key_path=str(tmp_path / "admin.pem"),
        attestation_path=str(att_file),
        attestation_max_age_s=120,
        cert_serial="c1",
        valid_until_utc="2027-01-01T00:00:00Z",
        auto_record=True,
        auto_decode=True,
        out_path=str(tmp_path / "cert.json"),
    )

    assert ok is True
    assert err is None
    cert = payload["certificate"]
    raw = base64.b64decode(cert["certificate_payload_b64"])
    doc = json.loads(raw.decode("utf-8"))
    assert doc["authorized_consumers"] == ["auto-record", "auto-decode"]
