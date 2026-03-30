from __future__ import annotations

import base64
import json
from pathlib import Path
import urllib.error

import pytest

from tools.azt_sdk.services import operations_service


def test_parse_meta_valid():
    out = operations_service.parse_meta(["a=1", "b = two"])
    assert out == {"a": "1", "b": "two"}


def test_parse_meta_invalid_raises():
    with pytest.raises(ValueError):
        operations_service.parse_meta(["broken"])


def test_apply_config_handles_post_failure(monkeypatch, tmp_path):
    cfg = tmp_path / "cfg.json"
    cfg.write_text(json.dumps({"config_version": 1}))
    key = tmp_path / "k.pem"
    key.write_bytes(b"k")

    monkeypatch.setattr(operations_service, "ed25519_fp_hex_from_private_key", lambda p: "f" * 64)
    monkeypatch.setattr(operations_service, "make_signed_config", lambda c, k, f: {"signed": True})
    monkeypatch.setattr(operations_service, "base_url", lambda **k: "http://h:8080")
    monkeypatch.setattr(operations_service, "get_json", lambda *a, **k: {"ok": True, "config_revision": 3})
    monkeypatch.setattr(operations_service, "http_json", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("post boom")))

    ok, payload = operations_service.apply_config(
        in_path=str(cfg),
        key_path=str(key),
        host="h",
        port=8080,
        timeout=1,
        fingerprint="",
    )
    assert ok is False
    assert payload["error"] == "APPLY_CONFIG_POST_FAILED"


def test_apply_config_success(monkeypatch, tmp_path):
    cfg = tmp_path / "cfg.json"
    cfg.write_text(json.dumps({"config_version": 1}))
    key = tmp_path / "k.pem"
    key.write_bytes(b"k")

    monkeypatch.setattr(operations_service, "ed25519_fp_hex_from_private_key", lambda p: "f" * 64)
    monkeypatch.setattr(operations_service, "make_signed_config", lambda c, k, f: {"signed": True})
    monkeypatch.setattr(operations_service, "base_url", lambda **k: "http://h:8080")
    monkeypatch.setattr(operations_service, "http_json", lambda *a, **k: {"ok": True})
    monkeypatch.setattr(operations_service, "get_json", lambda *a, **k: {"ok": True, "state": "ok"})

    ok, payload = operations_service.apply_config(
        in_path=str(cfg),
        key_path=str(key),
        host="h",
        port=8080,
        timeout=1,
        fingerprint="",
    )
    assert ok is True
    assert payload["state"]["ok"] is True


def test_apply_config_signs_with_if_version_from_state(monkeypatch, tmp_path):
    cfg = tmp_path / "cfg.json"
    cfg.write_text(json.dumps({"config_version": 1}))
    key = tmp_path / "k.pem"
    key.write_bytes(b"k")

    seen = {}

    def _mk(c, k, f):
        seen["if_version"] = c.get("if_version")
        return {"signed": True}

    monkeypatch.setattr(operations_service, "ed25519_fp_hex_from_private_key", lambda p: "f" * 64)
    monkeypatch.setattr(operations_service, "make_signed_config", _mk)
    monkeypatch.setattr(operations_service, "base_url", lambda **k: "http://h:8080")

    calls = {"n": 0}
    def _get(*a, **k):
        calls["n"] += 1
        if calls["n"] == 1:
            return {"ok": True, "config_revision": 7}
        return {"ok": True}

    monkeypatch.setattr(operations_service, "get_json", _get)
    monkeypatch.setattr(operations_service, "http_json", lambda *a, **k: {"ok": True})

    ok, _ = operations_service.apply_config(
        in_path=str(cfg),
        key_path=str(key),
        host="h",
        port=8080,
        timeout=1,
        fingerprint="",
    )

    assert ok is True
    assert seen["if_version"] == 7


def test_config_patch_requires_dict_patch_obj(monkeypatch, tmp_path):
    key = tmp_path / "k.pem"
    key.write_bytes(b"k")
    with pytest.raises(RuntimeError):
        operations_service.config_patch(
            patch_path="",
            patch_obj=["bad"],
            if_version=1,
            key_path=str(key),
            host="h",
            port=8080,
            timeout=1,
            fingerprint="",
        )


def test_config_patch_handles_state_get_failure(monkeypatch, tmp_path):
    key = tmp_path / "k.pem"
    key.write_bytes(b"k")
    monkeypatch.setattr(operations_service, "ed25519_fp_hex_from_private_key", lambda p: "f" * 64)
    monkeypatch.setattr(operations_service, "make_signed_config", lambda c, k, f: {"signed": True})
    monkeypatch.setattr(operations_service, "base_url", lambda **k: "http://h:8080")
    monkeypatch.setattr(operations_service, "http_json", lambda *a, **k: {"ok": True})
    monkeypatch.setattr(operations_service, "get_json", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))

    ok, payload = operations_service.config_patch(
        patch_path="",
        patch_obj={"x": 1},
        if_version=1,
        key_path=str(key),
        host="h",
        port=8080,
        timeout=1,
        fingerprint="",
    )

    assert ok is False
    assert payload["error"] == "CONFIG_PATCH_STATE_GET_FAILED"


def test_build_current_firmware_build_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(operations_service.build_service, "resolve_platformio", lambda: "pio")

    class Proc:
        returncode = 1
        stdout = "bad"
        stderr = "err"

    monkeypatch.setattr(operations_service.subprocess, "run", lambda *a, **k: Proc())

    with pytest.raises(RuntimeError, match="ERR_OTA_BUILD"):
        operations_service.build_current_firmware(repo_root=tmp_path, env="atom-echo")


def test_build_current_firmware_missing_output(monkeypatch, tmp_path):
    monkeypatch.setattr(operations_service.build_service, "resolve_platformio", lambda: "pio")

    class Proc:
        returncode = 0
        stdout = "ok"
        stderr = ""

    monkeypatch.setattr(operations_service.subprocess, "run", lambda *a, **k: Proc())

    with pytest.raises(RuntimeError, match="ERR_OTA_FIRMWARE_NOT_FOUND"):
        operations_service.build_current_firmware(repo_root=tmp_path, env="atom-echo")


def test_ota_bundle_create_rejects_missing_firmware(tmp_path):
    key = tmp_path / "k.pem"
    key.write_bytes(b"k")
    with pytest.raises(RuntimeError, match="ERR_OTA_FIRMWARE_NOT_FOUND"):
        operations_service.ota_bundle_create(
            repo_root=tmp_path,
            key_path=str(key),
            out_path=str(tmp_path / "o.otabundle"),
            firmware_path=str(tmp_path / "missing.bin"),
            env="atom-echo",
            target="atom-echo",
            channel="stable",
            version="1.0.0",
            version_code=1,
        )


def test_ota_bundle_create_rejects_invalid_codes_and_target(monkeypatch, tmp_path):
    fw = tmp_path / "firmware.bin"
    fw.write_bytes(b"abc")
    key = tmp_path / "k.pem"
    key.write_bytes(b"k")
    monkeypatch.setattr(operations_service, "sign_bytes", lambda *a, **k: b"sig")
    monkeypatch.setattr(operations_service, "ed25519_fp_hex_from_private_key", lambda p: "f" * 64)

    with pytest.raises(RuntimeError, match="ERR_OTA_VERSION_CODE_INVALID"):
        operations_service.ota_bundle_create(
            repo_root=tmp_path, key_path=str(key), out_path=str(tmp_path / "o1.otabundle"),
            firmware_path=str(fw), env="atom-echo", target="atom-echo", channel="stable", version="1", version_code=0
        )

    with pytest.raises(RuntimeError, match="ERR_OTA_ROLLBACK_FLOOR_INVALID"):
        operations_service.ota_bundle_create(
            repo_root=tmp_path, key_path=str(key), out_path=str(tmp_path / "o2.otabundle"),
            firmware_path=str(fw), env="atom-echo", target="atom-echo", channel="stable", version="1", version_code=1,
            rollback_floor_code=0,
        )

    with pytest.raises(RuntimeError, match="ERR_OTA_TARGET_INVALID"):
        operations_service.ota_bundle_create(
            repo_root=tmp_path, key_path=str(key), out_path=str(tmp_path / "o3.otabundle"),
            firmware_path=str(fw), env="atom-echo", target="bad-target", channel="stable", version="1", version_code=1,
        )


def test_ota_bundle_post_unhappy_paths(monkeypatch, tmp_path):
    missing = operations_service.ota_bundle_post(
        in_path=str(tmp_path / "missing.otabundle"),
        host="h",
        port=8080,
        upgrade_path="/upgrade",
        timeout=1,
    )
    assert missing[0] is False and missing[1] == "ERR_OTA_BUNDLE_NOT_FOUND"

    bundle = tmp_path / "b.otabundle"
    bundle.write_bytes(b"x")
    monkeypatch.setattr(operations_service, "base_url", lambda **k: "http://h:8080")

    class HErr(urllib.error.HTTPError):
        def __init__(self):
            super().__init__(url="http://h:8080/upgrade", code=500, msg="bad", hdrs=None, fp=None)

        def read(self):
            return b'{"ok":false}'

    def raise_http(*a, **k):
        raise HErr()

    monkeypatch.setattr(operations_service, "urlopen_with_tls", raise_http)
    ok, err, payload = operations_service.ota_bundle_post(
        in_path=str(bundle), host="h", port=8080, upgrade_path="/upgrade", timeout=1
    )
    assert ok is False and err == "ERR_OTA_BUNDLE_HTTP"

    monkeypatch.setattr(operations_service, "urlopen_with_tls", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    ok, err, payload = operations_service.ota_bundle_post(
        in_path=str(bundle), host="h", port=8080, upgrade_path="/upgrade", timeout=1
    )
    assert ok is False and err == "ERR_OTA_BUNDLE_POST"


def test_separate_headers_basic_errors(tmp_path):
    p = tmp_path / "in.azt"
    p.write_bytes(b"NOTAZT")
    ok, payload = operations_service.separate_headers(in_path=str(p), out_headers=str(tmp_path / "h.json"))
    assert ok is False and payload["error"] == "ERR_MAGIC"

    p.write_bytes(b"AZT1\n")
    ok, payload = operations_service.separate_headers(in_path=str(p), out_headers=str(tmp_path / "h.json"))
    assert ok is False and payload["error"] == "ERR_HEADER_JSON"


def test_decode_next_header_errors(tmp_path):
    p = tmp_path / "bad.request"
    p.write_text("{}")
    ok, payload = operations_service.decode_next_header(
        in_path=str(p), key_path=str(tmp_path / "k.pem"), out_path=str(tmp_path / "out.azt")
    )
    assert ok is False and payload["error"] == "ERR_MAGIC"


def test_combine_headers_schema_error(tmp_path):
    in_path = tmp_path / "in.azt"
    in_path.write_bytes(b"AZT1\n{}\nabc\n")
    headers = tmp_path / "headers.json"
    headers.write_text(json.dumps({"schema": "wrong"}))

    ok, payload = operations_service.combine_headers(
        in_path=str(in_path), headers_path=str(headers), decoded_next_header_path="", out_path=str(tmp_path / "out.azt")
    )
    assert ok is False and payload["error"] == "ERR_HEADER_PACKAGE_SCHEMA"


def _base_state() -> dict:
    return {
        "ok": True,
        "admin_fingerprint_hex": "a" * 64,
        "device_sign_public_key_b64": base64.b64encode(b"1" * 32).decode("ascii"),
        "device_sign_fingerprint_hex": "b" * 64,
        "device_chip_id_hex": "chip-1",
    }


def _att_for_state(state: dict, nonce: str) -> dict:
    return {
        "ok": True,
        "payload": {
            "nonce": nonce,
            "device_sign_public_key_b64": state["device_sign_public_key_b64"],
            "device_sign_fingerprint_hex": state["device_sign_fingerprint_hex"],
            "device_chip_id_hex": state["device_chip_id_hex"],
        },
        "signature_algorithm": "ed25519",
        "signature_b64": base64.b64encode(b"sig").decode("ascii"),
    }


def test_certify_issue_state_query_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(operations_service, "base_url", lambda **k: "http://h:8080")
    monkeypatch.setattr(operations_service, "get_json", lambda *a, **k: {"ok": False, "error": "x"})

    ok, err, payload = operations_service.certify_issue(
        host="h", port=8080, timeout=1, key_path=str(tmp_path / "k.pem"),
        serial="s", issue_id="i", title="t", expected="e", actual="a", repro=[], evidence=[], meta=[],
        nonce="", cert_serial="", no_upload_device_cert=True, out_path=str(tmp_path / "c.json")
    )
    assert ok is False and err == "ERR_STATE_QUERY"


def test_certify_issue_key_ownership_failure(monkeypatch, tmp_path):
    state = _base_state()
    monkeypatch.setattr(operations_service, "base_url", lambda **k: "http://h:8080")
    monkeypatch.setattr(operations_service, "get_json", lambda *a, **k: state)
    monkeypatch.setattr(operations_service, "ed25519_fp_hex_from_private_key", lambda p: "c" * 64)

    ok, err, payload = operations_service.certify_issue(
        host="h", port=8080, timeout=1, key_path=str(tmp_path / "k.pem"),
        serial="s", issue_id="i", title="t", expected="e", actual="a", repro=[], evidence=[], meta=[],
        nonce="n", cert_serial="", no_upload_device_cert=True, out_path=str(tmp_path / "c.json")
    )
    assert ok is False and err == "ERR_KEY_OWNERSHIP"


def test_certify_issue_attestation_mismatch_paths(monkeypatch, tmp_path):
    state = _base_state()
    att = _att_for_state(state, "nonce-good")

    def fake_get_json(url: str, timeout: int):
        if url.endswith("/api/v0/config/state"):
            return state
        return att

    monkeypatch.setattr(operations_service, "base_url", lambda **k: "http://h:8080")
    monkeypatch.setattr(operations_service, "get_json", fake_get_json)
    monkeypatch.setattr(operations_service, "ed25519_fp_hex_from_private_key", lambda p: state["admin_fingerprint_hex"])

    ok, err, payload = operations_service.certify_issue(
        host="h", port=8080, timeout=1, key_path=str(tmp_path / "k.pem"),
        serial="s", issue_id="i", title="t", expected="e", actual="a", repro=[], evidence=[], meta=[],
        nonce="nonce-other", cert_serial="", no_upload_device_cert=True, out_path=str(tmp_path / "c.json")
    )
    assert ok is False and err == "ERR_ATTESTATION_NONCE_MISMATCH"

    att["payload"]["nonce"] = "nonce-good"
    att["payload"]["device_sign_public_key_b64"] = "wrong"
    ok, err, payload = operations_service.certify_issue(
        host="h", port=8080, timeout=1, key_path=str(tmp_path / "k.pem"),
        serial="s", issue_id="i", title="t", expected="e", actual="a", repro=[], evidence=[], meta=[],
        nonce="nonce-good", cert_serial="", no_upload_device_cert=True, out_path=str(tmp_path / "c.json")
    )
    assert ok is False and err == "ERR_ATTESTATION_DEVICE_KEY_MISMATCH"


def test_certify_issue_signature_verify_failure(monkeypatch, tmp_path):
    state = _base_state()
    att = _att_for_state(state, "n")

    def fake_get_json(url: str, timeout: int):
        return state if url.endswith("/api/v0/config/state") else att

    monkeypatch.setattr(operations_service, "base_url", lambda **k: "http://h:8080")
    monkeypatch.setattr(operations_service, "get_json", fake_get_json)
    monkeypatch.setattr(operations_service, "ed25519_fp_hex_from_private_key", lambda p: state["admin_fingerprint_hex"])

    class BadPub:
        def verify(self, *a, **k):
            raise ValueError("bad sig")

    monkeypatch.setattr(operations_service.ed25519.Ed25519PublicKey, "from_public_bytes", lambda b: BadPub())

    ok, err, payload = operations_service.certify_issue(
        host="h", port=8080, timeout=1, key_path=str(tmp_path / "k.pem"),
        serial="s", issue_id="i", title="t", expected="e", actual="a", repro=[], evidence=[], meta=[],
        nonce="n", cert_serial="", no_upload_device_cert=True, out_path=str(tmp_path / "c.json")
    )
    assert ok is False and err == "ERR_ATTESTATION_SIG_VERIFY"


def test_certify_issue_success_and_upload_fail(monkeypatch, tmp_path):
    key_path = tmp_path / "k.pem"
    key_path.write_bytes(b"KEY")
    state = _base_state()

    class GoodPub:
        def verify(self, *a, **k):
            return None

    monkeypatch.setattr(operations_service.ed25519.Ed25519PublicKey, "from_public_bytes", lambda b: GoodPub())

    def fake_get_json(url: str, timeout: int):
        return state if url.endswith("/api/v0/config/state") else _att_for_state(state, "n")

    monkeypatch.setattr(operations_service, "base_url", lambda **k: "http://h:8080")
    monkeypatch.setattr(operations_service, "get_json", fake_get_json)
    monkeypatch.setattr(operations_service, "ed25519_fp_hex_from_private_key", lambda p: state["admin_fingerprint_hex"])
    monkeypatch.setattr(operations_service, "sign_bytes", lambda *a, **k: b"sig")
    monkeypatch.setattr(operations_service, "http_json", lambda *a, **k: {"ok": False, "error": "no"})

    ok, err, payload = operations_service.certify_issue(
        host="h", port=8080, timeout=1, key_path=str(key_path),
        serial="s", issue_id="i", title="t", expected="e", actual="a", repro=["r"], evidence=["x"], meta=["k=v"],
        nonce="n", cert_serial="", no_upload_device_cert=False, out_path=str(tmp_path / "cert.json")
    )
    assert ok is False and err == "ERR_DEVICE_CERT_UPLOAD"

    ok, err, payload = operations_service.certify_issue(
        host="h", port=8080, timeout=1, key_path=str(key_path),
        serial="s", issue_id="i", title="t", expected="e", actual="a", repro=["r"], evidence=["x"], meta=["k=v"],
        nonce="n", cert_serial="", no_upload_device_cert=True, out_path=str(tmp_path / "cert-ok.json")
    )
    assert ok is True and err is None
    assert Path(tmp_path / "cert-ok.json").exists()


def test_verify_certification_round_trip(monkeypatch, tmp_path):
    payload = {"x": 1}
    payload_raw = json.dumps(payload).encode("utf-8")
    cert = {
        "payload_b64": base64.b64encode(payload_raw).decode("ascii"),
        "signature_b64": base64.b64encode(b"sig").decode("ascii"),
    }
    in_path = tmp_path / "cert.json"
    in_path.write_text(json.dumps(cert))
    key_path = tmp_path / "pub.pem"
    key_path.write_bytes(b"PEM")

    class Pub:
        def verify(self, sig, raw):
            assert sig == b"sig"
            assert raw == payload_raw

    monkeypatch.setattr(operations_service, "public_key_from_pem_bytes", lambda b: Pub())

    ok, out = operations_service.verify_certification(in_path=str(in_path), key_path=str(key_path))
    assert ok is True
    assert out["payload"] == payload


def _make_basic_azt_with_encrypted_next_header(next_header_ct: bytes = b"CT", payload: bytes = b"PAYLOAD") -> bytes:
    plain = {
        "next_header_wrapped_key_b64": base64.b64encode(b"WRAPPED").decode("ascii"),
        "next_header_nonce_b64": base64.b64encode(b"N" * 12).decode("ascii"),
        "next_header_tag_b64": base64.b64encode(b"T" * 16).decode("ascii"),
        "next_header_plaintext_hash_alg": "sha256",
        "next_header_plaintext_sha256_b64": base64.b64encode(b"X" * 32).decode("ascii"),
    }
    plain_line = json.dumps(plain).encode("utf-8")
    sig_line = b"sigline"
    out = bytearray()
    out += b"AZT1\n"
    out += plain_line + b"\n"
    out += sig_line + b"\n"
    out += len(next_header_ct).to_bytes(2, "big")
    out += next_header_ct
    out += payload
    return bytes(out)


def test_ota_bundle_post_response_shape_not_ok(monkeypatch, tmp_path):
    bundle = tmp_path / "b.otabundle"
    bundle.write_bytes(b"x")
    monkeypatch.setattr(operations_service, "base_url", lambda **k: "http://h:8080")

    class Resp:
        def read(self):
            return b'{"ok":false,"error":"no"}'
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(operations_service, "urlopen_with_tls", lambda *a, **k: Resp())
    ok, err, payload = operations_service.ota_bundle_post(
        in_path=str(bundle), host="h", port=8080, upgrade_path="/upgrade", timeout=1
    )
    assert ok is False and err == "ERR_OTA_BUNDLE_POST_FAILED"


def test_decode_next_header_already_decoded(tmp_path):
    plain = {
        "next_header_wrapped_key_b64": base64.b64encode(b"WRAPPED").decode("ascii"),
        "next_header_nonce_b64": base64.b64encode(b"N" * 12).decode("ascii"),
        "next_header_tag_b64": base64.b64encode(b"T" * 16).decode("ascii"),
        "next_header_plaintext_hash_alg": "sha256",
        "next_header_plaintext_sha256_b64": base64.b64encode(b"X" * 32).decode("ascii"),
    }
    data = b"AZT1\n" + json.dumps(plain).encode("utf-8") + b"\nSIG\n" + (0xFFFF).to_bytes(2, "big") + b"already\nrest"
    in_path = tmp_path / "in.azt"
    in_path.write_bytes(data)

    ok, payload = operations_service.decode_next_header(
        in_path=str(in_path), key_path=str(tmp_path / "k.pem"), out_path=str(tmp_path / "out.azt")
    )
    assert ok is False and payload["error"] == "ERR_ALREADY_DECODED_NEXT_HEADER"


def test_decode_next_header_truncated_encrypted_header(tmp_path):
    plain = {
        "next_header_wrapped_key_b64": base64.b64encode(b"WRAPPED").decode("ascii"),
        "next_header_nonce_b64": base64.b64encode(b"N" * 12).decode("ascii"),
        "next_header_tag_b64": base64.b64encode(b"T" * 16).decode("ascii"),
        "next_header_plaintext_hash_alg": "sha256",
        "next_header_plaintext_sha256_b64": base64.b64encode(b"X" * 32).decode("ascii"),
    }
    # Declares encrypted header len=10 but only supplies 2 bytes.
    data = b"AZT1\n" + json.dumps(plain).encode("utf-8") + b"\nSIG\n" + (10).to_bytes(2, "big") + b"AB"
    in_path = tmp_path / "in.azt"
    in_path.write_bytes(data)
    ok, payload = operations_service.decode_next_header(
        in_path=str(in_path), key_path=str(tmp_path / "k.pem"), out_path=str(tmp_path / "out.azt")
    )
    assert ok is False and payload["error"] == "ERR_ENC_HEADER_TRUNCATED"


def test_decode_next_header_hash_alg_and_hash_mismatch(monkeypatch, tmp_path):
    data = _make_basic_azt_with_encrypted_next_header(next_header_ct=b"CT")
    in_path = tmp_path / "in.azt"
    in_path.write_bytes(data)

    class FakePriv:
        def decrypt(self, wrapped, padding):
            return b"K" * 16

    class FakeAES:
        def __init__(self, key):
            pass
        def decrypt(self, nonce, data, aad):
            return b"plain-next-header"

    monkeypatch.setattr(operations_service, "load_private_key_auto", lambda *a, **k: FakePriv())
    monkeypatch.setattr("cryptography.hazmat.primitives.ciphers.aead.AESGCM", FakeAES)

    # First force bad hash alg.
    plain = json.loads(data.split(b"\n", 2)[1].decode("utf-8"))
    plain["next_header_plaintext_hash_alg"] = "md5"
    bad_alg_data = b"AZT1\n" + json.dumps(plain).encode("utf-8") + b"\nSIG\n\x00\x02CTPAYLOAD"
    in_path.write_bytes(bad_alg_data)
    ok, payload = operations_service.decode_next_header(
        in_path=str(in_path), key_path=str(tmp_path / "k.pem"), out_path=str(tmp_path / "out.azt")
    )
    assert ok is False and payload["error"] == "ERR_PLAIN_HASH_ALG"

    # Then sha256 alg but mismatched hash.
    plain["next_header_plaintext_hash_alg"] = "sha256"
    plain["next_header_plaintext_sha256_b64"] = base64.b64encode(b"Z" * 32).decode("ascii")
    bad_hash_data = b"AZT1\n" + json.dumps(plain).encode("utf-8") + b"\nSIG\n\x00\x02CTPAYLOAD"
    in_path.write_bytes(bad_hash_data)
    ok, payload = operations_service.decode_next_header(
        in_path=str(in_path), key_path=str(tmp_path / "k.pem"), out_path=str(tmp_path / "out.azt")
    )
    assert ok is False and payload["error"] == "ERR_PLAIN_HASH_MISMATCH"


def test_combine_headers_signature_and_payload_guards(tmp_path):
    # Minimal source with signature line and payload bytes.
    src = b"AZT1\n{}\nSIGLINE\n" + b"BODY"
    in_path = tmp_path / "in.azt"
    in_path.write_bytes(src)

    headers = {
        "schema": "azt.header-separation.v1",
        "plain_header_json_utf8": "{}",
        "plain_header_signature_line_b64": "DIFFERENT",
        "payload_offset_bytes": 0,
        "payload_len_bytes": 1,
        "payload_sha256_hex": "00",
        "next_header_plaintext_hash_alg": "sha256",
        "next_header_plaintext_sha256_b64": base64.b64encode(b"X" * 32).decode("ascii"),
    }
    hp = tmp_path / "h.json"
    hp.write_text(json.dumps(headers))

    ok, payload = operations_service.combine_headers(
        in_path=str(in_path), headers_path=str(hp), decoded_next_header_path="", out_path=str(tmp_path / "out.azt")
    )
    assert ok is False and payload["error"] == "ERR_SIGNATURE_LINE_MISMATCH"

    headers["plain_header_signature_line_b64"] = "SIGLINE"
    headers["payload_offset_bytes"] = 999
    hp.write_text(json.dumps(headers))
    ok, payload = operations_service.combine_headers(
        in_path=str(in_path), headers_path=str(hp), decoded_next_header_path="", out_path=str(tmp_path / "out.azt")
    )
    assert ok is False and payload["error"] == "ERR_INPUT_PAYLOAD_RANGE"


def test_decode_next_header_detached_mode_errors(tmp_path):
    in_path = tmp_path / "req.json"

    # Not encrypted mode
    in_path.write_text(json.dumps({"schema": "azt.header-separation.v1", "next_header_mode": "plaintext"}))
    ok, payload = operations_service.decode_next_header(
        in_path=str(in_path), key_path=str(tmp_path / "k.pem"), out_path=str(tmp_path / "out.azt")
    )
    assert ok is False and payload["error"] == "ERR_DETACHED_MODE"

    # Missing plain header
    in_path.write_text(json.dumps({"schema": "azt.header-separation.v1", "next_header_mode": "encrypted"}))
    ok, payload = operations_service.decode_next_header(
        in_path=str(in_path), key_path=str(tmp_path / "k.pem"), out_path=str(tmp_path / "out.azt")
    )
    assert ok is False and payload["error"] == "ERR_DETACHED_PLAIN_HEADER"

    # Missing ciphertext
    in_path.write_text(json.dumps({
        "schema": "azt.header-separation.v1",
        "next_header_mode": "encrypted",
        "plain_header_json_utf8": json.dumps({"next_header_wrapped_key_b64": "QQ==", "next_header_nonce_b64": "QQ==", "next_header_tag_b64": "QQ==", "next_header_plaintext_hash_alg": "sha256", "next_header_plaintext_sha256_b64": "QQ=="}),
    }))
    ok, payload = operations_service.decode_next_header(
        in_path=str(in_path), key_path=str(tmp_path / "k.pem"), out_path=str(tmp_path / "out.azt")
    )
    assert ok is False and payload["error"] == "ERR_DETACHED_CIPHERTEXT"


def test_decode_next_header_detached_success(monkeypatch, tmp_path):
    next_header_pt = b'{"ok":true}'
    plain = {
        "next_header_wrapped_key_b64": base64.b64encode(b"WRAPPED").decode("ascii"),
        "next_header_nonce_b64": base64.b64encode(b"N" * 12).decode("ascii"),
        "next_header_tag_b64": base64.b64encode(b"T" * 16).decode("ascii"),
        "next_header_plaintext_hash_alg": "sha256",
        "next_header_plaintext_sha256_b64": base64.b64encode(__import__("hashlib").sha256(next_header_pt).digest()).decode("ascii"),
    }
    req = {
        "schema": "azt.header-separation.v1",
        "next_header_mode": "encrypted",
        "plain_header_json_utf8": json.dumps(plain),
        "next_header_ciphertext_b64": base64.b64encode(b"CT").decode("ascii"),
    }
    in_path = tmp_path / "req.json"
    in_path.write_text(json.dumps(req))

    class FakePriv:
        def decrypt(self, wrapped, padding):
            return b"K" * 16

    class FakeAES:
        def __init__(self, key):
            pass
        def decrypt(self, nonce, data, aad):
            return next_header_pt

    monkeypatch.setattr(operations_service, "load_private_key_auto", lambda *a, **k: FakePriv())
    monkeypatch.setattr("cryptography.hazmat.primitives.ciphers.aead.AESGCM", FakeAES)

    decoded_out = tmp_path / "decoded_next_header.json"
    ok, payload = operations_service.decode_next_header(
        in_path=str(in_path), key_path=str(tmp_path / "k.pem"), out_path=str(tmp_path / "ignored.azt"), out_decoded_next_header_path=str(decoded_out)
    )
    assert ok is True
    assert payload["input_mode"] == "request"
    assert decoded_out.exists()


def test_combine_headers_more_guards_and_success(tmp_path):
    payload = b"PAYLOAD"
    src = b"AZT1\n{}\nSIGLINE\n" + payload
    in_path = tmp_path / "in.azt"
    in_path.write_bytes(src)

    next_header = b'{"nh":1}'
    plain = {
        "next_header_plaintext_hash_alg": "sha256",
        "next_header_plaintext_sha256_b64": base64.b64encode(__import__("hashlib").sha256(next_header).digest()).decode("ascii"),
    }

    headers = {
        "schema": "azt.header-separation.v1",
        "plain_header_json_utf8": json.dumps(plain),
        "plain_header_signature_line_b64": "SIGLINE",
        "payload_offset_bytes": len(b"AZT1\n{}\nSIGLINE\n"),
        "payload_len_bytes": len(payload),
        "payload_sha256_hex": __import__("hashlib").sha256(payload).hexdigest(),
    }
    hp = tmp_path / "h.json"

    # payload mismatch
    bad = dict(headers)
    bad["payload_sha256_hex"] = "00"
    hp.write_text(json.dumps(bad))
    ok, out = operations_service.combine_headers(
        in_path=str(in_path), headers_path=str(hp), decoded_next_header_path="", out_path=str(tmp_path / "o1.azt")
    )
    assert ok is False and out["error"] == "ERR_INPUT_PAYLOAD_MISMATCH"

    # decoded header required
    bad = dict(headers)
    bad.pop("next_header_plaintext_json_utf8", None)
    hp.write_text(json.dumps(bad))
    ok, out = operations_service.combine_headers(
        in_path=str(in_path), headers_path=str(hp), decoded_next_header_path="", out_path=str(tmp_path / "o2.azt")
    )
    assert ok is False and out["error"] == "ERR_DECODED_NEXT_HEADER_REQUIRED"

    # bad hash alg
    bad = dict(headers)
    bad["next_header_plaintext_json_utf8"] = next_header.decode("utf-8")
    plain_bad_alg = dict(plain)
    plain_bad_alg["next_header_plaintext_hash_alg"] = "md5"
    bad["plain_header_json_utf8"] = json.dumps(plain_bad_alg)
    hp.write_text(json.dumps(bad))
    ok, out = operations_service.combine_headers(
        in_path=str(in_path), headers_path=str(hp), decoded_next_header_path="", out_path=str(tmp_path / "o3.azt")
    )
    assert ok is False and out["error"] == "ERR_PLAIN_HASH_ALG"

    # missing hash field
    plain_missing = dict(plain)
    plain_missing.pop("next_header_plaintext_sha256_b64")
    bad["plain_header_json_utf8"] = json.dumps(plain_missing)
    hp.write_text(json.dumps(bad))
    ok, out = operations_service.combine_headers(
        in_path=str(in_path), headers_path=str(hp), decoded_next_header_path="", out_path=str(tmp_path / "o4.azt")
    )
    assert ok is False and out["error"] == "ERR_PLAIN_HASH_FIELD"

    # hash mismatch
    plain_mismatch = dict(plain)
    plain_mismatch["next_header_plaintext_sha256_b64"] = base64.b64encode(b"X" * 32).decode("ascii")
    bad["plain_header_json_utf8"] = json.dumps(plain_mismatch)
    hp.write_text(json.dumps(bad))
    ok, out = operations_service.combine_headers(
        in_path=str(in_path), headers_path=str(hp), decoded_next_header_path="", out_path=str(tmp_path / "o5.azt")
    )
    assert ok is False and out["error"] == "ERR_PLAIN_HASH_MISMATCH"

    # success path
    good = dict(headers)
    good["next_header_plaintext_json_utf8"] = next_header.decode("utf-8")
    hp.write_text(json.dumps(good))
    outp = tmp_path / "ok.azt"
    ok, out = operations_service.combine_headers(
        in_path=str(in_path), headers_path=str(hp), decoded_next_header_path="", out_path=str(outp)
    )
    assert ok is True and outp.exists()
