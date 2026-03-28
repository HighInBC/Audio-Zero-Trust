from __future__ import annotations

import json
from pathlib import Path

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
