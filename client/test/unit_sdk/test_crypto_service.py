from __future__ import annotations

import json
from pathlib import Path

from tools.azt_sdk.services import crypto_service


def test_create_signing_credentials_respects_explicit_identity_and_kind(monkeypatch, tmp_path):
    key_path = tmp_path / "private_key.pem"
    key_path.write_text("dummy")

    def fake_gen(out_dir: Path, password_protected: bool = False):
        out_dir.mkdir(parents=True, exist_ok=True)
        return "pub", "abc123", key_path

    monkeypatch.setattr(crypto_service, "gen_ed25519_keypair_with_fingerprint", fake_gen)

    out = crypto_service.create_signing_credentials(identity="unit-1", identity_prefix="x", out_dir=str(tmp_path))
    assert out["identity"] == "unit-1"
    assert out["fingerprint"] == "abc123"
    assert out["private_key"] == str(key_path)
    assert out["kind"] == "signing"


def test_create_decoding_credentials_uses_prefix_when_identity_missing(monkeypatch, tmp_path):
    key_path = tmp_path / "dec_private_key.pem"
    key_path.write_text("dummy")
    monkeypatch.setattr(crypto_service.time, "strftime", lambda fmt: "20260101-010101")

    def fake_gen(out_dir: Path, password_protected: bool = False):
        out_dir.mkdir(parents=True, exist_ok=True)
        return "pubpem", "ff00", key_path

    monkeypatch.setattr(crypto_service, "gen_rsa_keypair_with_fingerprint", fake_gen)

    out = crypto_service.create_decoding_credentials(identity=None, identity_prefix="decoder", out_dir=str(tmp_path))
    assert out["identity"] == "decoder-20260101-010101"
    assert out["kind"] == "decoding"


def test_sign_config_file_uses_explicit_fingerprint(monkeypatch, tmp_path):
    unsigned_path = tmp_path / "unsigned.json"
    unsigned_path.write_text(json.dumps({"config_version": 1}))

    key_path = tmp_path / "private_key.pem"
    key_path.write_bytes(b"KEY")

    out_path = tmp_path / "signed" / "config_signed.json"

    monkeypatch.setattr(crypto_service, "make_signed_config", lambda cfg, key_bytes, fp: {"signed": True, "fp": fp, "cfg": cfg})

    out = crypto_service.sign_config_file(
        in_path=str(unsigned_path),
        key_path=str(key_path),
        out_path=str(out_path),
        fingerprint="explicit-fp",
    )

    saved = json.loads(out_path.read_text())
    assert saved["fp"] == "explicit-fp"
    assert out["fingerprint"] == "explicit-fp"


def test_sign_config_file_derives_fingerprint_when_blank(monkeypatch, tmp_path):
    unsigned_path = tmp_path / "unsigned.json"
    unsigned_path.write_text(json.dumps({"config_version": 1}))

    key_path = tmp_path / "private_key.pem"
    key_path.write_bytes(b"KEY")
    out_path = tmp_path / "signed.json"

    monkeypatch.setattr(crypto_service, "ed25519_fp_hex_from_private_key", lambda p: "derived-fp")
    monkeypatch.setattr(crypto_service, "make_signed_config", lambda cfg, key_bytes, fp: {"fp": fp})

    out = crypto_service.sign_config_file(
        in_path=str(unsigned_path),
        key_path=str(key_path),
        out_path=str(out_path),
        fingerprint="  ",
    )
    assert out["fingerprint"] == "derived-fp"


def test_key_fingerprint_from_private_key_passthrough(monkeypatch, tmp_path):
    key_path = tmp_path / "k.pem"
    key_path.write_text("x")
    monkeypatch.setattr(crypto_service, "ed25519_fp_hex_from_private_key", lambda p: "fpz")
    assert crypto_service.key_fingerprint_from_private_key(key_path=str(key_path)) == "fpz"
