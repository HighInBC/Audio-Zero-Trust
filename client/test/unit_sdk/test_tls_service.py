from __future__ import annotations

from pathlib import Path
import urllib.error

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from tools.azt_sdk.services import tls_service


def _patch_pki_paths(monkeypatch, tmp_path):
    pki = tmp_path / "pki"
    monkeypatch.setattr(tls_service, "PKI_DIR", pki)
    monkeypatch.setattr(tls_service, "CA_KEY", pki / "ca_private_key.pem")
    monkeypatch.setattr(tls_service, "CA_CERT", pki / "ca_cert.pem")
    monkeypatch.setattr(tls_service, "TRUSTED_CA_CERT", pki / "trusted_ca_cert.pem")
    return pki


def test_tls_ca_init_creates_materials(monkeypatch, tmp_path):
    _patch_pki_paths(monkeypatch, tmp_path)
    out = tls_service.tls_ca_init(common_name="Test CA", force=False)
    assert out["created"] is True
    assert Path(out["ca_key_path"]).exists()
    assert Path(out["ca_cert_path"]).exists()


def test_tls_ca_init_reuses_existing_without_force(monkeypatch, tmp_path):
    _patch_pki_paths(monkeypatch, tmp_path)
    first = tls_service.tls_ca_init(common_name="Test CA", force=False)
    second = tls_service.tls_ca_init(common_name="Test CA", force=False)
    assert second["created"] is False
    assert second["ca_fingerprint_hex"] == first["ca_fingerprint_hex"]


def test_tls_ca_export_and_import(monkeypatch, tmp_path):
    _patch_pki_paths(monkeypatch, tmp_path)
    tls_service.tls_ca_init(force=True)

    exported = tmp_path / "exported_ca.pem"
    out_exp = tls_service.tls_ca_export(out_path=str(exported))
    assert out_exp["exported"] is True
    assert exported.exists()

    # import into trusted slot
    out_imp = tls_service.tls_ca_import(in_path=str(exported))
    assert out_imp["imported"] is True
    assert Path(out_imp["trusted_ca_cert_path"]).exists()


def test_tls_ca_export_raises_when_no_ca(monkeypatch, tmp_path):
    _patch_pki_paths(monkeypatch, tmp_path)
    with pytest.raises(FileNotFoundError):
        tls_service.tls_ca_export(out_path=str(tmp_path / "x.pem"))


def test_tls_ca_status_reports_active_cert(monkeypatch, tmp_path):
    _patch_pki_paths(monkeypatch, tmp_path)
    tls_service.tls_ca_init(force=True)
    status = tls_service.tls_ca_status()
    assert status["has_ca_cert"] is True
    assert status["active_ca_cert_path"].endswith("ca_cert.pem")


def test_tls_material_generate_returns_san_hosts(monkeypatch, tmp_path):
    _patch_pki_paths(monkeypatch, tmp_path)
    tls_service.tls_ca_init(force=True)
    out = tls_service.tls_material_generate(cert_serial="", valid_days=30, san_hosts=["10.0.0.2", "device.local", "device.local"])
    assert out["tls_certificate_serial"]
    assert "10.0.0.2" in out["san_hosts"]
    assert "device.local" in out["san_hosts"]


def test_load_ca_signer_non_ec_key_raises(monkeypatch, tmp_path):
    _patch_pki_paths(monkeypatch, tmp_path)
    tls_service.tls_ca_init(force=True)

    class NotEcKey:
        pass

    monkeypatch.setattr(tls_service, "load_private_key_auto", lambda *a, **k: NotEcKey())
    with pytest.raises(RuntimeError, match="CA private key is not EC"):
        tls_service._load_ca_signer()


def test_tls_cert_issue_and_install_csr_fail(monkeypatch, tmp_path):
    _patch_pki_paths(monkeypatch, tmp_path)
    tls_service.tls_ca_init(force=True)

    monkeypatch.setattr(tls_service, "base_url", lambda **k: "http://h:8080")
    monkeypatch.setattr(tls_service, "get_json", lambda *a, **k: {"ok": False, "error": "no"})

    with pytest.raises(RuntimeError, match="tls csr fetch failed"):
        tls_service.tls_cert_issue_and_install(
            host="h",
            port=8080,
            timeout=1,
            admin_key_path=str(tmp_path / "admin.pem"),
            cert_serial="c1",
        )


def test_tls_cert_issue_and_install_post_fail(monkeypatch, tmp_path):
    _patch_pki_paths(monkeypatch, tmp_path)
    tls_service.tls_ca_init(force=True)

    priv = ed25519.Ed25519PrivateKey.generate()
    admin_path = tmp_path / "admin.pem"
    admin_path.write_bytes(
        priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    def fake_get_json(url: str, timeout: int):
        if url.endswith("/api/v0/tls/csr"):
            return {
                "ok": True,
                "public_key_pem": "PUB",
                "device_sign_fingerprint_hex": "d" * 64,
                "device_chip_id_hex": "chip1",
            }
        return {"ok": True}

    monkeypatch.setattr(tls_service, "base_url", lambda **k: "http://h:8080")
    monkeypatch.setattr(tls_service, "get_json", fake_get_json)
    monkeypatch.setattr(tls_service, "http_json", lambda *a, **k: {"ok": False})

    with pytest.raises(RuntimeError, match="tls cert post failed"):
        tls_service.tls_cert_issue_and_install(
            host="h",
            port=8080,
            timeout=1,
            admin_key_path=str(admin_path),
            cert_serial="c1",
        )


def test_tls_bootstrap_reboot_path(monkeypatch, tmp_path):
    _patch_pki_paths(monkeypatch, tmp_path)

    # Fake issue step to isolate bootstrap state/reboot flow.
    monkeypatch.setattr(tls_service, "tls_cert_issue_and_install", lambda **k: {"issued": True})
    monkeypatch.setattr(tls_service, "base_url", lambda **k: f"{k.get('scheme','http')}://{k['host']}:{k['port']}")

    priv = ed25519.Ed25519PrivateKey.generate()
    admin_path = tmp_path / "admin.pem"
    admin_path.write_bytes(
        priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    calls = {"n": 0}

    def fake_get_json(url: str, timeout: int):
        calls["n"] += 1
        # First https check fails -> triggers reboot branch.
        if url.startswith("https://") and calls["n"] == 1:
            raise urllib.error.URLError("down")
        if url.endswith("/device/reboot/challenge"):
            return {"ok": True, "nonce": "abc"}
        if url.startswith("https://"):
            return {"ok": True, "state": "ok"}
        return {"ok": True}

    monkeypatch.setattr(tls_service, "get_json", fake_get_json)
    monkeypatch.setattr(tls_service, "http_json", lambda *a, **k: {"ok": True})
    monkeypatch.setattr(tls_service, "ed25519_fp_hex_from_private_key", lambda p: "f" * 64)
    monkeypatch.setattr(tls_service, "load_private_key_auto", lambda p, purpose=None: priv)

    out = tls_service.tls_bootstrap(
        host="h",
        admin_key_path=str(admin_path),
        http_port=8080,
        https_port=8443,
        timeout=1,
        reboot_on_https_failure=True,
        reboot_wait_seconds=1,
    )

    assert out["reboot"]["attempted"] is True
    assert out["https_verify"]["ok"] is True


def test_tls_bootstrap_reboot_challenge_failure(monkeypatch, tmp_path):
    _patch_pki_paths(monkeypatch, tmp_path)
    monkeypatch.setattr(tls_service, "tls_cert_issue_and_install", lambda **k: {"issued": True})
    monkeypatch.setattr(tls_service, "base_url", lambda **k: f"{k.get('scheme','http')}://{k['host']}:{k['port']}")

    priv = ed25519.Ed25519PrivateKey.generate()
    admin_path = tmp_path / "admin.pem"
    admin_path.write_bytes(
        priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    def fake_get_json(url: str, timeout: int):
        if url.startswith("https://"):
            raise urllib.error.URLError("down")
        raise urllib.error.URLError("challenge down")

    monkeypatch.setattr(tls_service, "get_json", fake_get_json)
    monkeypatch.setattr(tls_service, "ed25519_fp_hex_from_private_key", lambda p: "f" * 64)
    monkeypatch.setattr(tls_service, "load_private_key_auto", lambda p, purpose=None: priv)

    out = tls_service.tls_bootstrap(
        host="h",
        admin_key_path=str(admin_path),
        http_port=8080,
        https_port=8443,
        timeout=1,
        reboot_on_https_failure=True,
        reboot_wait_seconds=1,
    )

    assert out["reboot"]["attempted"] is True
    assert out["reboot"]["response"]["error"] == "TLS_BOOTSTRAP_REBOOT_CHALLENGE_FAILED"
