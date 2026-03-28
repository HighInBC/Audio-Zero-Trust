from __future__ import annotations

from pathlib import Path

import pytest

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
