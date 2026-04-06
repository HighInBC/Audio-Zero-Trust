from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from tools.azt_sdk.services import provisioning_service


def _write_admin_key(tmp_path: Path) -> Path:
    priv = ed25519.Ed25519PrivateKey.generate()
    pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    p = tmp_path / "private_key.pem"
    p.write_bytes(pem)
    return p


def _base_kwargs(tmp_path: Path) -> dict:
    admin_key = _write_admin_key(tmp_path)

    return dict(
        admin_creds_dir=str(admin_key),
        listener_creds_dir=str(tmp_path),
        identity="id1",
        wifi_ssid="ssid",
        wifi_password="pw",
        authorized_listener_ips=[],
        time_servers=[],
        no_time=False,
        port="/dev/ttyUSB0",
        ip=None,
        baud=115200,
        ip_timeout=1,
        no_auto_ip=True,
        allow_serial_bootstrap=False,
        ota_version_code=None,
        ota_min_version_code=None,
        ota_min_version_code_clear=False,
        ota_signer_public_key_pem="",
        ota_signer_clear=False,
        mdns_enabled=False,
        mdns_hostname="",
        audio_preamp_gain=None,
        audio_adc_gain=None,
        tls_bootstrap=False,
        tls_valid_days=30,
    )


def _patch_common(monkeypatch):
    monkeypatch.setattr(provisioning_service, "load_keypair_from_artifact_dir", lambda p: ("REC_PEM", "REC_FP"))
    monkeypatch.setattr(provisioning_service, "ed25519_public_b64_from_private_key", lambda p: "PUB_B64")
    monkeypatch.setattr(provisioning_service, "ed25519_fp_hex_from_private_key", lambda p: "f" * 64)
    monkeypatch.setattr(provisioning_service, "make_bootstrap", lambda *a, **k: {"config_version": 1, "device_label": "x"})
    monkeypatch.setattr(provisioning_service, "make_signed_config", lambda *a, **k: {"signed": True})


def test_configure_device_invalid_audio_preamp(monkeypatch, tmp_path):
    _patch_common(monkeypatch)
    kwargs = _base_kwargs(tmp_path)
    kwargs["audio_preamp_gain"] = 99
    code, ok, err, payload = provisioning_service.configure_device(**kwargs)
    assert ok is False
    assert err == "INVALID_AUDIO_PREAMP_GAIN"


def test_configure_device_invalid_authorized_listener_ip(monkeypatch, tmp_path):
    _patch_common(monkeypatch)
    kwargs = _base_kwargs(tmp_path)
    kwargs["authorized_listener_ips"] = ["not-an-ip"]
    code, ok, err, payload = provisioning_service.configure_device(**kwargs)
    assert ok is False
    assert err == "INVALID_AUTHORIZED_LISTENER_IP"


def test_configure_device_ota_floor_requires_version(monkeypatch, tmp_path):
    _patch_common(monkeypatch)
    kwargs = _base_kwargs(tmp_path)
    kwargs["ota_min_version_code"] = 5
    code, ok, err, payload = provisioning_service.configure_device(**kwargs)
    assert ok is False
    assert err == "INVALID_OTA_VERSION_CODE"


def test_configure_device_serial_warning_message_shape(monkeypatch, tmp_path):
    _patch_common(monkeypatch)
    kwargs = _base_kwargs(tmp_path)
    kwargs["allow_serial_bootstrap"] = True
    kwargs["no_auto_ip"] = True

    monkeypatch.setattr(provisioning_service, "serial_apply_signed_config", lambda *a, **k: (True, None, "ok"))

    code, ok, err, payload = provisioning_service.configure_device(**kwargs)
    assert code == 0 and ok is True and err is None
    assert isinstance(payload.get("messages"), list)
    assert payload["messages"][0]["level"] == "caution"
