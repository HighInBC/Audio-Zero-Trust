from __future__ import annotations

import ipaddress
import json
import time
from pathlib import Path
import os

from tools.azt_client.config import make_signed_config
from tools.azt_client.crypto import ed25519_public_b64_from_private_key, ed25519_fp_hex_from_private_key, load_private_key_auto
from tools.azt_client.http import http_json
from tools.azt_sdk.services.url_service import base_url
from tools.azt_sdk.services.tls_service import tls_material_generate
from tools.provision_unit import (
    detect_device_ip_from_serial,
    load_keypair_from_artifact_dir,
    make_bootstrap,
    serial_apply_signed_config,
)


def configure_device(
    *,
    admin_creds_dir: str,
    recorder_creds_dir: str | None,
    identity: str,
    wifi_ssid: str,
    wifi_password: str,
    authorized_listener_ips: list[str],
    time_servers: list[str],
    no_time: bool,
    port: str,
    ip: str | None,
    baud: int,
    ip_timeout: int,
    no_auto_ip: bool,
    allow_serial_bootstrap: bool,
    ota_version_code: int | None,
    ota_min_version_code: int | None,
    ota_min_version_code_clear: bool,
    ota_signer_public_key_pem: str,
    ota_signer_clear: bool,
    mdns_enabled: bool,
    mdns_hostname: str,
    audio_preamp_gain: int | None,
    audio_adc_gain: int | None,
    tls_bootstrap: bool,
    tls_valid_days: int,
) -> tuple[int, bool, str | None, dict]:
    admin_input = Path(admin_creds_dir)
    recorder_input = Path(recorder_creds_dir) if recorder_creds_dir else admin_input

    admin_dir = admin_input if admin_input.is_dir() else admin_input.parent
    recorder_dir = recorder_input if recorder_input.is_dir() else recorder_input.parent

    rec_pub_pem, rec_fp = load_keypair_from_artifact_dir(recorder_input)

    if admin_input.is_file():
        priv_path = admin_input
    else:
        priv_path = admin_input / "private_key.pem"
        if not priv_path.exists():
            priv_path = admin_input / "admin_private_key.pem"
    priv_pem = priv_path.read_bytes()

    # Admin credentials are Ed25519 signing credentials.
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    try:
        admin_priv = load_private_key_auto(priv_pem, purpose=str(priv_path))
        if not isinstance(admin_priv, ed25519.Ed25519PrivateKey):
            raise ValueError("admin signing key must be Ed25519")
    except Exception as e:
        raise ValueError("admin creds must point to an Ed25519 private key PEM (used to sign config)") from e

    admin_pub_b64 = ed25519_public_b64_from_private_key(priv_path)
    fp = ed25519_fp_hex_from_private_key(priv_path)

    # Input validation for protocol-facing fields.
    ota_signer_public_key_pem = (ota_signer_public_key_pem or "").strip()
    mdns_hostname = (mdns_hostname or "").strip()
    if ota_version_code is not None and ota_version_code < 0:
        return 11, False, "INVALID_OTA_VERSION_CODE", {"detail": ota_version_code}
    if ota_min_version_code is not None and ota_min_version_code < 0:
        return 12, False, "INVALID_OTA_MIN_VERSION_CODE", {"detail": ota_min_version_code}
    if ota_min_version_code is not None and ota_version_code is None:
        return 15, False, "INVALID_OTA_VERSION_CODE", {"detail": "ota_version_code required when ota_min_version_code is set"}
    if ota_min_version_code is not None and ota_min_version_code_clear:
        return 13, False, "INVALID_OTA_MIN_VERSION_CODE_COMBINATION", {"detail": "cannot set and clear OTA floor together"}
    if ota_signer_public_key_pem and ota_signer_clear:
        return 14, False, "INVALID_OTA_SIGNER_COMBINATION", {"detail": "cannot set and clear OTA signer together"}
    if audio_preamp_gain is not None and not (0 <= int(audio_preamp_gain) <= 255):
        return 16, False, "INVALID_AUDIO_PREAMP_GAIN", {"detail": int(audio_preamp_gain)}
    if audio_adc_gain is not None and not (0 <= int(audio_adc_gain) <= 255):
        return 17, False, "INVALID_AUDIO_ADC_GAIN", {"detail": int(audio_adc_gain)}

    for listener_ip in authorized_listener_ips:
        try:
            ipaddress.IPv4Address(listener_ip)
        except Exception:
            return 11, False, "INVALID_AUTHORIZED_LISTENER_IP", {"detail": listener_ip}

    device_ip = ip or None
    detected_ip = None

    # Try to learn device IP before generating TLS cert so SAN can include IP.
    if allow_serial_bootstrap and (not no_auto_ip) and (not device_ip):
        detected_ip = detect_device_ip_from_serial(port, baud=baud, timeout_s=ip_timeout)
        if detected_ip:
            device_ip = detected_ip

    unsigned_cfg = make_bootstrap(identity, admin_pub_b64, fp, wifi_ssid, wifi_password)
    if authorized_listener_ips:
        unsigned_cfg["authorized_listener_ips"] = authorized_listener_ips

    if no_time:
        # Protocol requires a non-empty time object; use local loopback placeholder
        # to avoid external time dependencies while keeping config schema valid.
        resolved_time_servers = ["127.0.0.1"]
    elif time_servers:
        resolved_time_servers = time_servers
    else:
        resolved_time_servers = ["time.nist.gov"]

    unsigned_cfg["time"] = {"servers": resolved_time_servers}
    unsigned_cfg["recording_key"] = {
        "alg": "rsa-oaep-sha256",
        "public_key_pem": rec_pub_pem,
        "fingerprint_alg": "sha256-spki-der",
        "fingerprint_hex": rec_fp,
    }

    if audio_preamp_gain is not None or audio_adc_gain is not None:
        audio_cfg = unsigned_cfg.get("audio") if isinstance(unsigned_cfg.get("audio"), dict) else {}
        if audio_preamp_gain is not None:
            audio_cfg["preamp_gain"] = int(audio_preamp_gain)
        if audio_adc_gain is not None:
            audio_cfg["adc_gain"] = int(audio_adc_gain)
        unsigned_cfg["audio"] = audio_cfg

    if mdns_enabled or mdns_hostname:
        unsigned_cfg["mdns"] = {
            "enabled": bool(mdns_enabled),
            "hostname": mdns_hostname,
        }

    tls_material = None
    tls_deferred_until_ip = False
    if bool(tls_bootstrap):
        san_hosts: list[str] = []
        # Include IP SAN when known; otherwise defer TLS apply to phase-2 after IP discovery.
        if device_ip and str(device_ip).strip():
            san_hosts.append(str(device_ip).strip())
        if mdns_hostname:
            san_hosts.append(mdns_hostname)
            if not mdns_hostname.endswith(".local"):
                san_hosts.append(f"{mdns_hostname}.local")

        if not san_hosts or (device_ip is None):
            tls_deferred_until_ip = True
        else:
            tls_material = tls_material_generate(
                cert_serial="",
                valid_days=int(max(1, tls_valid_days)),
                san_hosts=san_hosts,
            )
            unsigned_cfg["tls"] = {
                "tls_certificate_serial": tls_material["tls_certificate_serial"],
                "tls_server_certificate_pem": tls_material["tls_server_certificate_pem"],
                "tls_server_private_key_pem": tls_material["tls_server_private_key_pem"],
                "tls_ca_certificate_pem": tls_material["tls_ca_certificate_pem"],
                "tls_san_hosts": tls_material.get("san_hosts") or [],
            }

    if ota_version_code is not None:
        unsigned_cfg["ota_version_code"] = int(ota_version_code)
    if ota_min_version_code is not None:
        unsigned_cfg["ota_min_allowed_version_code"] = int(ota_min_version_code)
    if ota_min_version_code_clear:
        unsigned_cfg["ota_min_allowed_version_code_clear"] = True
    if ota_signer_public_key_pem:
        unsigned_cfg["ota_signer_public_key_pem"] = ota_signer_public_key_pem
    if ota_signer_clear:
        unsigned_cfg["ota_signer_clear"] = True

    signed = make_signed_config(unsigned_cfg, priv_pem, fp)
    (admin_dir / "config_bootstrap.json").write_text(json.dumps(unsigned_cfg, indent=2))
    (admin_dir / "config_signed.json").write_text(json.dumps(signed, indent=2))

    state0 = None
    state0_err = None
    if device_ip:
        base = base_url(host=device_ip, port=8080, scheme=os.getenv("AZT_SCHEME", "auto"))
        try:
            state0 = http_json("GET", base + "/api/v0/config/state")
        except Exception as e:
            state0_err = str(e)

    serial_required = (
        (ota_min_version_code is not None)
        or bool(ota_min_version_code_clear)
        or bool(ota_signer_public_key_pem)
        or bool(ota_signer_clear)
    )

    common = {
        "ip": device_ip,
        "admin_creds_dir": str(admin_dir),
        "recorder_creds_dir": str(recorder_dir),
        "admin_fingerprint_hex": fp,
        "recorder_fingerprint_hex": rec_fp,
        "authorized_listener_ips": authorized_listener_ips,
        "time_servers": resolved_time_servers,
        "no_time": no_time,
        "ota_version_code": ota_version_code,
        "ota_min_version_code": ota_min_version_code,
        "ota_min_version_code_clear": ota_min_version_code_clear,
        "ota_signer_override_set": bool(ota_signer_public_key_pem),
        "ota_signer_clear": bool(ota_signer_clear),
        "mdns_enabled": bool(mdns_enabled),
        "mdns_hostname": mdns_hostname,
        "audio_preamp_gain": (int(audio_preamp_gain) if audio_preamp_gain is not None else None),
        "audio_adc_gain": (int(audio_adc_gain) if audio_adc_gain is not None else None),
        "tls_bootstrap_requested": bool(tls_bootstrap),
        "tls_deferred_until_ip": bool(tls_deferred_until_ip),
    }
    if tls_material:
        common["tls_certificate_serial"] = tls_material.get("tls_certificate_serial")
        common["tls_ca_fingerprint_hex"] = tls_material.get("ca_fingerprint_hex")
        common["tls_san_hosts"] = tls_material.get("san_hosts") or []
    if detected_ip:
        common["ip_detected"] = detected_ip
    if state0_err:
        common["state_probe_error"] = state0_err

    if state0 is None or serial_required:
        if not allow_serial_bootstrap:
            return 9, False, ("SERIAL_REQUIRED" if serial_required else "HTTP_UNREACHABLE"), {
                **common,
                "detail": ("serial bootstrap required for OTA floor controls" if serial_required else "HTTP state unreachable and serial bootstrap not allowed"),
            }

        ok_serial, ip_from_serial = serial_apply_signed_config(
            port,
            signed,
            baud=baud,
            timeout_s=max(20, int(ip_timeout)),
        )
        if not ok_serial:
            return 7, False, "SERIAL_BOOTSTRAP_FAILED", common

        if ip_from_serial:
            device_ip = ip_from_serial
            common["ip"] = device_ip
            common["ip_detected"] = ip_from_serial

        if not device_ip:
            # Serial apply succeeded; do not fail purely because IP extraction missed a log format variant.
            return 0, True, None, {
                **common,
                "path": "serial-bootstrap",
                "state_after": None,
                "postcheck_warning": "serial apply succeeded but device IP was not parsed from serial output",
                "postcheck_error": "IP_NOT_DETECTED_AFTER_SERIAL_BOOTSTRAP",
                "detail": "device IP not detected from serial output; provide --ip for deterministic postcheck",
            }

        # Phase 2: if TLS was deferred until IP was known, issue TLS material now and apply signed config again.
        if bool(tls_bootstrap) and tls_deferred_until_ip:
            san_hosts: list[str] = [str(device_ip)]
            if mdns_hostname:
                san_hosts.append(mdns_hostname)
                if not mdns_hostname.endswith(".local"):
                    san_hosts.append(f"{mdns_hostname}.local")
            tls_material = tls_material_generate(
                cert_serial="",
                valid_days=int(max(1, tls_valid_days)),
                san_hosts=san_hosts,
            )
            unsigned_cfg["tls"] = {
                "tls_certificate_serial": tls_material["tls_certificate_serial"],
                "tls_server_certificate_pem": tls_material["tls_server_certificate_pem"],
                "tls_server_private_key_pem": tls_material["tls_server_private_key_pem"],
                "tls_ca_certificate_pem": tls_material["tls_ca_certificate_pem"],
                "tls_san_hosts": tls_material.get("san_hosts") or [],
            }
            signed_phase2 = make_signed_config(unsigned_cfg, priv_pem, fp)
            (admin_dir / "config_signed.json").write_text(json.dumps(signed_phase2, indent=2))
            ok_phase2, ip_phase2 = serial_apply_signed_config(
                port,
                signed_phase2,
                baud=baud,
                timeout_s=max(20, int(ip_timeout)),
            )
            if not ok_phase2:
                return 10, False, "SERIAL_TLS_PHASE2_FAILED", {**common, "ip": device_ip}
            if ip_phase2:
                device_ip = ip_phase2
                common["ip"] = device_ip
                common["ip_detected"] = ip_phase2
            common["tls_certificate_serial"] = tls_material.get("tls_certificate_serial")
            common["tls_ca_fingerprint_hex"] = tls_material.get("ca_fingerprint_hex")
            common["tls_san_hosts"] = tls_material.get("san_hosts") or []

        time.sleep(1.0)
        # Post-serial liveness check should not depend on AZT_SCHEME auto-selection.
        # Force HTTP bootstrap endpoint here to avoid premature HTTPS-only probes.
        base_after = base_url(host=device_ip, port=8080, scheme="http")

        state1 = None
        postcheck_err = None
        for _ in range(20):
            try:
                st = http_json("GET", f"{base_after}/api/v0/config/state")
                if isinstance(st, dict) and st.get("ok"):
                    state1 = st
                    break
            except Exception as e:
                postcheck_err = str(e)
            time.sleep(1.0)

        if state1 is None:
            # Serial apply already succeeded; avoid hard-failing on transient network/API startup race.
            return 0, True, None, {
                **common,
                "path": "serial-bootstrap",
                "state_after": None,
                "postcheck_warning": "state endpoint unreachable after serial apply",
                "postcheck_error": postcheck_err,
                "postcheck_target": f"{base_after}/api/v0/config/state",
            }

        ok = state1.get("admin_fingerprint_hex") == fp
        return (0 if ok else 6), ok, (None if ok else "POSTCHECK_FP_MISMATCH"), {
            **common,
            "path": "serial-bootstrap",
            "state_after": state1,
        }

    state_name = state0.get("state")
    state_fp = str(state0.get("admin_fingerprint_hex") or "")
    if state_name != "UNSET_ADMIN":
        if state_fp == fp:
            return 0, True, None, {**common, "path": "http-existing", "state": state_name, "state_before": state0}
        return 5, False, "MISSING_ADMIN_KEY_ARTIFACT", {**common, "state": state_name, "fingerprint": state_fp}

    r1 = http_json("POST", base + "/api/v0/config", signed)
    r2 = http_json("POST", base + "/api/v0/config", signed)
    state1 = http_json("GET", base + "/api/v0/config/state")
    ok = state1.get("admin_fingerprint_hex") == fp
    return (0 if ok else 6), ok, (None if ok else "POSTCHECK_FP_MISMATCH"), {
        **common,
        "path": "http",
        "state_after": state1,
        "initial_signed_result": r1,
        "signed_result": r2,
    }
