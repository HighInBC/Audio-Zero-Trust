from __future__ import annotations

import base64
import json
import time
from datetime import datetime, timezone
from pathlib import Path
import os

from cryptography.hazmat.primitives import serialization


from tools.azt_client.crypto import ed25519_fp_hex_from_private_key, load_private_key_auto
from tools.azt_client.http import get_json
from tools.azt_sdk.services.attestation_service import verify_attestation
from tools.azt_sdk.services.device_service import certificate_post, state_get
from tools.azt_sdk.services.url_service import base_url


def _listener_value(obj: dict, listener_key: str, recording_key: str):
    return obj.get(listener_key) if obj.get(listener_key) not in (None, "") else obj.get(recording_key)


def _validate_attestation(*, att: dict, state: dict, host: str, port: int, attestation_max_age_s: int) -> tuple[bool, str | None, dict]:
    now_s = int(time.time())
    issued_at = int(att.get("issued_at_epoch_s") or 0)
    age = now_s - issued_at
    if issued_at <= 0 or age < 0 or age > int(attestation_max_age_s):
        return False, "ATTESTATION_STALE", {"age_s": age, "max_age_s": int(attestation_max_age_s)}

    if str(att.get("host")) != str(host) or int(att.get("port") or 0) != int(port):
        return False, "ATTESTATION_TARGET_MISMATCH", {"attestation_host": att.get("host"), "attestation_port": att.get("port")}

    if not bool(att.get("schema_ok")) or not bool(att.get("sig_ok")):
        return False, "ATTESTATION_NOT_VERIFIED", {"schema_ok": att.get("schema_ok"), "sig_ok": att.get("sig_ok"), "sig_detail": att.get("sig_detail")}

    if str(att.get("admin_fingerprint_hex") or "") != str(state.get("admin_fingerprint_hex") or ""):
        return False, "ATTESTATION_STATE_MISMATCH", {"attestation_admin_fp": att.get("admin_fingerprint_hex"), "state_admin_fp": state.get("admin_fingerprint_hex")}

    att_chip = str(att.get("device_chip_id_hex") or "")
    st_chip = str(state.get("device_chip_id_hex") or "")
    if att_chip != st_chip:
        return False, "ATTESTATION_CHIP_ID_MISMATCH", {"attestation_chip_id": att_chip, "state_chip_id": st_chip}

    att_listener_pub = str(_listener_value(att, "listener_public_key_pem", "recording_public_key_pem") or "")
    st_listener_pub = str(_listener_value(state, "listener_public_key_pem", "recording_public_key_pem") or "")
    if att_listener_pub != st_listener_pub:
        return False, "ATTESTATION_LISTENER_KEY_MISMATCH", {"attestation_listener_public_key_pem": att_listener_pub, "state_listener_public_key_pem": st_listener_pub}

    att_listener_fp = str(_listener_value(att, "listener_fingerprint_hex", "recording_fingerprint_hex") or "")
    st_listener_fp = str(_listener_value(state, "listener_fingerprint_hex", "recording_fingerprint_hex") or "")
    if att_listener_fp != st_listener_fp:
        return False, "ATTESTATION_LISTENER_FP_MISMATCH", {"attestation_listener_fingerprint_hex": att_listener_fp, "state_listener_fingerprint_hex": st_listener_fp}

    return True, None, {}


def revoke_certificate(*, host: str, port: int, timeout: int, key_path: str, cert_serial: str = "") -> tuple[bool, str | None, dict]:
    b = base_url(host=host, port=port, scheme=os.getenv("AZT_SCHEME", "auto"))
    state = state_get(host=host, port=port, timeout=timeout)
    if not bool(state.get("ok")):
        return False, "STATE_GET_FAILED", {"state": state}

    signer_fp = ed25519_fp_hex_from_private_key(Path(key_path))
    state_admin_fp = str(state.get("admin_fingerprint_hex") or "")
    if signer_fp != state_admin_fp:
        return False, "KEY_OWNERSHIP_MISMATCH", {"key_fingerprint_hex": signer_fp, "state_admin_fingerprint_hex": state_admin_fp}

    target_serial = (cert_serial or "").strip() or str(state.get("device_certificate_serial") or "")

    cert_challenge = get_json(f"{b}/api/v0/device/certificate/challenge", timeout=timeout)
    if not bool(cert_challenge.get("ok")):
        return False, "CERTIFICATE_CHALLENGE_FAILED", {"challenge_response": cert_challenge}
    cert_nonce = str(cert_challenge.get("nonce") or "")
    if not cert_nonce:
        return False, "CERTIFICATE_CHALLENGE_FAILED", {"detail": "missing nonce in challenge response"}

    payload = {
        "certificate_version": 1,
        "certificate_type": "device_key_revocation",
        "admin_signer_fingerprint_hex": state_admin_fp,
        "certificate_serial": target_serial,
        "nonce": cert_nonce,
        "issued_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "signature_algorithm": "ed25519",
    }
    payload_raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    priv = load_private_key_auto(Path(key_path), purpose=str(key_path))
    sig = priv.sign(payload_raw)
    cert_doc = {
        "certificate_payload_b64": base64.b64encode(payload_raw).decode("ascii"),
        "signature_algorithm": "ed25519",
        "signature_b64": base64.b64encode(sig).decode("ascii"),
    }

    post_res = certificate_post(host=host, port=port, timeout=timeout, payload=cert_doc)
    if not bool(post_res.get("ok")):
        return False, "CERTIFICATE_REVOKE_FAILED", {"post_response": post_res}

    return True, None, {
        "revoked": True,
        "certificate_serial": target_serial,
        "nonce": cert_nonce,
        "post_response": post_res,
    }


def issue_certificate(*, host: str, port: int, timeout: int, key_path: str, attestation_path: str | None, attestation_max_age_s: int, cert_serial: str, valid_until_utc: str, auto_record: bool = False, auto_decode: bool = False, out_path: str | None = None) -> tuple[bool, str | None, dict]:
    b = base_url(host=host, port=port, scheme=os.getenv("AZT_SCHEME", "auto"))
    state = get_json(f"{b}/api/v0/config/state", timeout=timeout)
    if not bool(state.get("ok")):
        return False, "STATE_GET_FAILED", {"state": state}

    att_source = "provided"
    if attestation_path:
        att = json.loads(Path(attestation_path).read_text())
    else:
        att_source = "auto"
        nonce = f"cert-{int(time.time())}"
        ok_att, payload_att = verify_attestation(host=host, port=port, nonce=nonce, timeout=timeout)
        if not ok_att:
            return False, "ATTESTATION_VERIFY_FAILED", payload_att
        att = payload_att.get("attestation_artifact") or {}

    ok_att, err_att, detail_att = _validate_attestation(
        att=att,
        state=state,
        host=host,
        port=port,
        attestation_max_age_s=attestation_max_age_s,
    )
    if not ok_att:
        return False, err_att, detail_att

    signer_fp = ed25519_fp_hex_from_private_key(Path(key_path))
    if signer_fp != str(state.get("admin_fingerprint_hex") or ""):
        return False, "KEY_OWNERSHIP_MISMATCH", {"key_fingerprint_hex": signer_fp, "state_admin_fingerprint_hex": state.get("admin_fingerprint_hex")}

    issued_at_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    authorized_consumers: list[str] = []
    if auto_record:
        authorized_consumers.append("auto-record")
    if auto_decode:
        authorized_consumers.append("auto-decode")

    cert_challenge = get_json(f"{b}/api/v0/device/certificate/challenge", timeout=timeout)
    if not bool(cert_challenge.get("ok")):
        return False, "CERTIFICATE_CHALLENGE_FAILED", {"challenge_response": cert_challenge}
    cert_nonce = str(cert_challenge.get("nonce") or "")
    if not cert_nonce:
        return False, "CERTIFICATE_CHALLENGE_FAILED", {"detail": "missing nonce in challenge response"}

    payload = {
        "certificate_version": 1,
        "certificate_type": "device_key_binding",
        "device_sign_public_key_b64": state.get("device_sign_public_key_b64", ""),
        "device_sign_fingerprint_hex": state.get("device_sign_fingerprint_hex", ""),
        "device_chip_id_hex": state.get("device_chip_id_hex", ""),
        "listener_public_key_pem": _listener_value(state, "listener_public_key_pem", "recording_public_key_pem") or "",
        "listener_fingerprint_hex": _listener_value(state, "listener_fingerprint_hex", "recording_fingerprint_hex") or "",
        # Backward-compat aliases
        "recording_public_key_pem": _listener_value(state, "listener_public_key_pem", "recording_public_key_pem") or "",
        "recording_fingerprint_hex": _listener_value(state, "listener_fingerprint_hex", "recording_fingerprint_hex") or "",
        "admin_signer_fingerprint_hex": state.get("admin_fingerprint_hex", ""),
        "authorized_consumers": authorized_consumers,
        "issued_at_utc": issued_at_utc,
        "valid_until_utc": valid_until_utc,
        "certificate_serial": cert_serial,
        "nonce": cert_nonce,
        "signature_algorithm": "ed25519",
    }
    payload_raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    priv = load_private_key_auto(Path(key_path), purpose=str(key_path))
    sig = priv.sign(payload_raw)
    cert_doc = {
        "certificate_payload_b64": base64.b64encode(payload_raw).decode("ascii"),
        "signature_algorithm": "ed25519",
        "signature_b64": base64.b64encode(sig).decode("ascii"),
    }

    post_res = None
    # By default auto-post; if --out was provided, keep local artifact only.
    if not out_path:
        post_res = certificate_post(host=host, port=port, timeout=timeout, payload=cert_doc)
        if not bool(post_res.get("ok")):
            return False, "CERTIFICATE_POST_FAILED", {"post_response": post_res}

    return True, None, {
        "certificate": cert_doc,
        "certificate_serial": cert_serial,
        "nonce": cert_nonce,
        "attestation_source": att_source,
        "post_response": post_res,
    }
