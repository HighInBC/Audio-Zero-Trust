from __future__ import annotations

import base64
import json
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization


from tools.azt_client.crypto import ed25519_fp_hex_from_private_key
from tools.azt_client.http import get_json
from tools.azt_sdk.services.attestation_service import verify_attestation
from tools.azt_sdk.services.device_service import certificate_post


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

    return True, None, {}


def issue_certificate(*, host: str, port: int, timeout: int, key_path: str, attestation_path: str | None, attestation_max_age_s: int, cert_serial: str, valid_from_utc: str, valid_until_utc: str, out_path: str | None = None) -> tuple[bool, str | None, dict]:
    state = get_json(f"http://{host}:{port}/api/v1/config/state", timeout=timeout)
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

    payload = {
        "certificate_version": 1,
        "certificate_type": "device_key_binding",
        "device_sign_public_key_b64": state.get("device_sign_public_key_b64", ""),
        "device_sign_fingerprint_hex": state.get("device_sign_fingerprint_hex", ""),
        "device_chip_id_hex": state.get("device_chip_id_hex", ""),
        "admin_signer_fingerprint_hex": state.get("admin_fingerprint_hex", ""),
        "valid_from_utc": valid_from_utc,
        "valid_until_utc": valid_until_utc,
        "certificate_serial": cert_serial,
        "signature_algorithm": "ed25519",
    }
    payload_raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    priv = serialization.load_pem_private_key(Path(key_path).read_bytes(), password=None)
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
        "attestation_source": att_source,
        "post_response": post_res,
    }
