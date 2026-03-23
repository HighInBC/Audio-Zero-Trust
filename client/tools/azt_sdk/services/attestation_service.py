from __future__ import annotations

import base64
import json
import time
from urllib.parse import quote
import os

from cryptography.hazmat.primitives.asymmetric import ed25519

from tools.azt_client.http import get_json
from tools.azt_sdk.services.url_service import base_url


def _nonce_matches(payload_nonce: str, requested_nonce: str) -> bool:
    if payload_nonce == requested_nonce:
        return True
    # Some firmware builds may echo query suffix in nonce field (e.g. "<nonce>?nonce=<nonce>").
    if payload_nonce.startswith(requested_nonce + "?nonce="):
        return True
    return False


def verify_attestation(*, host: str, port: int, nonce: str, timeout: int) -> tuple[bool, dict]:
    b = base_url(host=host, port=port, scheme=os.getenv("AZT_SCHEME", "auto"))
    state = get_json(f"{b}/api/v0/config/state", timeout=timeout)
    att = get_json(
        f"{b}/api/v0/device/attestation?nonce={quote(nonce, safe='')}",
        timeout=timeout,
    )

    payload = att.get("payload") if isinstance(att, dict) else None
    schema_ok = (
        bool(att.get("ok"))
        and isinstance(payload, dict)
        and payload.get("attestation_version") == 1
        and payload.get("attestation_type") == "device_key_ownership"
        and _nonce_matches(str(payload.get("nonce") or ""), nonce)
        and payload.get("device_sign_public_key_b64") == state.get("device_sign_public_key_b64")
        and payload.get("device_sign_fingerprint_hex") == state.get("device_sign_fingerprint_hex")
        and payload.get("device_chip_id_hex") == state.get("device_chip_id_hex")
        and att.get("signature_algorithm") == "ed25519"
        and isinstance(att.get("signature_b64"), str)
    )

    sig_ok = False
    sig_detail = "schema_failed"
    if schema_ok:
        try:
            payload_raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            sig = base64.b64decode(att["signature_b64"], validate=True)
            pub = ed25519.Ed25519PublicKey.from_public_bytes(base64.b64decode(payload["device_sign_public_key_b64"], validate=True))
            pub.verify(sig, payload_raw)
            sig_ok = True
            sig_detail = "verified"
        except Exception as ve:
            sig_detail = f"verify_error:{ve}"

    ok = schema_ok and sig_ok
    artifact = {
        "version": 1,
        "issued_at_epoch_s": int(time.time()),
        "host": host,
        "port": int(port),
        "nonce": nonce,
        "admin_fingerprint_hex": state.get("admin_fingerprint_hex"),
        "device_sign_fingerprint_hex": state.get("device_sign_fingerprint_hex"),
        "device_chip_id_hex": state.get("device_chip_id_hex"),
        "schema_ok": schema_ok,
        "sig_ok": sig_ok,
        "sig_detail": sig_detail,
        "attestation": att,
    }
    return ok, {
        "schema_ok": schema_ok,
        "sig_ok": sig_ok,
        "sig_detail": sig_detail,
        "attestation": att,
        "attestation_artifact": artifact,
    }
