from __future__ import annotations

import base64
import binascii
import json
import time
from urllib.parse import quote
import os

from cryptography.exceptions import InvalidSignature
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
    b = base_url(host=host, port=port, scheme="https")
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
        and payload.get("listener_public_key_pem") == state.get("listener_public_key_pem")
        and payload.get("listener_fingerprint_hex") == state.get("listener_fingerprint_hex")
        and att.get("signature_algorithm") == "ed25519"
        and isinstance(att.get("signature_b64"), str)
    )

    sig_ok = False
    sig_detail = "schema_failed"
    if schema_ok:
        payload_raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")

        try:
            sig_b64 = att["signature_b64"]
            sig = base64.b64decode(sig_b64, validate=True)
        except KeyError:
            sig_detail = "verify_error:signature_missing"
            sig = None
        except (binascii.Error, TypeError, ValueError) as e:
            sig_detail = f"verify_error:signature_invalid_b64:{type(e).__name__}:{e}"
            sig = None
        except Exception as e:
            sig_detail = f"verify_error:signature_unexpected:{type(e).__name__}:{e}"
            sig = None

        pub = None
        if sig is not None:
            try:
                pub_b64 = payload["device_sign_public_key_b64"]
                pub_raw = base64.b64decode(pub_b64, validate=True)
                pub = ed25519.Ed25519PublicKey.from_public_bytes(pub_raw)
            except KeyError:
                sig_detail = "verify_error:public_key_missing"
            except (binascii.Error, TypeError, ValueError) as e:
                sig_detail = f"verify_error:public_key_invalid:{type(e).__name__}:{e}"
            except Exception as e:
                sig_detail = f"verify_error:public_key_unexpected:{type(e).__name__}:{e}"

        if sig is not None and pub is not None:
            try:
                pub.verify(sig, payload_raw)
                sig_ok = True
                sig_detail = "verified"
            except InvalidSignature as e:
                sig_detail = f"verify_error:signature_mismatch:{type(e).__name__}:{e}"
            except Exception as e:
                sig_detail = f"verify_error:signature_unexpected:{type(e).__name__}:{e}"

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
        "listener_public_key_pem": state.get("listener_public_key_pem"),
        "listener_fingerprint_hex": state.get("listener_fingerprint_hex"),
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
