from __future__ import annotations

import base64
import binascii
import hashlib
import json
import secrets
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote
from urllib.request import Request, urlopen
import urllib.error

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding

from tools.azt_client.config import make_signed_config
from tools.azt_client.crypto import ed25519_fp_hex_from_private_key, load_private_key_auto
from tools.azt_client.http import http_json, get_json, urlopen_with_tls
from tools.azt_sdk.services import build_service
from tools.azt_sdk.services.url_service import base_url
import os


def _error_detail(*, where: str, exc: Exception, url: str | None = None, context: dict | None = None) -> dict:
    out = {
        "where": where,
        "exception_type": type(exc).__name__,
        "message": str(exc),
    }
    if url:
        out["url"] = url
    if context:
        out["context"] = context
    return out


def parse_meta(items: list[str]) -> dict:
    out = {}
    for item in items or []:
        if "=" not in item:
            raise ValueError(f"invalid --meta entry (expected key=value): {item}")
        k, v = item.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def sign_bytes(priv_pem: bytes, payload: bytes) -> bytes:
    priv = load_private_key_auto(priv_pem, purpose="signing key")
    return priv.sign(payload)


def public_key_from_pem_bytes(pem: bytes):
    try:
        priv = load_private_key_auto(pem, purpose="private key")
        return priv.public_key()
    except (ValueError, TypeError):
        return serialization.load_pem_public_key(pem)


def apply_config(*, in_path: str, key_path: str, host: str, port: int, timeout: int, fingerprint: str) -> tuple[bool, dict]:
    unsigned_cfg = json.loads(Path(in_path).read_text())
    keyp = Path(key_path)
    fp = fingerprint.strip() or ed25519_fp_hex_from_private_key(keyp)

    base = base_url(host=host, port=port, scheme="https")
    apply_url = f"{base}/api/v0/config"
    state_url = f"{base}/api/v0/config/state"

    try:
        state_before = get_json(state_url, timeout=timeout)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError, OSError) as e:
        return False, {
            "host": host,
            "port": port,
            "signer_fingerprint_hex": fp,
            "error": "APPLY_CONFIG_STATE_GET_FAILED",
            "detail": _error_detail(where="operations_service.apply_config.state_get_before", exc=e, url=state_url),
        }
    except Exception as e:
        return False, {
            "host": host,
            "port": port,
            "signer_fingerprint_hex": fp,
            "error": "APPLY_CONFIG_STATE_GET_FAILED",
            "detail": _error_detail(where="operations_service.apply_config.state_get_before", exc=e, url=state_url),
        }

    if_version = int(state_before.get("config_revision") or 0) if isinstance(state_before, dict) and state_before.get("ok") else 0
    unsigned_cfg["if_version"] = if_version
    signed_cfg = make_signed_config(unsigned_cfg, keyp.read_bytes(), fp)

    try:
        apply_res = http_json("POST", apply_url, signed_cfg, timeout=timeout)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError, OSError) as e:
        return False, {
            "host": host,
            "port": port,
            "signer_fingerprint_hex": fp,
            "error": "APPLY_CONFIG_POST_FAILED",
            "detail": _error_detail(where="operations_service.apply_config.post", exc=e, url=apply_url),
        }
    except Exception as e:
        return False, {
            "host": host,
            "port": port,
            "signer_fingerprint_hex": fp,
            "error": "APPLY_CONFIG_POST_FAILED",
            "detail": _error_detail(where="operations_service.apply_config.post", exc=e, url=apply_url),
        }
    try:
        state_res = get_json(state_url, timeout=timeout)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError, OSError) as e:
        return False, {
            "host": host,
            "port": port,
            "signer_fingerprint_hex": fp,
            "error": "APPLY_CONFIG_STATE_GET_FAILED",
            "detail": _error_detail(where="operations_service.apply_config.state_get", exc=e, url=state_url),
            "apply_response": apply_res,
        }
    except Exception as e:
        return False, {
            "host": host,
            "port": port,
            "signer_fingerprint_hex": fp,
            "error": "APPLY_CONFIG_STATE_GET_FAILED",
            "detail": _error_detail(where="operations_service.apply_config.state_get", exc=e, url=state_url),
            "apply_response": apply_res,
        }
    ok = bool(apply_res.get("ok")) and bool(state_res.get("ok"))
    return ok, {
        "host": host,
        "port": port,
        "signer_fingerprint_hex": fp,
        "if_version": int(if_version),
        "apply_url": apply_url,
        "state_url": state_url,
        "state_before": state_before,
        "apply_response": apply_res,
        "state": state_res,
    }


def config_patch(*, patch_path: str, patch_obj: dict | None, if_version: int, key_path: str, host: str, port: int, timeout: int, fingerprint: str) -> tuple[bool, dict]:
    if patch_obj is None:
        patch_obj = json.loads(Path(patch_path).read_text())
    if not isinstance(patch_obj, dict):
        raise RuntimeError("ERR_CONFIG_PATCH_SCHEMA")

    unsigned_cfg = {
        "config_version": 1,
        "if_version": int(if_version),
        "patch": patch_obj,
    }

    keyp = Path(key_path)
    fp = fingerprint.strip() or ed25519_fp_hex_from_private_key(keyp)
    signed_cfg = make_signed_config(unsigned_cfg, keyp.read_bytes(), fp)

    base = base_url(host=host, port=port, scheme="https")
    patch_url = f"{base}/api/v0/config/patch"
    state_url = f"{base}/api/v0/config/state"
    try:
        patch_res = http_json("POST", patch_url, signed_cfg, timeout=timeout)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError, OSError) as e:
        return False, {
            "host": host,
            "port": port,
            "signer_fingerprint_hex": fp,
            "if_version": int(if_version),
            "error": "CONFIG_PATCH_POST_FAILED",
            "detail": _error_detail(where="operations_service.config_patch.post", exc=e, url=patch_url),
        }
    except Exception as e:
        return False, {
            "host": host,
            "port": port,
            "signer_fingerprint_hex": fp,
            "if_version": int(if_version),
            "error": "CONFIG_PATCH_POST_FAILED",
            "detail": _error_detail(where="operations_service.config_patch.post", exc=e, url=patch_url),
        }
    try:
        state_res = get_json(state_url, timeout=timeout)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError, OSError) as e:
        return False, {
            "host": host,
            "port": port,
            "signer_fingerprint_hex": fp,
            "if_version": int(if_version),
            "error": "CONFIG_PATCH_STATE_GET_FAILED",
            "detail": _error_detail(where="operations_service.config_patch.state_get", exc=e, url=state_url),
            "patch_response": patch_res,
        }
    except Exception as e:
        return False, {
            "host": host,
            "port": port,
            "signer_fingerprint_hex": fp,
            "if_version": int(if_version),
            "error": "CONFIG_PATCH_STATE_GET_FAILED",
            "detail": _error_detail(where="operations_service.config_patch.state_get", exc=e, url=state_url),
            "patch_response": patch_res,
        }
    ok = bool(patch_res.get("ok")) and bool(state_res.get("ok"))
    return ok, {
        "host": host,
        "port": port,
        "signer_fingerprint_hex": fp,
        "if_version": int(if_version),
        "patch_url": patch_url,
        "state_url": state_url,
        "patch_response": patch_res,
        "state": state_res,
    }


def certify_issue(*, host: str, port: int, timeout: int, key_path: str, serial: str, issue_id: str, title: str, expected: str, actual: str, repro: list[str], evidence: list[str], meta: list[str], nonce: str, cert_serial: str, no_upload_device_cert: bool, out_path: str) -> tuple[bool, str | None, dict]:
    keyp = Path(key_path)
    base = base_url(host=host, port=port, scheme="https")
    state = get_json(f"{base}/api/v0/config/state", timeout=timeout)
    if not state.get("ok"):
        return False, "ERR_STATE_QUERY", {"state": state}

    key_fp = ed25519_fp_hex_from_private_key(keyp)
    device_fp = str(state.get("admin_fingerprint_hex") or "")
    if len(device_fp) != 64 or key_fp != device_fp:
        return False, "ERR_KEY_OWNERSHIP", {"key_fingerprint": key_fp, "device_fingerprint": device_fp}

    nonce_hex = nonce.strip() or secrets.token_hex(16)
    att = get_json(f"{base}/api/v0/device/attestation?nonce={quote(nonce_hex, safe='')}", timeout=timeout)
    if not att.get("ok"):
        return False, "ERR_ATTESTATION_QUERY", {"attestation": att}

    att_payload = att.get("payload") or {}
    att_sig_b64 = str(att.get("signature_b64") or "")
    if att_payload.get("nonce") != nonce_hex:
        return False, "ERR_ATTESTATION_NONCE_MISMATCH", {}

    state_dev_pub = str(state.get("device_sign_public_key_b64") or "")
    state_dev_fp = str(state.get("device_sign_fingerprint_hex") or "")
    if att_payload.get("device_sign_public_key_b64") != state_dev_pub:
        return False, "ERR_ATTESTATION_DEVICE_KEY_MISMATCH", {}
    if att_payload.get("device_sign_fingerprint_hex") != state_dev_fp:
        return False, "ERR_ATTESTATION_DEVICE_FP_MISMATCH", {}
    if str(att_payload.get("device_chip_id_hex") or "") != str(state.get("device_chip_id_hex") or ""):
        return False, "ERR_ATTESTATION_CHIP_ID_MISMATCH", {}

    try:
        att_payload_raw = json.dumps(att_payload, separators=(",", ":")).encode("utf-8")
        pub = ed25519.Ed25519PublicKey.from_public_bytes(base64.b64decode(state_dev_pub, validate=True))
        pub.verify(base64.b64decode(att_sig_b64, validate=True), att_payload_raw)
    except (binascii.Error, ValueError, TypeError, InvalidSignature) as e:
        return False, "ERR_ATTESTATION_SIG_VERIFY", {"detail": _error_detail(where="operations_service.certify_issue.attestation_sig_verify", exc=e)}
    except Exception as e:
        return False, "ERR_ATTESTATION_SIG_VERIFY", {"detail": _error_detail(where="operations_service.certify_issue.attestation_sig_verify", exc=e)}

    payload = {
        "schema": "azt.issue.certification.v1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "nonce_hex": nonce_hex,
        "device_serial": serial,
        "issue_id": issue_id,
        "title": title,
        "expected": expected,
        "actual": actual,
        "repro_steps": repro or [],
        "evidence": evidence or [],
        "metadata": parse_meta(meta),
        "attestation": {
            "verified": True,
            "signature_algorithm": att.get("signature_algorithm"),
            "payload": att_payload,
            "signature_b64": att_sig_b64,
        },
    }

    payload_raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sig_raw = sign_bytes(keyp.read_bytes(), payload_raw)
    signer_fp = ed25519_fp_hex_from_private_key(keyp)

    envelope = {
        "kind": "azt-issue-cert",
        "version": 1,
        "signature_algorithm": "ed25519",
        "signer_fingerprint_hex": signer_fp,
        "payload_b64": base64.b64encode(payload_raw).decode("ascii"),
        "signature_b64": base64.b64encode(sig_raw).decode("ascii"),
    }

    outp = Path(out_path)
    outp.parent.mkdir(parents=True, exist_ok=True)
    outp.write_text(json.dumps(envelope, indent=2) + "\n")

    upload_res = None
    cert_ser = cert_serial.strip() or issue_id
    if not no_upload_device_cert:
        cert_challenge = get_json(f"{base}/api/v0/device/certificate/challenge", timeout=timeout)
        if not cert_challenge.get("ok"):
            return False, "ERR_DEVICE_CERT_CHALLENGE", {"challenge": cert_challenge}
        cert_nonce = str(cert_challenge.get("nonce") or "")
        if not cert_nonce:
            return False, "ERR_DEVICE_CERT_CHALLENGE", {"detail": "missing nonce"}

        cert_payload = {
            "device_sign_public_key_b64": state_dev_pub,
            "device_sign_fingerprint_hex": state_dev_fp,
            "device_chip_id_hex": str(state.get("device_chip_id_hex") or ""),
            "admin_signer_fingerprint_hex": signer_fp,
            "certificate_serial": cert_ser,
            "nonce": cert_nonce,
        }
        cert_payload_raw = json.dumps(cert_payload, separators=(",", ":")).encode("utf-8")
        cert_sig_raw = sign_bytes(keyp.read_bytes(), cert_payload_raw)
        cert_doc = {
            "certificate_payload_b64": base64.b64encode(cert_payload_raw).decode("ascii"),
            "signature_algorithm": "ed25519",
            "signature_b64": base64.b64encode(cert_sig_raw).decode("ascii"),
        }
        upload_res = http_json("POST", f"{base}/api/v0/device/certificate", cert_doc, timeout=timeout)
        if not upload_res.get("ok"):
            return False, "ERR_DEVICE_CERT_UPLOAD", {"upload": upload_res}

    return True, None, {
        "host": host,
        "port": port,
        "out": str(outp),
        "nonce_hex": payload["nonce_hex"],
        "signer_fingerprint_hex": signer_fp,
        "verified_device_admin_fingerprint_hex": device_fp,
        "device_certificate_upload": upload_res,
        "device_certificate_serial": cert_ser,
    }


def verify_certification(*, in_path: str, key_path: str) -> tuple[bool, dict]:
    cert = json.loads(Path(in_path).read_text())
    payload_raw = base64.b64decode(cert["payload_b64"], validate=True)
    sig_raw = base64.b64decode(cert["signature_b64"], validate=True)
    pub = public_key_from_pem_bytes(Path(key_path).read_bytes())
    pub.verify(sig_raw, payload_raw)
    payload = json.loads(payload_raw.decode("utf-8"))
    return True, {"payload": payload}


def build_current_firmware(*, repo_root: Path, env: str) -> Path:
    pio = build_service.resolve_platformio()
    cmd = [
        pio,
        "run",
        "-d",
        str(repo_root / "firmware" / "audio_zero_trust"),
        "-e",
        env,
    ]
    p = subprocess.run(cmd, text=True, capture_output=True)
    if p.returncode != 0:
        raise RuntimeError(f"ERR_OTA_BUILD: {p.stdout}\n{p.stderr}")

    fw_path = repo_root / "firmware" / "audio_zero_trust" / ".pio" / "build" / env / "firmware.bin"
    if not fw_path.exists():
        raise RuntimeError(f"ERR_OTA_FIRMWARE_NOT_FOUND: {fw_path}")
    return fw_path


def ota_bundle_create(*, repo_root: Path, key_path: str, out_path: str, firmware_path: str, env: str, target: str, channel: str, version: str, version_code: int, rollback_floor_code: int | None = None) -> tuple[bool, dict]:
    keyp = Path(key_path)
    outp = Path(out_path)

    if (firmware_path or "").strip():
        fw_path = Path(firmware_path)
        if not fw_path.exists():
            raise RuntimeError(f"ERR_OTA_FIRMWARE_NOT_FOUND: {fw_path}")
    else:
        # Default behavior: rebuild from current source when --firmware is not provided.
        fw_path = build_current_firmware(repo_root=repo_root, env=env)

    if int(version_code) <= 0:
        raise RuntimeError("ERR_OTA_VERSION_CODE_INVALID")
    floor_code = None if rollback_floor_code is None else int(rollback_floor_code)
    if floor_code is not None and floor_code <= 0:
        raise RuntimeError("ERR_OTA_ROLLBACK_FLOOR_INVALID")

    fw = fw_path.read_bytes()
    fw_sha256 = hashlib.sha256(fw).hexdigest()
    target_val = (target or "").strip().lower()
    if target_val not in {"atom-echo", "atom-echos3r"}:
        raise RuntimeError("ERR_OTA_TARGET_INVALID")

    meta = {
        "schema": "azt.ota.bundle.v1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "channel": channel,
        "target": target_val,
        "version": version,
        "version_code": int(version_code),
        "firmware_name": fw_path.name,
        "firmware_size": len(fw),
        "firmware_sha256": fw_sha256,
    }
    if floor_code is not None:
        meta["rollback_floor_code"] = int(floor_code)

    meta_raw = json.dumps(meta, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sig_raw = sign_bytes(keyp.read_bytes(), meta_raw)
    signer_fp = ed25519_fp_hex_from_private_key(keyp)

    header = {
        "kind": "azt-ota-bundle",
        "version": 1,
        "signature_algorithm": "ed25519",
        "signer_fingerprint_hex": signer_fp,
        "meta_b64": base64.b64encode(meta_raw).decode("ascii"),
        "meta_signature_b64": base64.b64encode(sig_raw).decode("ascii"),
    }

    outp.parent.mkdir(parents=True, exist_ok=True)
    with outp.open("wb") as f:
        f.write(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        f.write(b"\n")
        f.write(fw)

    return True, {
        "out": str(outp),
        "firmware": str(fw_path),
        "firmware_size": len(fw),
        "firmware_sha256": fw_sha256,
        "target": target_val,
        "version_code": int(version_code),
        "rollback_floor_code": (None if floor_code is None else int(floor_code)),
        "signer_fingerprint_hex": signer_fp,
    }


def _ota_wake_if_possible(*, api_base: str, legacy_http_base: str, timeout: int, key_path: str, allow_self: bool, allowed_ip: str, window_seconds: int) -> tuple[bool, dict]:
    challenge_url = f"{api_base}/api/v0/device/ota/wake/challenge"
    wake_url = f"{api_base}/api/v0/device/ota/wake"

    ch = get_json(challenge_url, timeout=timeout)
    # Compatibility bridge: some deployed firmware builds still expose OTA wake challenge
    # on HTTP 8080 only. If HTTPS wake challenge is unavailable, fall back to legacy OTA HTTP endpoints.
    if not (isinstance(ch, dict) and ch.get("ok")):
        ch_err = str((ch or {}).get("error") or "")
        ch_detail = str((ch or {}).get("detail") or "")
        if ch_err == "HTTP_404" or "not found" in ch_detail.lower():
            challenge_url = f"{legacy_http_base}/api/v0/device/ota/wake/challenge"
            wake_url = f"{legacy_http_base}/api/v0/device/ota/wake"
            ch = get_json(challenge_url, timeout=timeout)
    if not (isinstance(ch, dict) and ch.get("ok")):
        return False, {
            "ok": False,
            "error": "ERR_OTA_WAKE_CHALLENGE",
            "challenge_url": challenge_url,
            "challenge_response": ch,
        }

    nonce = str(ch.get("nonce") or "")
    if not nonce:
        return False, {"ok": False, "error": "ERR_OTA_WAKE_CHALLENGE", "detail": "missing nonce in challenge response"}

    priv = load_private_key_auto(Path(key_path), purpose=str(key_path))
    if not isinstance(priv, ed25519.Ed25519PrivateKey):
        return False, {"ok": False, "error": "ERR_OTA_WAKE_KEY", "detail": "wake key must be Ed25519 private key PEM"}

    msg = f"ota_wake:{nonce}".encode("utf-8")
    sig_b64 = base64.b64encode(priv.sign(msg)).decode("ascii")
    signer_fp = ed25519_fp_hex_from_private_key(Path(key_path))

    payload = {
        "nonce": nonce,
        "signature_algorithm": "ed25519",
        "signature_b64": sig_b64,
        "signer_fingerprint_hex": signer_fp,
        "allow_self": bool(allow_self),
        "window_seconds": int(window_seconds),
    }
    if not allow_self:
        payload["allowed_ip"] = str(allowed_ip or "").strip()

    wake_res = http_json("POST", wake_url, payload, timeout=timeout)
    return bool(isinstance(wake_res, dict) and wake_res.get("ok")), {
        "ok": bool(isinstance(wake_res, dict) and wake_res.get("ok")),
        "challenge_url": challenge_url,
        "wake_url": wake_url,
        "response": wake_res,
    }


def ota_bundle_post(*,
                    in_path: str,
                    host: str,
                    port: int,
                    upgrade_path: str,
                    timeout: int,
                    key_path: str = "",
                    wake_window_seconds: int = 30,
                    wake_allow_self: bool = True,
                    wake_allowed_ip: str = "") -> tuple[bool, str | None, dict]:
    bundle_path = Path(in_path)
    if not bundle_path.exists():
        return False, "ERR_OTA_BUNDLE_NOT_FOUND", {"path": str(bundle_path)}

    data = bundle_path.read_bytes()
    # OTA upload body is currently sent over HTTP upgrade transport.
    # OTA wake challenge/auth must use HTTPS API.
    upgrade_base = base_url(host=host, port=port, scheme="http")
    api_base = base_url(host=host, port=8443, scheme="https")
    url = f"{upgrade_base}{upgrade_path}"

    resolved_key_path = str(key_path or os.getenv("AZT_ADMIN_KEY_PATH", "")).strip()
    wake_result: dict | None = None

    # Backward compatibility: transparently perform wake first when key material is available.
    if resolved_key_path:
        try:
            woke_ok, wake_result = _ota_wake_if_possible(
                api_base=api_base,
                legacy_http_base=upgrade_base,
                timeout=int(timeout),
                key_path=resolved_key_path,
                allow_self=bool(wake_allow_self),
                allowed_ip=str(wake_allowed_ip or ""),
                window_seconds=int(wake_window_seconds),
            )
            if not woke_ok:
                return False, "ERR_OTA_WAKE_FAILED", {"url": url, "wake": wake_result}
        except urllib.error.HTTPError as e:
            # Older firmware may not support wake endpoints; fall through and attempt direct post.
            if int(getattr(e, "code", 0) or 0) not in {404, 405}:
                body = e.read().decode("utf-8", errors="replace")
                return False, "ERR_OTA_WAKE_HTTP", {
                    "url": url,
                    "wake": wake_result,
                    "http_status": e.code,
                    "response": body,
                    "detail": _error_detail(where="operations_service.ota_bundle_post.wake", exc=e, url=url),
                }
        except Exception as e:
            return False, "ERR_OTA_WAKE", {
                "url": url,
                "wake": wake_result,
                "detail": _error_detail(where="operations_service.ota_bundle_post.wake", exc=e, url=url),
            }

    req = Request(url, data=data, method="POST", headers={"Content-Type": "application/octet-stream"})
    try:
        with urlopen_with_tls(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", errors="replace")
            try:
                parsed = json.loads(body)
            except json.JSONDecodeError:
                parsed = body
            ok = isinstance(parsed, dict) and bool(parsed.get("ok"))
            payload = {"url": url, "response": parsed}
            if wake_result is not None:
                payload["wake"] = wake_result
            return ok, (None if ok else "ERR_OTA_BUNDLE_POST_FAILED"), payload
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        try:
            parsed_err = json.loads(body)
        except Exception:
            parsed_err = body
        err_code = "ERR_OTA_BUNDLE_HTTP"
        if isinstance(parsed_err, dict) and parsed_err.get("error") == "ERR_OTA_WAKE_REQUIRED" and not resolved_key_path:
            err_code = "ERR_OTA_WAKE_REQUIRED"
        payload = {
            "url": url,
            "http_status": e.code,
            "response": parsed_err,
            "detail": _error_detail(where="operations_service.ota_bundle_post", exc=e, url=url),
        }
        if wake_result is not None:
            payload["wake"] = wake_result
        return False, err_code, payload
    except Exception as e:
        payload = {
            "url": url,
            "detail": _error_detail(where="operations_service.ota_bundle_post", exc=e, url=url),
        }
        if wake_result is not None:
            payload["wake"] = wake_result
        return False, "ERR_OTA_BUNDLE_POST", payload


def separate_headers(*, in_path: str, out_headers: str) -> tuple[bool, dict]:
    data = Path(in_path).read_bytes()
    if not data.startswith(b"AZT1\n"):
        return False, {"error": "ERR_MAGIC"}

    off = 5
    nl = data.find(b"\n", off)
    if nl < 0:
        return False, {"error": "ERR_HEADER_JSON"}
    plain_line = data[off:nl]
    plain = json.loads(plain_line.decode("utf-8"))
    off = nl + 1

    sig_nl = data.find(b"\n", off)
    if sig_nl < 0:
        return False, {"error": "ERR_HEADER_SIG"}
    sig_line = data[off:sig_nl]
    off = sig_nl + 1

    if off + 2 > len(data):
        return False, {"error": "ERR_NEXT_HEADER_LEN"}
    next_len = int.from_bytes(data[off:off+2], "big")
    off += 2

    pkg: dict = {
        "schema": "azt.header-separation.v1",
        "source_file": str(in_path),
        "plain_header_json_utf8": plain_line.decode("utf-8"),
        "plain_header_signature_line_b64": sig_line.decode("utf-8"),
        "next_header_len_u16": next_len,
        "next_header_plaintext_sha256_b64": plain.get("next_header_plaintext_sha256_b64", ""),
        "next_header_plaintext_hash_alg": plain.get("next_header_plaintext_hash_alg", ""),
    }

    if next_len == 0xFFFF:
        dec_nl = data.find(b"\n", off)
        if dec_nl < 0:
            return False, {"error": "ERR_PLAINTEXT_NEXT_HEADER"}
        pkg["next_header_mode"] = "plaintext"
        pkg["next_header_plaintext_json_utf8"] = data[off:dec_nl].decode("utf-8")
        off = dec_nl + 1
    else:
        if off + next_len > len(data):
            return False, {"error": "ERR_ENCRYPTED_NEXT_HEADER"}
        pkg["next_header_mode"] = "encrypted"
        pkg["next_header_ciphertext_b64"] = base64.b64encode(data[off:off+next_len]).decode("ascii")
        off += next_len

    payload = data[off:]
    pkg["payload_offset_bytes"] = off
    pkg["payload_len_bytes"] = len(payload)
    pkg["payload_sha256_hex"] = hashlib.sha256(payload).hexdigest()

    outp = Path(out_headers)
    outp.parent.mkdir(parents=True, exist_ok=True)
    outp.write_text(json.dumps(pkg, indent=2) + "\n", encoding="utf-8")

    return True, {
        "out_headers": str(outp),
        "payload_offset_bytes": off,
        "payload_bytes": len(payload),
        "next_header_mode": pkg.get("next_header_mode"),
    }


def decode_next_header(*, in_path: str, key_path: str, out_path: str, out_decoded_next_header_path: str = "") -> tuple[bool, dict]:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    data = Path(in_path).read_bytes()

    plain: dict
    plain_line: bytes
    sig_line: bytes = b""
    header_ct: bytes
    payload: bytes = b""
    input_mode = "azt"

    if data.startswith(b"AZT1\n"):
        off = 5
        nl = data.find(b"\n", off)
        if nl < 0:
            return False, {"error": "ERR_HEADER_JSON"}
        plain_line = data[off:nl]
        plain = json.loads(plain_line.decode("utf-8"))
        off = nl + 1

        sig_nl = data.find(b"\n", off)
        if sig_nl < 0:
            return False, {"error": "ERR_HEADER_SIG"}
        sig_line = data[off:sig_nl + 1]
        off = sig_nl + 1

        if off + 2 > len(data):
            return False, {"error": "ERR_ENC_HEADER_LENGTH"}
        enc_len = int.from_bytes(data[off:off+2], "big")
        off += 2

        if enc_len == 0xFFFF:
            return False, {"error": "ERR_ALREADY_DECODED_NEXT_HEADER"}
        if off + enc_len > len(data):
            return False, {"error": "ERR_ENC_HEADER_TRUNCATED"}

        header_ct = data[off:off+enc_len]
        payload = data[off+enc_len:]
    else:
        # Detached request package mode (.azt.request)
        try:
            req = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return False, {"error": "ERR_MAGIC"}
        if not isinstance(req, dict) or req.get("schema") != "azt.header-separation.v1":
            return False, {"error": "ERR_MAGIC"}
        if str(req.get("next_header_mode") or "") != "encrypted":
            return False, {"error": "ERR_DETACHED_MODE", "detail": "request package is not encrypted mode"}
        plain_line = str(req.get("plain_header_json_utf8") or "").encode("utf-8")
        if not plain_line:
            return False, {"error": "ERR_DETACHED_PLAIN_HEADER"}
        plain = json.loads(plain_line.decode("utf-8"))
        ctb64 = str(req.get("next_header_ciphertext_b64") or "")
        if not ctb64:
            return False, {"error": "ERR_DETACHED_CIPHERTEXT"}
        header_ct = base64.b64decode(ctb64, validate=True)
        input_mode = "request"

    priv = load_private_key_auto(Path(key_path), purpose=str(key_path))
    wrapped = base64.b64decode(str(plain["next_header_wrapped_key_b64"]), validate=True)
    header_key = priv.decrypt(wrapped, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    header_nonce = base64.b64decode(str(plain["next_header_nonce_b64"]), validate=True)
    header_tag = base64.b64decode(str(plain["next_header_tag_b64"]), validate=True)
    header_pt = AESGCM(header_key).decrypt(header_nonce, header_ct + header_tag, None)

    if str(plain.get("next_header_plaintext_hash_alg") or "") != "sha256":
        return False, {"error": "ERR_PLAIN_HASH_ALG"}
    expected_hash = base64.b64decode(str(plain.get("next_header_plaintext_sha256_b64") or ""), validate=True)
    if hashlib.sha256(header_pt).digest() != expected_hash:
        return False, {"error": "ERR_PLAIN_HASH_MISMATCH"}

    decoded_path_out = ""
    if (out_decoded_next_header_path or "").strip():
        dnp = Path(out_decoded_next_header_path)
        dnp.parent.mkdir(parents=True, exist_ok=True)
        dnp.write_bytes(header_pt)
        decoded_path_out = str(dnp)

    out_written = ""
    if input_mode == "azt" and (out_path or "").strip():
        out = bytearray()
        out += b"AZT1\n"
        out += plain_line + b"\n"
        out += sig_line
        out += (0xFFFF).to_bytes(2, "big")
        out += header_pt + b"\n"
        out += payload

        outp = Path(out_path)
        outp.parent.mkdir(parents=True, exist_ok=True)
        outp.write_bytes(bytes(out))
        out_written = str(outp)

    return True, {
        "out": out_written,
        "mode": ("decoded-next-header" if input_mode == "azt" else "detached-key"),
        "next_header_plaintext_bytes": len(header_pt),
        "decoded_next_header_out": decoded_path_out,
        "input_mode": input_mode,
    }


def combine_headers(*, in_path: str, headers_path: str, decoded_next_header_path: str, out_path: str) -> tuple[bool, dict]:
    src = Path(in_path).read_bytes()
    hdr = json.loads(Path(headers_path).read_text(encoding="utf-8"))
    if hdr.get("schema") != "azt.header-separation.v1":
        return False, {"error": "ERR_HEADER_PACKAGE_SCHEMA"}

    src_off = 5
    src_nl = src.find(b"\n", src_off)
    if src_nl < 0:
        return False, {"error": "ERR_INPUT_HEADER_JSON"}
    src_off = src_nl + 1
    src_sig_nl = src.find(b"\n", src_off)
    if src_sig_nl < 0:
        return False, {"error": "ERR_INPUT_HEADER_SIG"}
    if src[src_off:src_sig_nl] != str(hdr.get("plain_header_signature_line_b64", "")).encode("utf-8"):
        return False, {"error": "ERR_SIGNATURE_LINE_MISMATCH"}

    payload_offset = int(hdr.get("payload_offset_bytes", -1))
    payload_len = int(hdr.get("payload_len_bytes", -1))
    payload_sha256_hex = str(hdr.get("payload_sha256_hex", ""))
    if payload_offset < 0 or payload_len < 0 or payload_offset + payload_len > len(src):
        return False, {"error": "ERR_INPUT_PAYLOAD_RANGE"}
    payload = src[payload_offset:payload_offset + payload_len]
    if hashlib.sha256(payload).hexdigest() != payload_sha256_hex:
        return False, {"error": "ERR_INPUT_PAYLOAD_MISMATCH"}

    plain_line = str(hdr["plain_header_json_utf8"]).encode("utf-8")
    sig_line = str(hdr["plain_header_signature_line_b64"]).encode("utf-8")

    if decoded_next_header_path:
        next_header = Path(decoded_next_header_path).read_bytes()
    elif isinstance(hdr.get("next_header_plaintext_json_utf8"), str):
        next_header = str(hdr["next_header_plaintext_json_utf8"]).encode("utf-8")
    else:
        return False, {"error": "ERR_DECODED_NEXT_HEADER_REQUIRED"}

    plain = json.loads(plain_line.decode("utf-8"))
    if str(plain.get("next_header_plaintext_hash_alg") or "") != "sha256":
        return False, {"error": "ERR_PLAIN_HASH_ALG"}
    expected_b64 = str(plain.get("next_header_plaintext_sha256_b64") or "")
    if not expected_b64:
        return False, {"error": "ERR_PLAIN_HASH_FIELD"}
    if hashlib.sha256(next_header).digest() != base64.b64decode(expected_b64, validate=True):
        return False, {"error": "ERR_PLAIN_HASH_MISMATCH"}

    out = bytearray()
    out += b"AZT1\n"
    out += plain_line + b"\n"
    out += sig_line + b"\n"
    out += (0xFFFF).to_bytes(2, "big")
    out += next_header + b"\n"
    out += payload

    outp = Path(out_path)
    outp.parent.mkdir(parents=True, exist_ok=True)
    outp.write_bytes(bytes(out))
    return True, {"out": str(outp), "mode": "decoded-next-header", "payload_bytes": len(payload), "next_header_plaintext_bytes": len(next_header)}
