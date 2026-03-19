from __future__ import annotations

import base64
import hashlib
import json
import secrets
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote
from urllib.request import Request, urlopen
import urllib.error

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ed25519

from tools.azt_client.config import make_signed_config
from tools.azt_client.crypto import spki_fp_hex_from_private_key
from tools.azt_client.http import http_json, get_json
from tools.azt_sdk.services import build_service


def parse_meta(items: list[str]) -> dict:
    out = {}
    for item in items or []:
        if "=" not in item:
            raise ValueError(f"invalid --meta entry (expected key=value): {item}")
        k, v = item.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def sign_bytes(priv_pem: bytes, payload: bytes) -> bytes:
    priv = serialization.load_pem_private_key(priv_pem, password=None)
    return priv.sign(payload, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256().digest_size), hashes.SHA256())


def public_key_from_pem_bytes(pem: bytes):
    try:
        priv = serialization.load_pem_private_key(pem, password=None)
        return priv.public_key()
    except Exception:
        return serialization.load_pem_public_key(pem)


def apply_config(*, in_path: str, key_path: str, host: str, port: int, timeout: int, fingerprint: str) -> tuple[bool, dict]:
    unsigned_cfg = json.loads(Path(in_path).read_text())
    keyp = Path(key_path)
    fp = fingerprint.strip() or spki_fp_hex_from_private_key(keyp)
    signed_cfg = make_signed_config(unsigned_cfg, keyp.read_bytes(), fp)

    base = f"http://{host}:{port}"
    apply_res = http_json("POST", f"{base}/api/v1/config", signed_cfg, timeout=timeout)
    state_res = get_json(f"{base}/api/v1/config/state", timeout=timeout)
    ok = bool(apply_res.get("ok")) and bool(state_res.get("ok"))
    return ok, {
        "host": host,
        "port": port,
        "signer_fingerprint_hex": fp,
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
    fp = fingerprint.strip() or spki_fp_hex_from_private_key(keyp)
    signed_cfg = make_signed_config(unsigned_cfg, keyp.read_bytes(), fp)

    base = f"http://{host}:{port}"
    patch_res = http_json("POST", f"{base}/api/v1/config/patch", signed_cfg, timeout=timeout)
    state_res = get_json(f"{base}/api/v1/config/state", timeout=timeout)
    ok = bool(patch_res.get("ok")) and bool(state_res.get("ok"))
    return ok, {
        "host": host,
        "port": port,
        "signer_fingerprint_hex": fp,
        "if_version": int(if_version),
        "patch_response": patch_res,
        "state": state_res,
    }


def certify_issue(*, host: str, port: int, timeout: int, key_path: str, serial: str, issue_id: str, title: str, expected: str, actual: str, repro: list[str], evidence: list[str], meta: list[str], nonce: str, cert_serial: str, no_upload_device_cert: bool, out_path: str) -> tuple[bool, str | None, dict]:
    keyp = Path(key_path)
    state = get_json(f"http://{host}:{port}/api/v1/config/state", timeout=timeout)
    if not state.get("ok"):
        return False, "ERR_STATE_QUERY", {"state": state}

    key_fp = spki_fp_hex_from_private_key(keyp)
    device_fp = str(state.get("admin_fingerprint_hex") or "")
    if len(device_fp) != 64 or key_fp != device_fp:
        return False, "ERR_KEY_OWNERSHIP", {"key_fingerprint": key_fp, "device_fingerprint": device_fp}

    nonce_hex = nonce.strip() or secrets.token_hex(16)
    att = get_json(f"http://{host}:{port}/api/v1/device/attestation?nonce={quote(nonce_hex, safe='')}", timeout=timeout)
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
    except Exception as e:
        return False, "ERR_ATTESTATION_SIG_VERIFY", {"detail": str(e)}

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
    signer_fp = spki_fp_hex_from_private_key(keyp)

    envelope = {
        "kind": "azt-issue-cert",
        "version": 1,
        "signature_algorithm": "rsa-pss-sha256",
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
        cert_payload = {
            "device_sign_public_key_b64": state_dev_pub,
            "device_sign_fingerprint_hex": state_dev_fp,
            "device_chip_id_hex": str(state.get("device_chip_id_hex") or ""),
            "admin_signer_fingerprint_hex": signer_fp,
            "certificate_serial": cert_ser,
        }
        cert_payload_raw = json.dumps(cert_payload, separators=(",", ":")).encode("utf-8")
        cert_sig_raw = sign_bytes(keyp.read_bytes(), cert_payload_raw)
        cert_doc = {
            "certificate_payload_b64": base64.b64encode(cert_payload_raw).decode("ascii"),
            "signature_algorithm": "rsa-pss-sha256",
            "signature_b64": base64.b64encode(cert_sig_raw).decode("ascii"),
        }
        upload_res = http_json("POST", f"http://{host}:{port}/api/v1/device/certificate", cert_doc, timeout=timeout)
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
    pub.verify(sig_raw, payload_raw, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256().digest_size), hashes.SHA256())
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


def ota_bundle_create(*, repo_root: Path, key_path: str, out_path: str, firmware_path: str, env: str, channel: str, version: str, version_code: int, rollback_floor_code: int | None = None) -> tuple[bool, dict]:
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
    meta = {
        "schema": "azt.ota.bundle.v1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "channel": channel,
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
    signer_fp = spki_fp_hex_from_private_key(keyp)

    header = {
        "kind": "azt-ota-bundle",
        "version": 1,
        "signature_algorithm": "rsa-pss-sha256",
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
        "version_code": int(version_code),
        "rollback_floor_code": (None if floor_code is None else int(floor_code)),
        "signer_fingerprint_hex": signer_fp,
    }


def ota_bundle_post(*, in_path: str, host: str, port: int, upgrade_path: str, timeout: int) -> tuple[bool, str | None, dict]:
    bundle_path = Path(in_path)
    if not bundle_path.exists():
        return False, "ERR_OTA_BUNDLE_NOT_FOUND", {"path": str(bundle_path)}

    data = bundle_path.read_bytes()
    url = f"http://{host}:{port}{upgrade_path}"
    req = Request(url, data=data, method="POST", headers={"Content-Type": "application/octet-stream"})
    try:
        with urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", errors="replace")
            try:
                parsed = json.loads(body)
            except Exception:
                parsed = body
            ok = isinstance(parsed, dict) and bool(parsed.get("ok"))
            return ok, (None if ok else "ERR_OTA_BUNDLE_POST_FAILED"), {"url": url, "response": parsed}
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        return False, "ERR_OTA_BUNDLE_HTTP", {"url": url, "http_status": e.code, "response": body}
    except Exception as e:
        return False, "ERR_OTA_BUNDLE_POST", {"url": url, "error": str(e)}


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
        except Exception:
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

    priv = serialization.load_pem_private_key(Path(key_path).read_bytes(), password=None)
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
