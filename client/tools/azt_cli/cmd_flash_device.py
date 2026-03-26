from __future__ import annotations

import argparse
import base64
import hashlib
import json
import tempfile
from pathlib import Path
import os
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from tools.azt_cli.output import emit_envelope, exception_detail
from tools.azt_cli.targets import env_for_target
from tools.azt_client.crypto import load_private_key_auto
from tools.azt_sdk.services import build_service

# Must match firmware default in azt_http_api.cpp (kOtaSignerPublicKeyPem)
DEFAULT_EMBEDDED_OTA_SIGNER_PUBLIC_KEY_B64 = "6n6Ge+vZPN6HC+09FrDdBTlaEzQ0di799FuFCg+XR78="


def _pubkey_raw_from_pem_or_raw_b64(path_or_b64: str) -> bytes:
    s = (path_or_b64 or "").strip()
    if not s:
        return base64.b64decode(DEFAULT_EMBEDDED_OTA_SIGNER_PUBLIC_KEY_B64, validate=True)

    p = Path(s)
    if p.exists():
        data = p.read_bytes()
        try:
            priv = load_private_key_auto(data, purpose=str(p))
            pub = priv.public_key()
        except Exception:
            pub = serialization.load_pem_public_key(data)
        if not isinstance(pub, ed25519.Ed25519PublicKey):
            raise ValueError("firmware key must be Ed25519 private/public PEM")
        return pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    raw = base64.b64decode(s, validate=True)
    if len(raw) != 32:
        raise ValueError("firmware key b64 must decode to 32-byte Ed25519 raw public key")
    return raw


def _parse_and_verify_ota_bundle(bundle_path: str, signer_key_ref: str, bypass_validation: bool) -> dict:
    data = Path(bundle_path).read_bytes()
    nl = data.find(b"\n")
    if nl <= 0:
        raise ValueError("invalid ota bundle: missing header line")

    header_raw = data[:nl]
    fw = data[nl + 1 :]
    header = json.loads(header_raw.decode("utf-8"))

    meta_raw = base64.b64decode(header["meta_b64"], validate=True)
    meta_sig = base64.b64decode(header["meta_signature_b64"], validate=True)
    meta = json.loads(meta_raw.decode("utf-8"))

    fw_sha = hashlib.sha256(fw).hexdigest()
    fw_size = len(fw)

    signer_pub_raw = _pubkey_raw_from_pem_or_raw_b64(signer_key_ref)
    signer_fp = hashlib.sha256(signer_pub_raw).hexdigest()

    if not bypass_validation:
        if header.get("kind") != "azt-ota-bundle":
            raise ValueError("invalid ota bundle kind")
        if header.get("signer_fingerprint_hex") != signer_fp:
            raise ValueError("ota signer fingerprint mismatch")

        pub = ed25519.Ed25519PublicKey.from_public_bytes(signer_pub_raw)
        pub.verify(meta_sig, meta_raw)

        version_code = int(meta.get("version_code") or 0)
        if version_code <= 0:
            raise ValueError("invalid ota version_code")

        m_fw_size = int(meta.get("firmware_size") or 0)
        m_fw_sha = str(meta.get("firmware_sha256") or "")
        if m_fw_size != fw_size:
            raise ValueError("firmware size mismatch")
        if m_fw_sha != fw_sha:
            raise ValueError("firmware sha256 mismatch")

    return {
        "header": header,
        "meta": meta,
        "firmware_bytes": fw,
        "firmware_sha256": fw_sha,
        "firmware_size": fw_size,
        "signer_fingerprint_hex": signer_fp,
        "signer_public_key_b64": base64.b64encode(signer_pub_raw).decode("ascii"),
    }


def _serial_apply_ota_state(*, port: str, version_code: int, floor_code: int | None, signer_public_key_b64: str, timeout_s: float = 28.0) -> dict:
    try:
        import serial  # type: ignore
    except Exception as e:
        raise RuntimeError(f"pyserial missing for OTA state apply: {e}")

    payload: dict = {
        "ota_version_code": int(version_code),
        "ota_signer_public_key_pem": signer_public_key_b64,
    }
    if floor_code is not None:
        payload["ota_min_allowed_version_code"] = int(floor_code)

    line = f"AZT_OTA_APPLY {json.dumps(payload, separators=(',', ':'))}\n"

    started = time.time()
    last_tx = 0.0
    last_lines: list[str] = []
    with serial.Serial(port, baudrate=115200, timeout=0.25) as ser:
        while (time.time() - started) < float(timeout_s):
            now = time.time()
            # Device may reboot after flashing; retry sending until we get an explicit response.
            if (now - last_tx) >= 2.0:
                ser.write(line.encode("utf-8"))
                ser.flush()
                last_tx = now

            raw = ser.readline()
            if not raw:
                continue
            txt = raw.decode("utf-8", errors="replace").strip()
            if txt:
                last_lines.append(txt)
                if len(last_lines) > 40:
                    last_lines = last_lines[-40:]
            if txt.startswith("AZT_OTA_APPLY code="):
                marker = " body="
                code_part = txt.split(" ", 2)[1] if " " in txt else "code=0"
                code = int(code_part.replace("code=", "").strip())
                body = ""
                if marker in txt:
                    body = txt.split(marker, 1)[1]
                body_obj = None
                try:
                    body_obj = json.loads(body) if body else None
                except Exception:
                    body_obj = body
                return {
                    "ok": code == 200,
                    "code": code,
                    "response": body_obj,
                    "line": txt,
                    "tail": last_lines,
                }

    raise RuntimeError(f"timeout waiting for AZT_OTA_APPLY response (tail={last_lines[-10:]})")


def run(args: argparse.Namespace) -> int:
    try:
        as_json = bool(getattr(args, "as_json", False))
        from_source = bool(getattr(args, "from_source", False))
        from_ota = (getattr(args, "from_ota", "") or "").strip()

        if from_source == bool(from_ota):
            emit_envelope(
                command="flash-device",
                ok=False,
                error="FLASH_MODE_REQUIRED",
                detail="exactly one of --from-source or --from-ota is required",
                as_json=as_json,
            )
            return 1

        env = env_for_target(getattr(args, "target", ""))

        if from_source:
            code, payload, out = build_service.flash_device(env=env, port=args.port, stream=(not as_json))
            emit_envelope(
                command="flash-device",
                ok=(code == 0),
                payload={**payload, "mode": "from-source", "target": args.target, "env": env},
                error=None if code == 0 else "FLASH_FAILED",
                detail=out[-1500:],
                as_json=as_json,
            )
            return int(code)

        # --from-ota path
        parsed = _parse_and_verify_ota_bundle(
            bundle_path=from_ota,
            signer_key_ref=(getattr(args, "firmware_key", "") or "").strip(),
            bypass_validation=bool(getattr(args, "bypass_validation", False)),
        )

        with tempfile.NamedTemporaryFile(prefix="azt-ota-fw-", suffix=".bin", delete=False) as tf:
            tf.write(parsed["firmware_bytes"])
            temp_fw = tf.name

        try:
            code, payload, out = build_service.flash_firmware_bin(
                env=env,
                port=args.port,
                firmware_bin=temp_fw,
                stream=(not as_json),
            )
        finally:
            try:
                os.unlink(temp_fw)
            except Exception:
                pass

        ota_apply = None
        if code == 0 and bool(getattr(args, "apply_ota_state", True)):
            meta = parsed.get("meta") or {}
            version_code = int(meta.get("version_code") or 0)
            if version_code <= 0:
                raise RuntimeError("ota bundle missing valid version_code for serial OTA state apply")

            floor_raw = (getattr(args, "ota_floor_code", "") or "").strip()
            floor_code = None
            if floor_raw:
                floor_code = int(floor_raw)
            elif meta.get("rollback_floor_code") is not None:
                floor_code = int(meta.get("rollback_floor_code"))

            ota_apply = _serial_apply_ota_state(
                port=args.port,
                version_code=version_code,
                floor_code=floor_code,
                signer_public_key_b64=str(parsed.get("signer_public_key_b64") or ""),
            )

        result_payload = {
            **payload,
            "mode": "from-ota",
            "target": args.target,
            "env": env,
            "ota_bundle": str(Path(from_ota)),
            "bypass_validation": bool(getattr(args, "bypass_validation", False)),
            "ota_meta": parsed.get("meta"),
            "ota_signer_fingerprint_hex": parsed.get("signer_fingerprint_hex"),
            "ota_firmware_sha256": parsed.get("firmware_sha256"),
            "ota_firmware_size": parsed.get("firmware_size"),
            "ota_state_apply": ota_apply,
            "ota_state_apply_enabled": bool(getattr(args, "apply_ota_state", True)),
        }

        emit_envelope(
            command="flash-device",
            ok=(code == 0),
            payload=result_payload,
            error=None if code == 0 else "FLASH_FAILED",
            detail=out[-1500:],
            as_json=as_json,
        )
        return int(code)
    except Exception as e:
        emit_envelope(
            command="flash-device",
            ok=False,
            error="FLASH_EXCEPTION",
            detail=exception_detail("cmd_flash_device.run", e),
            as_json=bool(getattr(args, "as_json", False)),
        )
        return 2
