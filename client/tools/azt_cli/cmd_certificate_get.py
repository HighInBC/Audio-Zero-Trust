from __future__ import annotations

import argparse
import base64
import json

from tools.azt_cli.output import emit_envelope, exception_detail
from tools.azt_sdk.services.device_service import certificate_get, state_get


def _decode_certificate_payload_for_human(res: dict) -> dict:
    out = dict(res)
    cert = out.get("certificate")
    if not isinstance(cert, dict):
        return out

    payload_b64 = cert.get("certificate_payload_b64")
    if not isinstance(payload_b64, str) or not payload_b64:
        return out

    cert2 = dict(cert)
    try:
        raw = base64.b64decode(payload_b64)
        try:
            cert2["certificate_payload"] = json.loads(raw.decode("utf-8"))
        except Exception:
            cert2["certificate_payload"] = raw.decode("utf-8", errors="replace")
    except Exception:
        cert2["certificate_payload_decode_error"] = "invalid base64"

    out["certificate"] = cert2
    return out


def run(args: argparse.Namespace) -> int:
    try:
        host = str(getattr(args, "host", "") or "").strip()
        port = int(args.port)
        timeout = int(args.timeout)
        if not host:
            emit_envelope(command="certificate-get", ok=False, error="CERTIFICATE_GET_ARGS", payload={"detail": "missing required options: --host"}, as_json=bool(getattr(args, "as_json", False)))
            return 1

        res = certificate_get(host=host, port=port, timeout=timeout)
        ok = bool(res.get("ok"))
        as_json = bool(getattr(args, "as_json", False))

        decoded = _decode_certificate_payload_for_human(res)
        cert = decoded.get("certificate") if isinstance(decoded, dict) else None
        cert_payload = cert.get("certificate_payload") if isinstance(cert, dict) else None

        verify = {
            "status": "unknown",
            "checks": {},
        }
        if ok and isinstance(cert_payload, dict):
            st = state_get(host=host, port=port, timeout=timeout)
            state = st if isinstance(st, dict) and st.get("ok") else {}
            checks = {
                "device_sign_fingerprint_match": cert_payload.get("device_sign_fingerprint_hex") == state.get("device_sign_fingerprint_hex"),
                "device_chip_id_match": cert_payload.get("device_chip_id_hex") == state.get("device_chip_id_hex"),
                "recording_fingerprint_match": cert_payload.get("recording_fingerprint_hex") == state.get("recording_fingerprint_hex"),
                "admin_fingerprint_match": cert_payload.get("admin_signer_fingerprint_hex") == state.get("admin_fingerprint_hex"),
                "serial_matches_active": cert_payload.get("certificate_serial") == state.get("device_certificate_serial"),
            }
            verify = {
                "status": "verified-binding" if all(bool(v) for v in checks.values()) else "mismatch",
                "checks": checks,
            }

        if as_json:
            emit_envelope(
                command="certificate-get",
                ok=ok,
                payload={"response": decoded, "verification": verify},
                error=None if ok else str(res.get("error") or "CERTIFICATE_GET_FAILED"),
                detail=res.get("detail"),
                as_json=True,
            )
            return 0 if ok else 1

        summary = "Certificate retrieved."
        if ok and isinstance(cert_payload, dict):
            summary = (
                f"Certificate serial: {cert_payload.get('certificate_serial', '')}\n"
                f"Issued at: {cert_payload.get('issued_at_utc', '')}\n"
                f"Valid until: {cert_payload.get('valid_until_utc', '')}\n"
                f"Device chip: {cert_payload.get('device_chip_id_hex', '')}\n"
                f"Device signer fp: {cert_payload.get('device_sign_fingerprint_hex', '')}\n"
                f"Recorder fp: {cert_payload.get('recording_fingerprint_hex', '')}\n"
                f"Admin signer fp: {cert_payload.get('admin_signer_fingerprint_hex', '')}\n"
                f"Verification: {verify.get('status', 'unknown')}"
            )

        emit_envelope(
            command="certificate-get",
            ok=ok,
            payload={
                "machine": {"response": decoded, "verification": verify},
                "human": {"summary": summary},
            },
            error=None if ok else str(res.get("error") or "CERTIFICATE_GET_FAILED"),
            detail=res.get("detail"),
            as_json=False,
        )
        return 0 if ok else 1
    except Exception as e:
        emit_envelope(command="certificate-get", ok=False, error="CERTIFICATE_GET_FAILED", detail=exception_detail("cmd_certificate_get.run", e), as_json=bool(getattr(args, "as_json", False)))
        return 1
