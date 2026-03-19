from __future__ import annotations

import argparse
import base64
import json

from tools.azt_cli.output import emit_envelope
from tools.azt_sdk.services.device_service import certificate_get


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
    res = certificate_get(host=args.host, port=int(args.port), timeout=int(args.timeout))
    ok = bool(res.get("ok"))
    as_json = bool(getattr(args, "as_json", False))
    human_res = res if as_json else _decode_certificate_payload_for_human(res)
    emit_envelope(
        command="certificate-get",
        ok=ok,
        payload={"response": human_res},
        error=None if ok else str(res.get("error") or "CERTIFICATE_GET_FAILED"),
        detail=res.get("detail"),
        as_json=as_json,
    )
    return 0 if ok else 1
