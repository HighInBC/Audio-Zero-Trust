from __future__ import annotations

import argparse
import secrets
import sys

from tools.azt_cli.output import emit_envelope, emit_level, exception_detail
from tools.azt_sdk.services.device_service import attestation_get


def run(args: argparse.Namespace) -> int:
    try:
        host = str(getattr(args, "host", "") or "").strip()
        if not host:
            emit_envelope(command="attestation-get", ok=False, error="ATTESTATION_GET_ARGS", payload={"detail": "missing required options: --host"}, as_json=bool(getattr(args, "as_json", False)))
            return 1

        nonce_raw = str(getattr(args, "nonce", "") or "").strip()
        if nonce_raw:
            emit_level("caution", "attestation-get: --nonce is test-only; prefer auto-generated nonce for normal use", stream=sys.stderr)
            nonce = nonce_raw
        else:
            nonce = secrets.token_hex(16)

        att = attestation_get(host=host, port=int(args.port), timeout=int(args.timeout), nonce=nonce)
        ok = bool(att.get("ok"))
        emit_envelope(
            command="attestation-get",
            ok=ok,
            payload={"nonce": nonce, "response": att},
            error=None if ok else str(att.get("error") or "ATTESTATION_GET_FAILED"),
            detail=att.get("detail"),
            as_json=bool(getattr(args, "as_json", False)),
        )
        return 0 if ok else 1
    except Exception as e:
        emit_envelope(command="attestation-get", ok=False, error="ATTESTATION_GET_FAILED", detail=exception_detail("cmd_attestation_get.run", e), as_json=bool(getattr(args, "as_json", False)))
        return 1
