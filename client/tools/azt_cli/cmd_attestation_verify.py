from __future__ import annotations

import argparse
import json
import secrets
import sys
from pathlib import Path

from tools.azt_cli.output import emit_envelope, emit_level, exception_detail
from tools.azt_sdk.services.attestation_service import verify_attestation


def run(args: argparse.Namespace) -> int:
    nonce_raw = str(getattr(args, "nonce", "") or "").strip()
    if nonce_raw:
        emit_level("caution", "attestation-verify: --nonce is test-only; prefer auto-generated nonce for normal use", stream=sys.stderr)
        nonce = nonce_raw
    else:
        nonce = secrets.token_hex(16)

    try:
        ok, payload = verify_attestation(host=args.host, port=int(args.port), nonce=nonce, timeout=int(args.timeout))
        artifact = payload.get("attestation_artifact") if isinstance(payload, dict) else None
        if args.out_path and isinstance(artifact, dict):
            outp = Path(args.out_path)
            outp.parent.mkdir(parents=True, exist_ok=True)
            outp.write_text(json.dumps(artifact, indent=2))

        emit_envelope(
            command="attestation-verify",
            ok=ok,
            error=None if ok else "ATTESTATION_VERIFY_FAILED",
            payload={**(payload or {}), "nonce": nonce, "out_path": args.out_path},
            as_json=bool(getattr(args, "as_json", False)),
        )
        return 0 if ok else 1
    except Exception as e:
        emit_envelope(
            command="attestation-verify",
            ok=False,
            error="ATTESTATION_VERIFY_ERROR",
            detail=exception_detail("cmd_attestation_verify.run", e),
            as_json=bool(getattr(args, "as_json", False)),
        )
        return 1
