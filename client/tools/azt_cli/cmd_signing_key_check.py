from __future__ import annotations

import argparse

from tools.azt_cli.output import emit_envelope, exception_detail
from tools.azt_sdk.services.device_service import signing_key_check


def run(args: argparse.Namespace) -> int:
    try:
        ok, payload = signing_key_check(host=args.host, port=int(args.port), timeout=int(args.timeout))
        emit_envelope(
            command="signing-key-check",
            ok=ok,
            error=None if ok else "SIGNING_KEY_CHECK_FAILED",
            payload=payload,
            as_json=bool(getattr(args, "as_json", False)),
        )
        return 0 if ok else 1
    except Exception as e:
        emit_envelope(
            command="signing-key-check",
            ok=False,
            error="SIGNING_KEY_CHECK_ERROR",
            detail=exception_detail("cmd_signing_key_check.run", e),
            as_json=bool(getattr(args, "as_json", False)),
        )
        return 1
