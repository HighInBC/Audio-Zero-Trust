from __future__ import annotations

import argparse

from tools.azt_cli.output import emit_envelope
from tools.azt_sdk.services.stream_service import stream_validate


def run(args: argparse.Namespace) -> int:
    try:
        out = stream_validate(in_path=args.in_path, key_path=args.key_path)
        emit_envelope(command="stream-validate", ok=bool(out.get("ok")), error=None if out.get("ok") else "STREAM_VALIDATE_FAILED", payload=out, as_json=bool(getattr(args, "as_json", False)))
        return 0 if out.get("ok") else 1
    except Exception as e:
        emit_envelope(command="stream-validate", ok=False, error="STREAM_VALIDATE_EXCEPTION", detail=str(e), payload={}, as_json=bool(getattr(args, "as_json", False)))
        return 1
