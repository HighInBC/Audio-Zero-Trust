from __future__ import annotations

import argparse

from tools.azt_cli.output import emit_envelope, exception_detail
from tools.azt_sdk.services.device_service import stream_redirect_check


def run(args: argparse.Namespace) -> int:
    try:
        ok, payload = stream_redirect_check(
            host=args.host,
            port=int(args.port),
            seconds=int(args.seconds),
            stream_port=int(args.stream_port),
            timeout=int(args.timeout),
        )
        emit_envelope(
            command="stream-redirect-check",
            ok=ok,
            error=None if ok else "STREAM_REDIRECT_CHECK_FAILED",
            payload=payload,
            as_json=bool(getattr(args, "as_json", False)),
        )
        return 0 if ok else 1
    except Exception as e:
        emit_envelope(
            command="stream-redirect-check",
            ok=False,
            error="STREAM_REDIRECT_CHECK_ERROR",
            detail=exception_detail("cmd_stream_redirect_check.run", e),
            as_json=bool(getattr(args, "as_json", False)),
        )
        return 1
