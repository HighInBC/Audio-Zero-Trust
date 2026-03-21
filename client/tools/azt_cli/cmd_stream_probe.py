from __future__ import annotations

import argparse

from tools.azt_cli.output import emit_envelope
from tools.azt_sdk.services.device_service import stream_probe


def run(args: argparse.Namespace) -> int:
    command_name = str(getattr(args, "command_name", "stream-read"))
    try:
        seconds = None if getattr(args, "seconds", None) is None else float(args.seconds)
        ok, payload = stream_probe(host=args.host, port=int(args.port), seconds=seconds, timeout=int(args.timeout))
        emit_envelope(
            command=command_name,
            ok=ok,
            error=None if ok else "STREAM_PROBE_EMPTY",
            payload=payload,
            as_json=bool(getattr(args, "as_json", False)),
        )
        return 0 if ok else 1
    except Exception as e:
        emit_envelope(
            command=command_name,
            ok=False,
            error="STREAM_PROBE_ERROR",
            detail=str(e),
            as_json=bool(getattr(args, "as_json", False)),
        )
        return 1
