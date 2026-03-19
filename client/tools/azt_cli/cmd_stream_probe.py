from __future__ import annotations

import argparse

from tools.azt_cli.output import emit_envelope
from tools.azt_sdk.services.device_service import stream_probe


def run(args: argparse.Namespace) -> int:
    try:
        ok, payload = stream_probe(host=args.host, port=int(args.port), seconds=float(args.seconds), timeout=int(args.timeout))
        emit_envelope(
            command="stream-probe",
            ok=ok,
            error=None if ok else "STREAM_PROBE_EMPTY",
            payload=payload,
            as_json=bool(getattr(args, "as_json", False)),
        )
        return 0 if ok else 1
    except Exception as e:
        emit_envelope(
            command="stream-probe",
            ok=False,
            error="STREAM_PROBE_ERROR",
            detail=str(e),
            as_json=bool(getattr(args, "as_json", False)),
        )
        return 1
