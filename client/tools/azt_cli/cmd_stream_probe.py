from __future__ import annotations

import argparse

from tools.azt_cli.output import emit_envelope
from tools.azt_sdk.services.device_service import stream_read


def run(args: argparse.Namespace) -> int:
    command_name = str(getattr(args, "command_name", "stream-read"))
    try:
        seconds = None if getattr(args, "seconds", None) is None else float(args.seconds)
        out_path = (getattr(args, "out_path", "") or "").strip()
        probe = bool(getattr(args, "probe", False))

        if not out_path and not probe:
            emit_envelope(
                command=command_name,
                ok=False,
                error="STREAM_READ_ARGS",
                detail="provide either --out <file.azt> or --probe",
                as_json=bool(getattr(args, "as_json", False)),
            )
            return 1
        if out_path and probe:
            emit_envelope(
                command=command_name,
                ok=False,
                error="STREAM_READ_ARGS",
                detail="--out and --probe are mutually exclusive",
                as_json=bool(getattr(args, "as_json", False)),
            )
            return 1

        ok, payload = stream_read(
            host=args.host,
            port=int(args.port),
            seconds=seconds,
            timeout=int(args.timeout),
            out_path=(out_path or None),
            probe=probe,
        )
        emit_envelope(
            command=command_name,
            ok=ok,
            error=None if ok else "STREAM_READ_EMPTY",
            payload=payload,
            as_json=bool(getattr(args, "as_json", False)),
        )
        return 0 if ok else 1
    except Exception as e:
        emit_envelope(
            command=command_name,
            ok=False,
            error="STREAM_READ_ERROR",
            detail=str(e),
            as_json=bool(getattr(args, "as_json", False)),
        )
        return 1
