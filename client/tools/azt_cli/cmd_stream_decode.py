from __future__ import annotations

import argparse
from pathlib import Path

from tools.azt_cli.output import emit_envelope
from tools.azt_sdk.services.stream_service import stream_decode


def run(args: argparse.Namespace) -> int:
    try:
        in_path = str(args.in_path)
        out_path = str(args.out_path).strip() or (in_path + ".wav")
        out_path = str(Path(out_path))
        out = stream_decode(
            in_path=in_path,
            key_path=args.key_path,
            out_path=out_path,
            apply_gain=bool(getattr(args, "apply_gain", False)),
            gain=(float(args.gain) if getattr(args, "gain", None) is not None else None),
        )
        emit_envelope(
            command="stream-decode",
            ok=bool(out.get("ok")),
            error=None if out.get("ok") else "STREAM_DECODE_FAILED",
            payload=out,
            as_json=bool(getattr(args, "as_json", False)),
        )
        return 0 if out.get("ok") else 1
    except Exception as e:
        emit_envelope(
            command="stream-decode",
            ok=False,
            error="STREAM_DECODE_EXCEPTION",
            detail=str(e),
            payload={},
            as_json=bool(getattr(args, "as_json", False)),
        )
        return 1
