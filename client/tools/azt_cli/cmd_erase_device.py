from __future__ import annotations

import argparse

from tools.azt_cli.output import emit_envelope
from tools.azt_sdk.services.build_service import erase_device


def run(args: argparse.Namespace) -> int:
    try:
        as_json = bool(getattr(args, "as_json", False))
        code, payload, out = erase_device(env=args.env, port=args.port, stream=(not as_json))
        emit_envelope(
            command="erase-device",
            ok=(code == 0),
            payload=payload,
            error=None if code == 0 else "ERASE_FAILED",
            detail=out[-1500:],
            as_json=as_json,
        )
        return int(code)
    except Exception as e:
        emit_envelope(
            command="erase-device",
            ok=False,
            error="ERASE_EXCEPTION",
            detail=str(e),
            as_json=bool(getattr(args, "as_json", False)),
        )
        return 2
