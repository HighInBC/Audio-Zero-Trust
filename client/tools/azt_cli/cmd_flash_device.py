from __future__ import annotations

import argparse

from tools.azt_cli.output import emit_envelope
from tools.azt_sdk.services.build_service import flash_device


def run(args: argparse.Namespace) -> int:
    try:
        as_json = bool(getattr(args, "as_json", False))
        code, payload, out = flash_device(env=args.env, port=args.port, stream=(not as_json))
        emit_envelope(
            command="flash-device",
            ok=(code == 0),
            payload=payload,
            error=None if code == 0 else "FLASH_FAILED",
            detail=out[-1500:],
            as_json=as_json,
        )
        return int(code)
    except Exception as e:
        emit_envelope(
            command="flash-device",
            ok=False,
            error="FLASH_EXCEPTION",
            detail=str(e),
            as_json=bool(getattr(args, "as_json", False)),
        )
        return 2
