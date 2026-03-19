from __future__ import annotations

import argparse

from tools.azt_cli.output import emit_envelope
from tools.azt_sdk.services.device_service import ip_detect


def run(args: argparse.Namespace) -> int:
    ok, payload = ip_detect(port=args.port, baud=int(args.baud), timeout=int(args.timeout))
    emit_envelope(
        command="ip-detect",
        ok=ok,
        payload=payload,
        error=None if ok else "IP_DETECT_FAILED",
        as_json=bool(getattr(args, "as_json", False)),
    )
    return 0 if ok else 1
