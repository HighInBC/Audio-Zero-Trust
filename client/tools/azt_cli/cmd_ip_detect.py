from __future__ import annotations

import argparse

from tools.azt_cli.output import emit_envelope, exception_detail
from tools.azt_sdk.services.device_service import ip_detect


def run(args: argparse.Namespace) -> int:
    try:
        ok, payload = ip_detect(port=args.port, baud=int(args.baud), timeout=int(args.timeout))
        emit_envelope(
            command="ip-detect",
            ok=ok,
            payload=payload,
            error=None if ok else "IP_DETECT_FAILED",
            as_json=bool(getattr(args, "as_json", False)),
        )
        return 0 if ok else 1
    except Exception as e:
        emit_envelope(command="ip-detect", ok=False, error="IP_DETECT_FAILED", detail=exception_detail("cmd_ip_detect.run", e), as_json=bool(getattr(args, "as_json", False)))
        return 1
