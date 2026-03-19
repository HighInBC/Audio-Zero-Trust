from __future__ import annotations

import argparse

from tools.azt_cli.output import emit_envelope
from tools.azt_sdk.services.device_service import reboot_device


def run(args: argparse.Namespace) -> int:
    res = reboot_device(host=args.host, port=int(args.port), timeout=int(args.timeout))
    ok = bool(res.get("ok"))
    emit_envelope(
        command="reboot-device",
        ok=ok,
        payload={"response": res},
        error=None if ok else str(res.get("error") or "REBOOT_FAILED"),
        detail=res.get("detail"),
        as_json=bool(getattr(args, "as_json", False)),
    )
    return 0 if ok else 1
