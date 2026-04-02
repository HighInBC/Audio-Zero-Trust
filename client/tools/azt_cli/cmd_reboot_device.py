from __future__ import annotations

import argparse
from pathlib import Path

from tools.azt_cli.output import emit_envelope, exception_detail
from tools.azt_sdk.services.device_service import reboot_device


def run(args: argparse.Namespace) -> int:
    try:
        host = str(getattr(args, "host", "") or "").strip()
        key_path = str(getattr(args, "key_path", "") or "").strip()
        missing = []
        if not host:
            missing.append("--host")
        if not key_path:
            missing.append("--key")
        if missing:
            emit_envelope(command="reboot-device", ok=False, error="REBOOT_ARGS", payload={"detail": f"missing required options: {', '.join(missing)}"}, as_json=bool(getattr(args, "as_json", False)))
            return 1
        if Path(key_path).is_dir():
            emit_envelope(command="reboot-device", ok=False, error="REBOOT_ARGS", payload={"detail": f"--key must be a PEM file, got directory: {key_path}"}, as_json=bool(getattr(args, "as_json", False)))
            return 1

        res = reboot_device(host=host, port=int(args.port), timeout=int(args.timeout), key_path=key_path)
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
    except Exception as e:
        emit_envelope(command="reboot-device", ok=False, error="REBOOT_FAILED", detail=exception_detail("cmd_reboot_device.run", e), as_json=bool(getattr(args, "as_json", False)))
        return 1
