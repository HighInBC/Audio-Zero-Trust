from __future__ import annotations

import argparse
import json
from pathlib import Path

from tools.azt_cli.output import emit_envelope
from tools.azt_sdk.services.device_service import certificate_post


def run(args: argparse.Namespace) -> int:
    payload = json.loads(Path(args.in_path).read_text())
    res = certificate_post(host=args.host, port=int(args.port), timeout=int(args.timeout), payload=payload)
    ok = bool(res.get("ok"))
    emit_envelope(
        command="certificate-post",
        ok=ok,
        payload={"response": res},
        error=None if ok else str(res.get("error") or "CERTIFICATE_POST_FAILED"),
        detail=res.get("detail"),
        as_json=bool(getattr(args, "as_json", False)),
    )
    return 0 if ok else 1
