from __future__ import annotations

import argparse
import json
from pathlib import Path

from tools.azt_cli.output import emit_envelope, exception_detail
from tools.azt_sdk.services.device_service import certificate_post


def run(args: argparse.Namespace) -> int:
    try:
        host = str(getattr(args, "host", "") or "").strip()
        in_path = str(getattr(args, "in_path", "") or "").strip()
        missing = []
        if not host:
            missing.append("--host")
        if not in_path:
            missing.append("--in")
        if missing:
            emit_envelope(command="certificate-post", ok=False, error="CERTIFICATE_POST_ARGS", payload={"detail": f"missing required options: {', '.join(missing)}"}, as_json=bool(getattr(args, "as_json", False)))
            return 1

        payload = json.loads(Path(in_path).read_text())
        res = certificate_post(host=host, port=int(args.port), timeout=int(args.timeout), payload=payload)
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
    except Exception as e:
        emit_envelope(command="certificate-post", ok=False, error="CERTIFICATE_POST_FAILED", detail=exception_detail("cmd_certificate_post.run", e), as_json=bool(getattr(args, "as_json", False)))
        return 1
