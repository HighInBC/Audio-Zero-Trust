from __future__ import annotations

import argparse

from tools.azt_cli.output import emit_envelope, exception_detail
from tools.azt_client.http import get_json
from tools.azt_sdk.services.url_service import base_url
import os


def run(args: argparse.Namespace) -> int:
    try:
        host = str(getattr(args, "host", "") or "").strip()
        if not host:
            emit_envelope(
                command="tls-status",
                ok=False,
                error="TLS_STATUS_ARGS",
                payload={"detail": "missing required options: --host"},
                as_json=bool(getattr(args, "as_json", False)),
            )
            return 1

        b = base_url(host=host, port=int(args.port), scheme="https")
        res = get_json(f"{b}/api/v0/tls/state", timeout=int(args.timeout))
        ok = bool(res.get("ok"))
        emit_envelope(
            command="tls-status",
            ok=ok,
            payload={"response": res},
            error=None if ok else str(res.get("error") or "TLS_STATUS_FAILED"),
            detail=res.get("detail"),
            as_json=bool(getattr(args, "as_json", False)),
        )
        return 0 if ok else 1
    except Exception as e:
        emit_envelope(
            command="tls-status",
            ok=False,
            error="TLS_STATUS_FAILED",
            detail=exception_detail("cmd_tls_status.run", e),
            as_json=bool(getattr(args, "as_json", False)),
        )
        return 1
