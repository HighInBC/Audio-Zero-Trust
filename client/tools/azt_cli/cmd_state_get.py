from __future__ import annotations

import argparse

from tools.azt_cli.output import emit_envelope, exception_detail
from tools.azt_sdk.services.device_service import state_get


def run(args: argparse.Namespace) -> int:
    try:
        host = str(getattr(args, "host", "") or "").strip()
        if not host:
            emit_envelope(command="state-get", ok=False, error="STATE_GET_ARGS", payload={"detail": "missing required options: --host"}, as_json=bool(getattr(args, "as_json", False)))
            return 1

        st = state_get(host=host, port=int(args.port), timeout=int(args.timeout))
        ok = bool(st.get("ok"))
        emit_envelope(
            command="state-get",
            ok=ok,
            payload={"state": st},
            error=None if ok else str(st.get("error") or "STATE_GET_FAILED"),
            detail=st.get("detail"),
            as_json=bool(getattr(args, "as_json", False)),
        )
        return 0 if ok else 1
    except Exception as e:
        emit_envelope(command="state-get", ok=False, error="STATE_GET_FAILED", detail=exception_detail("cmd_state_get.run", e), as_json=bool(getattr(args, "as_json", False)))
        return 1
