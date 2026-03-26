from __future__ import annotations

import argparse

from tools.azt_cli.output import emit_envelope, exception_detail
from tools.azt_sdk.services.crypto_service import key_fingerprint_from_private_key
from tools.azt_sdk.services.device_service import state_get


def run(args: argparse.Namespace) -> int:
    try:
        st = state_get(host=args.host, port=int(args.port), timeout=int(args.timeout))
        expected = str(st.get("admin_fingerprint_hex") or "")
        got = key_fingerprint_from_private_key(key_path=args.key_path)
        ok = bool(st.get("ok")) and expected == got
        emit_envelope(
            command="key-match-check",
            ok=ok,
            error=None if ok else "KEY_MISMATCH",
            payload={"device_admin_fingerprint_hex": expected, "key_fingerprint_hex": got},
            as_json=bool(getattr(args, "as_json", False)),
        )
        return 0 if ok else 1
    except Exception as e:
        emit_envelope(command="key-match-check", ok=False, error="KEY_MATCH_CHECK_ERROR", detail=exception_detail("cmd_key_match_check.run", e), as_json=bool(getattr(args, "as_json", False)))
        return 2
