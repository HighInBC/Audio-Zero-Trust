from __future__ import annotations

import argparse
from pathlib import Path

from tools.azt_cli.output import emit_envelope, exception_detail
from tools.azt_sdk.services.crypto_service import sign_config_file


def run(args: argparse.Namespace) -> int:
    try:
        in_path = str(getattr(args, "in_path", "") or "").strip()
        key_path = str(getattr(args, "key_path", "") or "").strip()
        out_path = str(getattr(args, "out_path", "") or "").strip()
        missing = []
        if not in_path:
            missing.append("--in")
        if not key_path:
            missing.append("--key")
        if not out_path:
            missing.append("--out")
        if missing:
            emit_envelope(command="sign-config", ok=False, error="SIGN_CONFIG_ARGS", payload={"detail": f"missing required options: {', '.join(missing)}"}, as_json=bool(getattr(args, "as_json", False)))
            return 1
        if Path(key_path).is_dir():
            emit_envelope(command="sign-config", ok=False, error="SIGN_CONFIG_ARGS", payload={"detail": f"--key must be a PEM file, got directory: {key_path}"}, as_json=bool(getattr(args, "as_json", False)))
            return 1

        payload = sign_config_file(
            in_path=in_path,
            key_path=key_path,
            out_path=out_path,
            fingerprint=args.fingerprint,
        )
        emit_envelope(
            command="sign-config",
            ok=True,
            payload=payload,
            as_json=bool(getattr(args, "as_json", False)),
        )
        return 0
    except Exception as e:
        emit_envelope(command="sign-config", ok=False, error="SIGN_CONFIG_FAILED", detail=exception_detail("cmd_sign_config.run", e), as_json=bool(getattr(args, "as_json", False)))
        return 1
