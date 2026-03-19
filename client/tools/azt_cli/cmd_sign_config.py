from __future__ import annotations

import argparse

from tools.azt_cli.output import emit_envelope
from tools.azt_sdk.services.crypto_service import sign_config_file


def run(args: argparse.Namespace) -> int:
    payload = sign_config_file(
        in_path=args.in_path,
        key_path=args.key_path,
        out_path=args.out_path,
        fingerprint=args.fingerprint,
    )
    emit_envelope(
        command="sign-config",
        ok=True,
        payload=payload,
        as_json=bool(getattr(args, "as_json", False)),
    )
    return 0
