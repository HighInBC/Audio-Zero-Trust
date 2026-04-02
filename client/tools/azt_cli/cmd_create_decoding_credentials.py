from __future__ import annotations

import argparse

from tools.azt_cli.output import emit_envelope, exception_detail
from tools.azt_sdk.services.crypto_service import create_decoding_credentials


def run(args: argparse.Namespace) -> int:
    try:
        payload = create_decoding_credentials(identity=args.identity, identity_prefix=args.identity_prefix, out_dir=(getattr(args, "out_dir", "") or "").strip() or None, password_protected=bool(getattr(args, "password", False)))
        emit_envelope(
            command="create-decoding-credentials",
            ok=True,
            payload=payload,
            as_json=bool(getattr(args, "as_json", False)),
        )
        return 0
    except Exception as e:
        emit_envelope(command="create-decoding-credentials", ok=False, error="CREATE_DECODING_CREDENTIALS_FAILED", detail=exception_detail("cmd_create_decoding_credentials.run", e), as_json=bool(getattr(args, "as_json", False)))
        return 1
