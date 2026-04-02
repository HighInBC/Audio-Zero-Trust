from __future__ import annotations

import argparse

from tools.azt_cli.output import emit_envelope, exception_detail
from tools.azt_sdk.services.crypto_service import create_signing_credentials


def run(args: argparse.Namespace) -> int:
    try:
        payload = create_signing_credentials(identity=args.identity, identity_prefix=args.identity_prefix, out_dir=(getattr(args, "out_dir", "") or "").strip() or None, password_protected=bool(getattr(args, "password", False)))
        emit_envelope(
            command="create-signing-credentials",
            ok=True,
            payload=payload,
            as_json=bool(getattr(args, "as_json", False)),
        )
        return 0
    except Exception as e:
        emit_envelope(command="create-signing-credentials", ok=False, error="CREATE_SIGNING_CREDENTIALS_FAILED", detail=exception_detail("cmd_create_signing_credentials.run", e), as_json=bool(getattr(args, "as_json", False)))
        return 1
