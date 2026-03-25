from __future__ import annotations

import argparse
from tools.azt_cli.output import emit_envelope
from tools.azt_sdk.services.crypto_service import create_decoding_credentials


def run(args: argparse.Namespace) -> int:
    payload = create_decoding_credentials(identity=args.identity, identity_prefix=args.identity_prefix, password_protected=bool(getattr(args, "password", False)))
    emit_envelope(
        command="create-decoding-credentials",
        ok=True,
        payload=payload,
        as_json=bool(getattr(args, "as_json", False)),
    )
    return 0
