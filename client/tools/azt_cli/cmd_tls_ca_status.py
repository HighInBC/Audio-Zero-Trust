from __future__ import annotations

import argparse

from tools.azt_cli.output import emit_envelope
from tools.azt_sdk.services.tls_service import tls_ca_status


def run(args: argparse.Namespace) -> int:
    payload = tls_ca_status()
    emit_envelope(command="tls-ca-status", ok=True, payload=payload, as_json=bool(getattr(args, "as_json", False)))
    return 0
