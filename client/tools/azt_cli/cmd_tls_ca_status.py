from __future__ import annotations

import argparse

from tools.azt_cli.output import emit_envelope, exception_detail
from tools.azt_sdk.services.tls_service import tls_ca_status


def run(args: argparse.Namespace) -> int:
    try:
        payload = tls_ca_status()
        emit_envelope(command="tls-ca-status", ok=True, payload=payload, as_json=bool(getattr(args, "as_json", False)))
        return 0
    except Exception as e:
        emit_envelope(command="tls-ca-status", ok=False, error="TLS_CA_STATUS_FAILED", detail=exception_detail("cmd_tls_ca_status.run", e), as_json=bool(getattr(args, "as_json", False)))
        return 1
