from __future__ import annotations

import argparse

from tools.azt_cli.output import emit_envelope, exception_detail
from tools.azt_sdk.services.tls_service import tls_ca_export


def run(args: argparse.Namespace) -> int:
    try:
        payload = tls_ca_export(out_path=str(args.out_path))
        emit_envelope(command="tls-ca-export", ok=True, payload=payload, as_json=bool(getattr(args, "as_json", False)))
        return 0
    except Exception as e:
        emit_envelope(command="tls-ca-export", ok=False, error="TLS_CA_EXPORT_FAILED", detail=exception_detail("cmd_tls_ca_export.run", e), as_json=bool(getattr(args, "as_json", False)))
        return 1
