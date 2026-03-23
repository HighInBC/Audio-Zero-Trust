from __future__ import annotations

import argparse

from tools.azt_cli.output import emit_envelope
from tools.azt_sdk.services import tls_service


def run(args: argparse.Namespace) -> int:
    try:
        host = str(args.host)
        payload = tls_service.tls_cert_issue_and_install(
            host=host,
            port=int(args.port),
            timeout=int(args.timeout),
            admin_key_path=str(args.key_path),
            cert_serial=str(args.cert_serial),
            valid_days=int(args.valid_days),
        )
        payload["next_steps"] = [
            "export AZT_SCHEME=https",
            f"export AZT_TLS_CA_CERT={payload.get('ca_cert_path','client/tools/pki/ca_cert.pem')}",
            f"python3 client/tools/azt_tool.py state-get --host {host} --port 8443",
        ]
        emit_envelope(command="tls-cert-issue", ok=True, payload=payload, as_json=bool(getattr(args, "as_json", False)))
        return 0
    except Exception as e:
        emit_envelope(command="tls-cert-issue", ok=False, error="TLS_CERT_ISSUE_FAILED", detail=str(e), as_json=bool(getattr(args, "as_json", False)))
        return 1
