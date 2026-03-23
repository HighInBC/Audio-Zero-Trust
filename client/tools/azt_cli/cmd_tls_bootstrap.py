from __future__ import annotations

import argparse
from datetime import datetime, timezone

from tools.azt_cli.output import emit_envelope
from tools.azt_sdk.services.tls_service import tls_bootstrap


def run(args: argparse.Namespace) -> int:
    try:
        cert_serial = (str(args.cert_serial or "").strip())
        if not cert_serial:
            cert_serial = "tls-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")

        payload = tls_bootstrap(
            host=str(args.host),
            admin_key_path=str(args.key_path),
            http_port=int(args.port),
            https_port=int(args.https_port),
            timeout=int(args.timeout),
            cert_serial=cert_serial,
            valid_days=int(args.valid_days),
            reboot_on_https_failure=not bool(getattr(args, "no_reboot", False)),
            reboot_wait_seconds=int(args.reboot_wait_seconds),
            ca_key_path=str(getattr(args, "ca_key_path", "") or ""),
            ca_cert_path=str(getattr(args, "ca_cert_path", "") or ""),
        )

        https_ok = bool((payload.get("https_verify") or {}).get("ok"))
        if not https_ok:
            emit_envelope(
                command="tls-bootstrap",
                ok=False,
                error="TLS_BOOTSTRAP_HTTPS_VERIFY_FAILED",
                detail=str((payload.get("https_verify") or {}).get("error") or "https verification failed"),
                payload=payload,
                as_json=bool(getattr(args, "as_json", False)),
            )
            return 1

        emit_envelope(command="tls-bootstrap", ok=True, payload=payload, as_json=bool(getattr(args, "as_json", False)))
        return 0
    except Exception as e:
        emit_envelope(command="tls-bootstrap", ok=False, error="TLS_BOOTSTRAP_FAILED", detail=str(e), as_json=bool(getattr(args, "as_json", False)))
        return 1
