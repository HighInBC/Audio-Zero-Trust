from __future__ import annotations

import argparse
from pathlib import Path

from tools.azt_cli.output import emit_envelope, exception_detail
from tools.azt_sdk.services.certificate_service import revoke_certificate


def run(args: argparse.Namespace) -> int:
    try:
        host = (getattr(args, "host", "") or "").strip()
        key_path = (getattr(args, "key_path", "") or "").strip()
        cert_serial = (getattr(args, "cert_serial", "") or "").strip()

        missing: list[str] = []
        if not host:
            missing.append("--host")
        if not key_path:
            missing.append("--key")
        if missing:
            emit_envelope(
                command="certificate-revoke",
                ok=False,
                error="CERTIFICATE_REVOKE_ARGS",
                detail=f"missing required options: {', '.join(missing)}",
                payload={"missing": missing},
                as_json=bool(getattr(args, "as_json", False)),
            )
            return 1

        kp = Path(key_path)
        if kp.is_dir():
            emit_envelope(
                command="certificate-revoke",
                ok=False,
                error="CERTIFICATE_REVOKE_ARGS",
                detail=f"--key must be a PEM file, got directory: {key_path}",
                payload={"key_path": key_path},
                as_json=bool(getattr(args, "as_json", False)),
            )
            return 1

        ok, err, payload = revoke_certificate(
            host=host,
            port=int(args.port),
            timeout=int(args.timeout),
            key_path=key_path,
            cert_serial=cert_serial,
        )
        emit_envelope(
            command="certificate-revoke",
            ok=ok,
            error=err,
            payload=payload or {},
            as_json=bool(getattr(args, "as_json", False)),
        )
        return 0 if ok else 2
    except Exception as e:
        emit_envelope(command="certificate-revoke", ok=False, error="CERTIFICATE_REVOKE_ERROR", detail=exception_detail("cmd_certificate_revoke.run", e), as_json=bool(getattr(args, "as_json", False)))
        return 2
