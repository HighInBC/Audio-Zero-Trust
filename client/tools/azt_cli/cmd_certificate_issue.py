from __future__ import annotations

import argparse
import json
from pathlib import Path

from tools.azt_cli.output import emit_envelope, exception_detail
from tools.azt_sdk.services.certificate_service import issue_certificate


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
        if not cert_serial:
            missing.append("--cert-serial")
        if missing:
            emit_envelope(
                command="certificate-issue",
                ok=False,
                error="CERTIFICATE_ISSUE_ARGS",
                payload={"detail": f"missing required options: {', '.join(missing)}"},
                as_json=bool(getattr(args, "as_json", False)),
            )
            return 1

        kp = Path(key_path)
        if kp.is_dir():
            emit_envelope(
                command="certificate-issue",
                ok=False,
                error="CERTIFICATE_ISSUE_ARGS",
                payload={"detail": f"--key must be a PEM file, got directory: {key_path}"},
                as_json=bool(getattr(args, "as_json", False)),
            )
            return 1

        ok, err, payload = issue_certificate(
            host=host,
            port=int(args.port),
            timeout=int(args.timeout),
            key_path=key_path,
            attestation_path=(args.attestation_path or None),
            attestation_max_age_s=int(args.attestation_max_age_s),
            cert_serial=cert_serial,
            valid_until_utc=args.valid_until_utc,
            auto_record=bool(getattr(args, "auto_record", False)),
            auto_decode=bool(getattr(args, "auto_decode", False)),
            out_path=(args.out_path or None),
        )
        cert_doc = payload.get("certificate") if isinstance(payload, dict) else None
        if ok and args.out_path and isinstance(cert_doc, dict):
            with open(args.out_path, "w", encoding="utf-8") as f:
                json.dump(cert_doc, f, indent=2)

        emit_envelope(
            command="certificate-issue",
            ok=ok,
            error=err,
            payload={**(payload or {}), "out_path": args.out_path},
            as_json=bool(getattr(args, "as_json", False)),
        )
        return 0 if ok else 2
    except Exception as e:
        emit_envelope(command="certificate-issue", ok=False, error="CERTIFICATE_ISSUE_ERROR", detail=exception_detail("cmd_certificate_issue.run", e), as_json=bool(getattr(args, "as_json", False)))
        return 2
