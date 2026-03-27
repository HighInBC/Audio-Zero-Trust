from __future__ import annotations

import argparse
import json

from tools.azt_cli.output import emit_envelope, exception_detail
from tools.azt_sdk.services.certificate_service import issue_certificate


def run(args: argparse.Namespace) -> int:
    try:
        ok, err, payload = issue_certificate(
            host=args.host,
            port=int(args.port),
            timeout=int(args.timeout),
            key_path=args.key_path,
            attestation_path=(args.attestation_path or None),
            attestation_max_age_s=int(args.attestation_max_age_s),
            cert_serial=args.cert_serial,
            valid_from_utc=args.valid_from_utc,
            valid_until_utc=args.valid_until_utc,
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
