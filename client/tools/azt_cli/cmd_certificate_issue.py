from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from tools.azt_cli.output import emit_envelope, exception_detail
from tools.azt_sdk.services.certificate_service import issue_certificate


def _normalize_fingerprint(s: str) -> str:
    v = str(s or "").strip()
    if not v:
        return ""
    if v.lower().startswith("sha256:"):
        return "SHA256:" + v.split(":", 1)[1].strip()
    return v


def _fingerprint_from_pem_file(path: Path) -> str:
    raw = path.read_bytes()
    try:
        pub = serialization.load_pem_public_key(raw)
    except Exception:
        priv = serialization.load_pem_private_key(raw, password=None)
        pub = priv.public_key()
    pub_der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return "SHA256:" + hashlib.sha256(pub_der).hexdigest()


def _resolve_auto_decode_target_key(raw_value: str) -> tuple[str, str | None]:
    v = str(raw_value or "").strip()
    if not v:
        return "", None

    p = Path(v)
    if not p.exists():
        return _normalize_fingerprint(v), None

    if p.is_dir():
        candidates: list[Path] = []
        for name in (
            "fingerprint.txt",
            "fingerprint_hex.txt",
            "public_key_fingerprint.txt",
            "public_key_fingerprint_hex.txt",
            "public_key_b64.txt",
            "public_key.pem",
            "private_key.pem",
            "admin_private_key.pem",
        ):
            c = p / name
            if c.exists() and c.is_file():
                candidates.append(c)
        if not candidates:
            for c in sorted(p.iterdir()):
                if c.is_file() and "fingerprint" in c.name.lower() and c.suffix.lower() in {".txt", ".fp", ".fingerprint"}:
                    candidates.append(c)
            for c in sorted(p.iterdir()):
                if c.is_file() and c.suffix.lower() == ".pem":
                    candidates.append(c)
        for c in candidates:
            if "fingerprint" in c.name.lower() or c.suffix.lower() in {".txt", ".fp", ".fingerprint"}:
                txt = c.read_text(encoding="utf-8", errors="ignore").strip()
                if txt:
                    return _normalize_fingerprint(txt), None
            if c.suffix.lower() == ".pem":
                try:
                    return _fingerprint_from_pem_file(c), None
                except Exception:
                    continue
        return "", f"could not resolve fingerprint from directory: {v}"

    if p.is_file():
        if p.suffix.lower() in {".txt", ".fp", ".fingerprint"} or "fingerprint" in p.name.lower():
            txt = p.read_text(encoding="utf-8", errors="ignore").strip()
            if not txt:
                return "", f"empty fingerprint file: {v}"
            return _normalize_fingerprint(txt), None
        if p.suffix.lower() == ".pem":
            try:
                return _fingerprint_from_pem_file(p), None
            except Exception:
                return "", f"could not derive fingerprint from PEM file: {v}"

    return _normalize_fingerprint(v), None


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

        reencrypt_fp, resolve_err = _resolve_auto_decode_target_key(getattr(args, "auto_decode_target_key", ""))
        if resolve_err:
            emit_envelope(
                command="certificate-issue",
                ok=False,
                error="CERTIFICATE_ISSUE_ARGS",
                payload={"detail": f"invalid --auto-decode-target-key: {resolve_err}"},
                as_json=bool(getattr(args, "as_json", False)),
            )
            return 1

        auto_decode_enabled = bool(getattr(args, "auto_decode", False))
        if reencrypt_fp and not auto_decode_enabled:
            emit_envelope(
                command="certificate-issue",
                ok=False,
                error="CERTIFICATE_ISSUE_ARGS",
                payload={"detail": "--auto-decode-target-key requires --auto-decode"},
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
            auto_decode=auto_decode_enabled,
            reencrypt_to_key_fingerprint=reencrypt_fp,
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
