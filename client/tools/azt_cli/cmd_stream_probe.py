from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from tools.azt_cli.output import emit_envelope, exception_detail
from tools.azt_sdk.services.device_service import stream_read


def _active_streams_path() -> Path:
    return Path.home() / ".config" / "azt" / "active-streams.json"


def _load_active_streams() -> dict:
    p = _active_streams_path()
    if not p.exists():
        return {"streams": {}}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("streams"), dict):
            return data
    except Exception:
        pass
    return {"streams": {}}


def _save_active_stream(host: str, payload: dict, key_path: str) -> None:
    nonce = str(payload.get("stream_auth_nonce") or "").strip()
    if not nonce:
        return
    p = _active_streams_path()
    doc = _load_active_streams()
    streams = doc.setdefault("streams", {})
    streams[str(host).strip()] = {
        "stream_auth_nonce": nonce,
        "host": str(host).strip(),
        "port": 8080,
        "key_path": key_path,
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run(args: argparse.Namespace) -> int:
    command_name = str(getattr(args, "command_name", "stream-read"))
    try:
        seconds = None if getattr(args, "seconds", None) is None else float(args.seconds)
        out_path = (getattr(args, "out_path", "") or "").strip()
        probe = bool(getattr(args, "probe", False))

        if not out_path and not probe:
            emit_envelope(
                command=command_name,
                ok=False,
                error="STREAM_READ_ARGS",
                detail="provide either --out <file.azt> or --probe",
                as_json=bool(getattr(args, "as_json", False)),
            )
            return 1
        if out_path and probe:
            emit_envelope(
                command=command_name,
                ok=False,
                error="STREAM_READ_ARGS",
                detail="--out and --probe are mutually exclusive",
                as_json=bool(getattr(args, "as_json", False)),
            )
            return 1

        key_path = (getattr(args, "key_path", "") or "").strip()
        auth_key_path = (getattr(args, "auth_key_path", "") or "").strip()
        if out_path and not key_path:
            emit_envelope(
                command=command_name,
                ok=False,
                error="STREAM_READ_ARGS",
                detail="trusted recording requires --key <admin_private_key.pem>",
                as_json=bool(getattr(args, "as_json", False)),
            )
            return 1

        ok, payload = stream_read(
            host=args.host,
            port=int(args.port),
            seconds=seconds,
            timeout=int(args.timeout),
            out_path=(out_path or None),
            probe=probe,
            key_path=(key_path or None),
            auth_key_path=(auth_key_path or None),
        )
        if ok and not probe and isinstance(payload, dict):
            _save_active_stream(args.host, payload, auth_key_path or key_path)

        emit_envelope(
            command=command_name,
            ok=ok,
            error=None if ok else "STREAM_READ_EMPTY",
            payload=payload,
            as_json=bool(getattr(args, "as_json", False)),
        )
        return 0 if ok else 1
    except Exception as e:
        emit_envelope(
            command=command_name,
            ok=False,
            error="STREAM_READ_ERROR",
            detail=exception_detail("cmd_stream_probe.run", e),
            as_json=bool(getattr(args, "as_json", False)),
        )
        return 1
