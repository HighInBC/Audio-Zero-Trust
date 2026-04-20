from __future__ import annotations

import argparse
import json
from pathlib import Path

from tools.azt_cli.output import emit_envelope, exception_detail
from tools.azt_sdk.services.device_service import stream_terminate


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


def _resolve_session(host: str, explicit_nonce: str) -> tuple[str, str]:
    if explicit_nonce.strip():
        return explicit_nonce.strip(), ""
    doc = _load_active_streams()
    streams = doc.get("streams", {}) if isinstance(doc, dict) else {}
    row = streams.get(host)
    if not isinstance(row, dict):
        return "", f"no active stream nonce found for host '{host}'"
    nonce = str(row.get("stream_auth_nonce") or "").strip()
    if not nonce:
        return "", f"no active stream nonce stored for host '{host}'"
    return nonce, ""


def _clear_session(host: str) -> None:
    p = _active_streams_path()
    doc = _load_active_streams()
    streams = doc.get("streams") if isinstance(doc, dict) else None
    if not isinstance(streams, dict):
        return
    if host in streams:
        del streams[host]
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run(args: argparse.Namespace) -> int:
    command_name = str(getattr(args, "command_name", "stream-terminate"))
    try:
        host = str(getattr(args, "host", "") or "").strip()
        key_path = str(getattr(args, "key_path", "") or "").strip()
        if not host:
            emit_envelope(command=command_name, ok=False, error="STREAM_TERMINATE_ARGS", detail="--host is required", as_json=bool(getattr(args, "as_json", False)))
            return 1
        if not key_path:
            emit_envelope(command=command_name, ok=False, error="STREAM_TERMINATE_ARGS", detail="--key is required", as_json=bool(getattr(args, "as_json", False)))
            return 1

        nonce, err = _resolve_session(host, str(getattr(args, "stream_auth_nonce", "") or ""))
        if err:
            emit_envelope(command=command_name, ok=False, error="STREAM_TERMINATE_NONCE", detail=err, as_json=bool(getattr(args, "as_json", False)))
            return 1

        reason_code = int(getattr(args, "reason_code", 2))
        message_json_text = str(getattr(args, "message_json", "") or "").strip()
        message_obj = {}
        if message_json_text:
            try:
                parsed = json.loads(message_json_text)
                if isinstance(parsed, dict):
                    message_obj = parsed
                else:
                    message_obj = {"value": parsed}
            except Exception as e:
                emit_envelope(command=command_name, ok=False, error="STREAM_TERMINATE_ARGS", detail=f"invalid --message-json: {e}", as_json=bool(getattr(args, "as_json", False)))
                return 1

        ok, payload = stream_terminate(
            host=host,
            port=int(args.port),
            timeout=int(args.timeout),
            key_path=key_path,
            stream_auth_nonce=nonce,
            reason_code=reason_code,
            message_json=message_obj,
        )

        if ok:
            _clear_session(host)

        emit_envelope(
            command=command_name,
            ok=ok,
            error=None if ok else "STREAM_TERMINATE_FAILED",
            payload=payload,
            as_json=bool(getattr(args, "as_json", False)),
        )
        return 0 if ok else 1
    except Exception as e:
        emit_envelope(
            command=command_name,
            ok=False,
            error="STREAM_TERMINATE_ERROR",
            detail=exception_detail("cmd_stream_terminate.run", e),
            as_json=bool(getattr(args, "as_json", False)),
        )
        return 1
