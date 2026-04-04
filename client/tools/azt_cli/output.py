from __future__ import annotations

import json
import os
import sys
from typing import Any, Literal

REQUIRED_KEYS = ("ok", "command", "error", "detail", "payload")

LogLevel = Literal["info", "caution", "danger"]


def _supports_color(stream: Any) -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    try:
        return bool(getattr(stream, "isatty", lambda: False)())
    except Exception:
        return False


def _level_color(level: LogLevel) -> str:
    return {
        "info": "\x1b[32m",      # green
        "caution": "\x1b[33m",   # yellow
        "danger": "\x1b[31m",    # red
    }[level]


def _paint(text: str, level: LogLevel, stream: Any) -> str:
    if not _supports_color(stream):
        return text
    return f"{_level_color(level)}{text}\x1b[0m"


def emit_level(level: LogLevel, message: str, *, stream: Any = sys.stdout) -> None:
    level_tag = level.upper()
    print(_paint(f"{level_tag}: {message}", level, stream), file=stream)


def exception_detail(where: str, exc: Exception, *, context: dict[str, Any] | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {
        "where": where,
        "exception_type": type(exc).__name__,
        "message": str(exc),
    }
    if context:
        out["context"] = context
    return out


def _append_message(payload: dict[str, Any], *, level: LogLevel, text: str, code: str | None = None, context: dict[str, Any] | None = None) -> None:
    msgs = payload.get("messages")
    if not isinstance(msgs, list):
        msgs = []
        payload["messages"] = msgs

    item: dict[str, Any] = {
        "level": level,
        "text": str(text),
    }
    if code:
        item["code"] = code
    if context:
        item["context"] = context
    msgs.append(item)


def _normalize_payload_messages(*, ok: bool, error: str | None, detail: Any, payload: dict[str, Any]) -> dict[str, Any]:
    # Work on a shallow copy so callers keep their original object unchanged.
    out = dict(payload)

    msgs = out.get("messages")
    if not isinstance(msgs, list):
        out["messages"] = []

    # Ensure top-level failure includes a canonical danger message.
    if not ok and isinstance(error, str) and error.strip():
        msg_text = str(detail) if isinstance(detail, str) and detail.strip() else error
        _append_message(out, level="danger", code=error, text=msg_text)

    return out


def validate_envelope(env: dict[str, Any]) -> None:
    for k in REQUIRED_KEYS:
        if k not in env:
            raise ValueError(f"missing envelope key: {k}")
    if not isinstance(env.get("ok"), bool):
        raise TypeError("envelope 'ok' must be bool")
    if not isinstance(env.get("command"), str) or not env.get("command"):
        raise TypeError("envelope 'command' must be non-empty string")
    if env.get("error") is not None and not isinstance(env.get("error"), str):
        raise TypeError("envelope 'error' must be string or null")
    if not isinstance(env.get("payload"), dict):
        raise TypeError("envelope 'payload' must be object")


def emit_envelope(*, command: str, ok: bool, payload: dict[str, Any] | None = None, error: str | None = None, detail: Any = None, as_json: bool = False) -> None:
    norm_payload = _normalize_payload_messages(ok=bool(ok), error=error, detail=detail, payload=(payload or {}))

    env = {
        "ok": bool(ok),
        "command": command,
        "error": error,
        "detail": detail,
        "payload": norm_payload,
    }
    validate_envelope(env)
    if as_json:
        print(json.dumps(env, indent=2))
        return

    status = "OK" if env["ok"] else "FAIL"
    status_level: LogLevel = "info" if env["ok"] else "danger"
    print(_paint(f"{status} {env['command']}", status_level, sys.stdout))

    if env.get("error"):
        print(_paint(f"error: {env['error']}", "danger", sys.stdout))

    if env.get("detail") not in (None, "", {}):
        if isinstance(env["detail"], str):
            print(_paint(f"detail: {env['detail']}", "danger" if not env["ok"] else "info", sys.stdout))
        else:
            print(_paint("detail:", "danger" if not env["ok"] else "info", sys.stdout))
            print(json.dumps(env["detail"], indent=2))

    payload_obj = env.get("payload", {}) if isinstance(env.get("payload"), dict) else {}
    human_obj = payload_obj.get("human") if isinstance(payload_obj.get("human"), dict) else {}
    machine_obj = payload_obj.get("machine") if isinstance(payload_obj.get("machine"), dict) else payload_obj

    summary = human_obj.get("summary") if isinstance(human_obj.get("summary"), str) else ""
    if summary:
        print(_paint(summary, "info" if env["ok"] else "danger", sys.stdout))

    msgs = machine_obj.get("messages") if isinstance(machine_obj, dict) else None
    if isinstance(msgs, list):
        for m in msgs:
            if not isinstance(m, dict):
                continue
            level = m.get("level") if m.get("level") in ("info", "caution", "danger") else "info"
            text = str(m.get("text") or "")
            if not text:
                continue
            code = str(m.get("code") or "").strip()
            line = f"{code}: {text}" if code else text
            emit_level(level, line, stream=sys.stderr if level in ("caution", "danger") else sys.stdout)
