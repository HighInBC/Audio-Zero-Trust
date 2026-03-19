from __future__ import annotations

import json
from typing import Any

REQUIRED_KEYS = ("ok", "command", "error", "detail", "payload")


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
    env = {
        "ok": bool(ok),
        "command": command,
        "error": error,
        "detail": detail,
        "payload": payload or {},
    }
    validate_envelope(env)
    if as_json:
        print(json.dumps(env, indent=2))
        return

    status = "OK" if env["ok"] else "FAIL"
    print(f"{status} {env['command']}")
    if env.get("error"):
        print(f"error: {env['error']}")
    if env.get("detail") not in (None, "", {}):
        if isinstance(env["detail"], str):
            print(f"detail: {env['detail']}")
        else:
            print("detail:")
            print(json.dumps(env["detail"], indent=2))
    if env.get("payload"):
        print("payload:")
        print(json.dumps(env["payload"], indent=2))
