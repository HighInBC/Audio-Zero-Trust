#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def run_cmd(base: str, args: list[str]) -> tuple[int, dict, str]:
    cmd = [*shlex.split(base), *args, "--json"]
    p = subprocess.run(cmd, cwd=str(ROOT), text=True, capture_output=True)
    out = ((p.stdout or "") + (p.stderr or "")).strip()
    try:
        obj = json.loads(out)
    except Exception:
        return p.returncode, {}, out
    return p.returncode, obj if isinstance(obj, dict) else {}, out


def require_envelope(obj: dict, command: str) -> list[str]:
    errs: list[str] = []
    for key in ("ok", "command", "error", "detail", "payload"):
        if key not in obj:
            errs.append(f"missing key: {key}")
    if "command" in obj and obj.get("command") != command:
        errs.append(f"command mismatch: expected {command}, got {obj.get('command')}")
    if "ok" in obj and not isinstance(obj.get("ok"), bool):
        errs.append("ok must be boolean")
    if "payload" in obj and not isinstance(obj.get("payload"), dict):
        errs.append("payload must be object")
    return errs


def main() -> int:
    ap = argparse.ArgumentParser(description="Validate AZT CLI --json envelope contract")
    ap.add_argument("--tool-cmd", default="python3 client/tools/azt_tool.py")
    ap.add_argument("--host", default="", help="Optional device host for device-backed checks")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()

    failures: list[str] = []

    ident = f"contract-{int(time.time())}"
    rc, obj, raw = run_cmd(args.tool_cmd, ["create-signing-credentials", "--identity", ident])
    errs = require_envelope(obj, "create-signing-credentials")
    if rc != 0:
        errs.append(f"exit={rc}")
    payload = obj.get("payload") if isinstance(obj.get("payload"), dict) else {}
    art = str(payload.get("artifacts") or "")
    if not art:
        errs.append("missing payload.artifacts")
    if errs:
        failures.append("create-signing-credentials: " + "; ".join(errs) + f" | raw={raw[:300]}")

    for cmd in (["erase-device", "--port", "/dev/null"], ["flash-device", "--port", "/dev/null"]):
        # Expected to fail on invalid port but still should emit envelope.
        rc, obj, raw = run_cmd(args.tool_cmd, cmd)
        name = cmd[0]
        errs = require_envelope(obj, name)
        if not errs and obj.get("ok") is True:
            errs.append("expected failure with /dev/null but got ok=true")
        if errs:
            failures.append(f"{name}: " + "; ".join(errs) + f" | raw={raw[:300]}")

    if args.host:
        device_cmds = [
            ["state-get", "--host", args.host, "--port", str(args.port)],
            ["attestation-get", "--host", args.host, "--nonce", f"contract-{int(time.time())}", "--port", str(args.port)],
            ["stream-redirect-check", "--host", args.host, "--port", str(args.port)],
            ["stream-read", "--host", args.host, "--port", str(args.port), "--seconds", "0.5"],
        ]
        for cmd in device_cmds:
            rc, obj, raw = run_cmd(args.tool_cmd, cmd)
            name = cmd[0]
            errs = require_envelope(obj, name)
            if rc != 0 or not obj.get("ok"):
                errs.append(f"expected success, rc={rc}, ok={obj.get('ok')}")
            if errs:
                failures.append(f"{name}: " + "; ".join(errs) + f" | raw={raw[:300]}")

    if failures:
        print(json.dumps({"ok": False, "failures": failures}, indent=2))
        return 1

    print(json.dumps({"ok": True, "checked": "cli-json-contract"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
