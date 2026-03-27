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


def require_structured_detail(obj: dict) -> list[str]:
    errs: list[str] = []
    detail = obj.get("detail")
    if detail in (None, "", {}):
        return ["expected structured detail on failure"]
    if not isinstance(detail, dict):
        return ["detail should be object on failure"]
    for k in ("where", "exception_type", "message"):
        if k not in detail:
            errs.append(f"detail missing {k}")
    return errs


def _write_json(path: Path, obj: dict) -> None:
    path.write_text(json.dumps(obj), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description="Validate AZT CLI --json envelope contract")
    ap.add_argument("--tool-cmd", default="python3 tools/azt_tool.py")
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

    # Negative-path regression checks for structured service failure codes.
    if art:
        artp = Path(art)
        keyp = artp / "private_key.pem"
        cfgp = artp / "contract-unsigned-config.json"
        patchp = artp / "contract-patch.json"
        _write_json(cfgp, {"config_version": 1, "device_label": ident})
        _write_json(patchp, {"device_label": ident + "-p"})
        neg_host = "203.0.113.1"

        neg_cases = [
            (
                "apply-config",
                ["apply-config", "--host", neg_host, "--timeout", "1", "--in", str(cfgp), "--key", str(keyp)],
                {"APPLY_CONFIG_POST_FAILED", "APPLY_CONFIG_STATE_GET_FAILED"},
            ),
            (
                "config-patch",
                ["config-patch", "--host", neg_host, "--timeout", "1", "--patch", str(patchp), "--if-version", "1", "--key", str(keyp)],
                {"CONFIG_PATCH_POST_FAILED", "CONFIG_PATCH_STATE_GET_FAILED"},
            ),
            (
                "state-get",
                ["state-get", "--host", neg_host, "--timeout", "1"],
                {"STATE_GET_V0_FAILED"},
            ),
        ]

        for name, cmd, expected_codes in neg_cases:
            rc, obj, raw = run_cmd(args.tool_cmd, cmd)
            errs = require_envelope(obj, name)
            if rc == 0 or obj.get("ok") is not False:
                errs.append(f"expected failure, rc={rc}, ok={obj.get('ok')}")
            got_error = str(obj.get("error") or "")
            if got_error not in expected_codes:
                errs.append(f"unexpected error code: {got_error} expected one of {sorted(expected_codes)}")
            detail = obj.get("detail")
            payload = obj.get("payload") if isinstance(obj.get("payload"), dict) else {}
            if name in {"apply-config", "config-patch", "state-get"} and got_error:
                # service-level failures should include structured detail either at top-level detail
                # (legacy command wrappers) or payload.detail (newer style).
                pdetail = payload.get("detail") if isinstance(payload.get("detail"), dict) else None
                tdetail = obj.get("detail") if isinstance(obj.get("detail"), dict) else None
                detail_obj = pdetail if isinstance(pdetail, dict) else tdetail
                if not isinstance(detail_obj, dict):
                    errs.append("missing structured detail object")
                else:
                    for k in ("where", "exception_type", "message", "url"):
                        if k not in detail_obj:
                            errs.append(f"detail missing {k}")
            if errs:
                failures.append(f"{name}: " + "; ".join(errs) + f" | raw={raw[:300]}")

    for cmd in (["erase-device", "--port", "/dev/null", "--target", "atom-echo"], ["flash-device", "--port", "/dev/null", "--target", "atom-echo", "--from-source"]):
        # Expected to fail on invalid port but still should emit envelope.
        rc, obj, raw = run_cmd(args.tool_cmd, cmd)
        name = cmd[0]
        errs = require_envelope(obj, name)
        if not errs and obj.get("ok") is True:
            errs.append("expected failure with /dev/null but got ok=true")
        if obj.get("ok") is False:
            err_code = str(obj.get("error") or "")
            # Structured detail is mandatory for exception-wrapper style failures.
            if err_code.endswith("_ERROR") or err_code.endswith("_EXCEPTION"):
                errs.extend(require_structured_detail(obj))
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
