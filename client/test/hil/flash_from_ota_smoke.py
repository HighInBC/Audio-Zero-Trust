#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shlex
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def run_json(tool_cmd: str, args: list[str]) -> tuple[int, dict, str]:
    cmd = [*shlex.split(tool_cmd), *args, "--json"]
    p = subprocess.run(cmd, cwd=str(ROOT), text=True, capture_output=True)
    raw = ((p.stdout or "") + (p.stderr or "")).strip()
    try:
        obj = json.loads(raw)
    except Exception:
        return p.returncode, {}, raw
    return p.returncode, obj if isinstance(obj, dict) else {}, raw


def fail(msg: str, raw: str = "") -> int:
    out = {"ok": False, "error": msg}
    if raw:
        out["raw"] = raw[:1200]
    print(json.dumps(out, indent=2))
    return 1


def main() -> int:
    ap = argparse.ArgumentParser(description="HIL smoke test for flash-device --from-ota deterministic profile")
    ap.add_argument("--tool-cmd", default="python3 tools/azt_tool.py")
    ap.add_argument("--bundle", required=True, help="Path to .otabundle")
    ap.add_argument("--port", default="/dev/ttyUSB0")
    ap.add_argument("--env", default="m5stack-atom-m4-2-native")
    ap.add_argument("--firmware-key", default="")
    ap.add_argument("--host", default="", help="Optional host for post-flash state check")
    args = ap.parse_args()

    bundle = Path(args.bundle)
    if not bundle.exists():
        return fail(f"bundle not found: {bundle}")

    flash_args = [
        "flash-device",
        "--from-ota",
        str(bundle),
        "--port",
        args.port,
        "--env",
        args.env,
    ]
    if args.firmware_key:
        flash_args += ["--firmware-key", args.firmware_key]

    rc, obj, raw = run_json(args.tool_cmd, flash_args)
    if rc != 0:
        return fail(f"flash-device failed rc={rc}", raw)
    if not obj.get("ok"):
        return fail("flash-device ok=false", raw)

    payload = obj.get("payload") if isinstance(obj.get("payload"), dict) else {}
    if payload.get("flash_method") != "esptool_deterministic_v1_full_layout":
        return fail("unexpected flash_method", json.dumps(payload))

    ota_apply = payload.get("ota_state_apply")
    if not isinstance(ota_apply, dict) or not ota_apply.get("ok"):
        return fail("ota_state_apply missing/failed", json.dumps(payload))

    checks: dict[str, object] = {
        "flash_method": payload.get("flash_method"),
        "ota_state_apply_ok": ota_apply.get("ok"),
        "ota_version_code": ((payload.get("ota_meta") or {}) if isinstance(payload.get("ota_meta"), dict) else {}).get("version_code"),
    }

    if args.host:
        rc2, obj2, raw2 = run_json(args.tool_cmd, ["state-get", "--host", args.host])
        if rc2 != 0 or not obj2.get("ok"):
            return fail("state-get after flash failed", raw2)
        st = ((obj2.get("payload") or {}) if isinstance(obj2.get("payload"), dict) else {}).get("state")
        if not isinstance(st, dict):
            return fail("state-get payload missing state", raw2)

        ota_meta = payload.get("ota_meta") if isinstance(payload.get("ota_meta"), dict) else {}
        expected_vc = ota_meta.get("version_code")
        got_vc = st.get("last_ota_version_code")
        if expected_vc is not None and got_vc != expected_vc:
            return fail(f"last_ota_version_code mismatch expected={expected_vc} got={got_vc}", raw2)

        checks["state_host"] = args.host
        checks["state_last_ota_version_code"] = got_vc
        checks["state_ota_floor"] = st.get("ota_min_allowed_version_code")

    print(json.dumps({"ok": True, "checks": checks}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
