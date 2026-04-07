#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


def run_json(cmd: list[str], cwd: Path) -> dict:
    print(f"\n$ {' '.join(cmd)}")
    p = subprocess.run(cmd, cwd=str(cwd), text=True, capture_output=True)
    if p.stdout:
        print(p.stdout.strip())
    if p.stderr:
        print(p.stderr.strip(), file=sys.stderr)
    try:
        out = json.loads(p.stdout or "{}")
    except Exception:
        raise RuntimeError(f"command did not return JSON: {' '.join(cmd)}")
    out["_exit_code"] = p.returncode
    return out


def ok(resp: dict) -> bool:
    return bool(resp.get("ok"))


def main() -> int:
    ap = argparse.ArgumentParser(description="Erase -> flash -> configure -> OTA smoke loop")
    ap.add_argument("--repo", default=".")
    ap.add_argument("--port", default="/dev/ttyACM0")
    ap.add_argument("--target", default="atom-echos3r", choices=["atom-echo", "atom-echos3r"])
    ap.add_argument("--identity", default="localdev")
    ap.add_argument("--host", default="localdev-mic.local")
    ap.add_argument("--admin-key", default="client/tools/provisioned/iter-admin/private_key.pem")
    ap.add_argument("--firmware-key", default="client/tools/provisioned/iter-fw/private_key.pem")
    ap.add_argument("--wifi-ssid", default="")
    ap.add_argument("--wifi-password", default="")
    ap.add_argument("--expect-ota-fail", action="store_true", help="Current known-bad mode: require OTA step to fail")
    args = ap.parse_args()

    repo = Path(args.repo).resolve()
    tool = ["python3", "./client/tools/azt_tool.py"]

    steps: list[tuple[str, list[str], bool]] = [
        (
            "erase",
            tool + ["erase-device", "--port", args.port, "--target", args.target, "--json"],
            True,
        ),
        (
            "flash",
            tool + ["flash-device", "--from-source", "--port", args.port, "--target", args.target, "--json"],
            True,
        ),
        (
            "configure",
            tool
            + [
                "configure-device",
                "--identity",
                args.identity,
                "--port",
                args.port,
                "--allow-serial-bootstrap",
                "--admin-creds-dir",
                str(Path(args.admin_key).parent),
                "--wifi-ssid",
                args.wifi_ssid,
                "--wifi-password",
                args.wifi_password,
                "--json",
            ],
            True,
        ),
        (
            "ota",
            tool
            + [
                "ota-bundle-create",
                "--firmware-key",
                args.firmware_key,
                "--admin-key",
                args.admin_key,
                "--version-code",
                "timestamp",
                "--rollback-floor-code",
                "same",
                "--post",
                "--host",
                args.host,
                "--target",
                args.target,
                "--json",
            ],
            not args.expect_ota_fail,
        ),
    ]

    results: dict[str, dict] = {}
    for name, cmd, should_pass in steps:
        resp = run_json(cmd, repo)
        results[name] = resp
        passed = ok(resp)
        if should_pass and not passed:
            print(f"\n[FAIL] step={name} expected=pass got=fail", file=sys.stderr)
            return 1
        if (not should_pass) and passed:
            print(f"\n[FAIL] step={name} expected=fail got=pass", file=sys.stderr)
            return 2

    print("\n[OK] ota feedback loop completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
