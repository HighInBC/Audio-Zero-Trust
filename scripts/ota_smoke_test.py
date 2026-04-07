#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


def _extract_last_json_blob(text: str) -> dict:
    s = text or ""
    dec = json.JSONDecoder()
    i = 0
    last = None
    while i < len(s):
        j = s.find("{", i)
        if j < 0:
            break
        try:
            obj, end = dec.raw_decode(s, j)
            if isinstance(obj, dict):
                last = obj
            i = end
        except Exception:
            i = j + 1
    if last is None:
        raise RuntimeError("no JSON object found in command output")
    return last


def run_json(cmd: list[str], cwd: Path) -> dict:
    print(f"\n$ {' '.join(cmd)}")
    p = subprocess.run(cmd, cwd=str(cwd), text=True, capture_output=True)
    if p.stdout:
        print(p.stdout.strip())
    if p.stderr:
        print(p.stderr.strip(), file=sys.stderr)
    try:
        out = _extract_last_json_blob(p.stdout or "")
    except Exception:
        raise RuntimeError(f"command did not return JSON envelope: {' '.join(cmd)}")
    out["_exit_code"] = p.returncode
    return out


def ok(resp: dict) -> bool:
    return bool(resp.get("ok"))


def ensure_signing_creds(repo: Path, tool: list[str], out_dir: Path, identity: str) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    priv = out_dir / "private_key.pem"
    if not priv.exists():
        cmd = tool + [
            "create-signing-credentials",
            "--identity",
            identity,
            "--out-dir",
            str(out_dir),
            "--json",
        ]
        resp = run_json(cmd, repo)
        if not ok(resp):
            raise RuntimeError(f"failed to create signing creds at {out_dir}")
    return out_dir, priv


def main() -> int:
    ap = argparse.ArgumentParser(description="Erase -> flash -> configure -> OTA smoke loop")
    ap.add_argument("--repo", default=".")
    ap.add_argument("--port", default="/dev/ttyACM0")
    ap.add_argument("--target", default="atom-echos3r", choices=["atom-echo", "atom-echos3r"])
    ap.add_argument("--identity", default="localdev")
    ap.add_argument("--host", default="localdev-mic.local")
    ap.add_argument("--admin-key", default="client/tools/provisioned/iter-admin/private_key.pem")
    ap.add_argument("--admin-creds-dir", default="client/tools/provisioned/iter-admin")
    ap.add_argument("--firmware-key", default="client/tools/provisioned/iter-fw/private_key.pem")
    ap.add_argument("--wifi-ssid", default="")
    ap.add_argument("--wifi-password", default="")
    ap.add_argument("--expect-ota-fail", action="store_true", help="Current known-bad mode: require OTA step to fail")
    args = ap.parse_args()

    repo = Path(args.repo).resolve()
    tool = ["python3", "./client/tools/azt_tool.py"]

    admin_creds_dir = Path(args.admin_creds_dir)
    admin_key = Path(args.admin_key)
    firmware_key = Path(args.firmware_key)

    if not admin_key.exists() or not admin_creds_dir.exists():
        admin_creds_dir, admin_key = ensure_signing_creds(repo, tool, repo / ".tmp" / "ota-smoke-admin", "ota-smoke-admin")
    if not firmware_key.exists():
        _fw_dir, firmware_key = ensure_signing_creds(repo, tool, repo / ".tmp" / "ota-smoke-fw", "ota-smoke-fw")

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
                str(admin_creds_dir),
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
                str(firmware_key),
                "--admin-key",
                str(admin_key),
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
