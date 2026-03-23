#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import shlex
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def run_json(cmd: str, env: dict | None = None) -> dict:
    p = subprocess.run(shlex.split(cmd), cwd=str(ROOT), text=True, capture_output=True, env=env)
    raw = ((p.stdout or "") + (p.stderr or "")).strip()
    if p.returncode != 0:
        raise RuntimeError(f"command failed rc={p.returncode}: {cmd}\n{raw}")
    return json.loads(raw)


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description="HIL: issue TLS cert and verify HTTPS state-get")
    ap.add_argument("--host", required=True)
    ap.add_argument("--admin-key", required=True)
    ap.add_argument("--cert-serial", default="tls-hil-smoke")
    ap.add_argument("--http-port", type=int, default=8080)
    ap.add_argument("--https-port", type=int, default=8443)
    args = ap.parse_args()

    run_json("python3 tools/azt_tool.py tls-ca-init --force --json")

    issue = run_json(
        f"python3 tools/azt_tool.py tls-cert-issue --host {args.host} --key {args.admin_key} --cert-serial {args.cert_serial} --port {args.http_port} --json"
    )
    # ensure HTTPS server reloads newly installed key/cert
    run_json(
        f"python3 tools/azt_tool.py reboot-device --host {args.host} --key {args.admin_key} --port {args.http_port} --json"
    )
    assert issue.get("ok") is True
    ca = issue.get("payload", {}).get("ca_cert_path")
    assert ca and Path(ca).exists()

    env = dict(os.environ)
    env["AZT_SCHEME"] = "https"
    env["AZT_TLS_CA_CERT"] = str(ca)
    st = run_json(
        f"python3 tools/azt_tool.py state-get --host {args.host} --port {args.https_port} --json",
        env=env,
    )
    assert st.get("ok") is True

    state = st.get("payload", {}).get("state", {})
    assert state.get("tls_server_cert_configured") is True
    assert state.get("tls_server_key_configured") is True

    print(json.dumps({"ok": True, "cert_serial": state.get("tls_certificate_serial")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
