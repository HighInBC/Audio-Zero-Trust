#!/usr/bin/env python3
from __future__ import annotations

import json
import shlex
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def run_json(cmd: str) -> dict:
    p = subprocess.run(shlex.split(cmd), cwd=str(ROOT), text=True, capture_output=True)
    raw = ((p.stdout or "") + (p.stderr or "")).strip()
    if p.returncode != 0:
        raise RuntimeError(f"command failed rc={p.returncode}: {cmd}\n{raw}")
    return json.loads(raw)


def main() -> int:
    pki = ROOT / "tools" / "pki"
    out = Path("/tmp/azt-ca-smoke-export.pem")

    # cleanup from prior runs
    for f in [pki / "ca_private_key.pem", pki / "ca_cert.pem", pki / "trusted_ca_cert.pem", out]:
        if f.exists():
            f.unlink()

    st0 = run_json("python3 tools/azt_tool.py tls-ca-status --json")
    assert st0["ok"] is True
    assert st0["payload"]["has_ca_private_key"] is False

    init = run_json("python3 tools/azt_tool.py tls-ca-init --json")
    assert init["ok"] is True
    fp = init["payload"]["ca_fingerprint_hex"]

    ex = run_json(f"python3 tools/azt_tool.py tls-ca-export --out {out} --json")
    assert ex["ok"] is True
    assert ex["payload"]["ca_fingerprint_hex"] == fp

    imp = run_json(f"python3 tools/azt_tool.py tls-ca-import --in {out} --json")
    assert imp["ok"] is True
    assert imp["payload"]["ca_fingerprint_hex"] == fp

    st1 = run_json("python3 tools/azt_tool.py tls-ca-status --json")
    assert st1["ok"] is True
    assert st1["payload"]["active_ca_fingerprint_hex"] == fp

    print(json.dumps({"ok": True, "ca_fingerprint_hex": fp}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
