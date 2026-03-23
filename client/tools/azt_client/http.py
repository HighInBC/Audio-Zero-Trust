from __future__ import annotations

import json
import os
import ssl
import urllib.error
from urllib.request import Request, urlopen


def _ssl_context_for_url(url: str):
    if not url.startswith("https://"):
        return None
    insecure = os.getenv("AZT_TLS_INSECURE", "").strip().lower() in {"1", "true", "yes", "on"}
    if insecure:
        return ssl._create_unverified_context()

    ca_override = os.getenv("AZT_TLS_CA_CERT", "").strip()
    if ca_override:
        return ssl.create_default_context(cafile=ca_override)

    # Prefer imported verifier cert, then local issuer cert if present.
    candidates = [
        "client/tools/pki/trusted_ca_cert.pem",
        "client/tools/pki/ca_cert.pem",
    ]
    for p in candidates:
        if os.path.exists(p):
            return ssl.create_default_context(cafile=p)

    return ssl.create_default_context()


def http_json(method: str, url: str, payload: dict | None = None, timeout: int = 10) -> dict:
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = Request(url, data=data, method=method, headers=headers)
    ctx = _ssl_context_for_url(url)
    try:
        with urlopen(req, timeout=timeout, context=ctx) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        try:
            return json.loads(body)
        except Exception:
            return {"ok": False, "error": f"HTTP_{e.code}", "detail": body}


def get_json(url: str, timeout: int = 10) -> dict:
    return http_json("GET", url, timeout=timeout)
