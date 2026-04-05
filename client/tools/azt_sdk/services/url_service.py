from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[4]


def _has_local_tls_trust() -> bool:
    pki = REPO_ROOT / "client" / "tools" / "pki"
    return (pki / "trusted_ca_cert.pem").exists() or (pki / "ca_cert.pem").exists()


def _normalize(*, host: str, port: int, scheme: str, tls_port: int) -> str:
    h = (host or "").strip()
    if h.startswith("http://") or h.startswith("https://"):
        return h.rstrip("/")

    s = (scheme or "auto").strip().lower()
    p = int(port)
    if s == "auto":
        if _has_local_tls_trust():
            s = "https"
            if p == 8080:
                p = tls_port
        else:
            s = "http"
    return f"{s}://{h}:{p}"


def base_url(*, host: str, port: int, scheme: str = "auto") -> str:
    return _normalize(host=host, port=port, scheme=scheme, tls_port=8443)


def stream_base_url(*, host: str, port: int, scheme: str = "auto") -> str:
    return _normalize(host=host, port=port, scheme=scheme, tls_port=8444)
