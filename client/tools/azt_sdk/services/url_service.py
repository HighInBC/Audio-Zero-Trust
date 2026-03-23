from __future__ import annotations


def base_url(*, host: str, port: int, scheme: str = "http") -> str:
    h = (host or "").strip()
    if h.startswith("http://") or h.startswith("https://"):
        return h.rstrip("/")
    return f"{scheme}://{h}:{int(port)}"
