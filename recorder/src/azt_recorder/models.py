from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class DiscoveryAd:
    source_ip: str
    source_port: int
    discovery_version: int
    device_type: str
    device_key_fingerprint_hex: str
    admin_key_fingerprint_hex: str
    device_name: str
    http_port: int
    certificate_serial: str
    recorder_auth_fingerprint_hex: str
    cert_auto_record: bool
    cert_auto_decode: bool
    raw: dict[str, Any]

    @property
    def base_url(self) -> str:
        # Legacy API base (kept for compatibility with older callers).
        return f"http://{self.source_ip}:{self.http_port}"

    @property
    def api_https_url(self) -> str:
        https_port = int(self.raw.get("https_port", 8443) or 8443)
        return f"https://{self.source_ip}:{https_port}"

    @property
    def stream_http_url(self) -> str:
        stream_port = int(self.raw.get("stream_port", 8081) or 8081)
        return f"http://{self.source_ip}:{stream_port}"
