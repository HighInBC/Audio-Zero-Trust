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
    api_tls_port: int
    stream_tls_port: int
    certificate_serial: str
    raw: dict[str, Any]

    @property
    def api_url(self) -> str:
        port = self.api_tls_port or self.http_port
        return f"https://{self.source_ip}:{port}"

    @property
    def stream_url(self) -> str:
        port = self.stream_tls_port or self.http_port
        return f"https://{self.source_ip}:{port}"
