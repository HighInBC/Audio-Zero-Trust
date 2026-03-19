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
    raw: dict[str, Any]

    @property
    def base_url(self) -> str:
        return f"http://{self.source_ip}:{self.http_port}"
