from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import yaml


@dataclass
class DiscoveryConfig:
    udp_port: int = 33333


@dataclass
class RecordingConfig:
    output_dir: str = "/data/recordings"
    hourly_rollover: bool = True
    reconnect_backoff_seconds: list[int] = field(default_factory=lambda: [1, 2, 5, 10, 30])
    auto_timestamp_on_complete: bool = True
    timestamp_tsa_url: str = "http://timestamp.digicert.com"


@dataclass
class TrustedAdminKey:
    fingerprint_hex: str
    public_key_pem_path: str


@dataclass
class TrustConfig:
    allow_device_fingerprints: list[str] = field(default_factory=list)
    allow_admin_fingerprints: list[str] = field(default_factory=list)
    require_certificate_for_admin_auth: bool = True
    trusted_admin_keys: list[dict] = field(default_factory=list)


@dataclass
class AppConfig:
    discovery: DiscoveryConfig = field(default_factory=DiscoveryConfig)
    recording: RecordingConfig = field(default_factory=RecordingConfig)
    trust: TrustConfig = field(default_factory=TrustConfig)



def _normalize_hex_list(values: list[str]) -> list[str]:
    out: list[str] = []
    for v in values:
        s = v.strip().lower()
        if s:
            out.append(s)
    return out


def load_config(path: str | Path) -> AppConfig:
    p = Path(path)
    raw = yaml.safe_load(p.read_text()) or {}

    cfg = AppConfig(
        discovery=DiscoveryConfig(**(raw.get("discovery") or {})),
        recording=RecordingConfig(**(raw.get("recording") or {})),
        trust=TrustConfig(**(raw.get("trust") or {})),
    )

    cfg.trust.allow_device_fingerprints = _normalize_hex_list(cfg.trust.allow_device_fingerprints)
    cfg.trust.allow_admin_fingerprints = _normalize_hex_list(cfg.trust.allow_admin_fingerprints)

    norm_keys: list[dict] = []
    for item in cfg.trust.trusted_admin_keys:
        if not isinstance(item, dict):
            continue
        fp = str(item.get("fingerprint_hex", "")).strip().lower()
        pem_path = str(item.get("public_key_pem_path", "")).strip()
        if fp and pem_path:
            norm_keys.append({"fingerprint_hex": fp, "public_key_pem_path": pem_path})
    cfg.trust.trusted_admin_keys = norm_keys

    return cfg
