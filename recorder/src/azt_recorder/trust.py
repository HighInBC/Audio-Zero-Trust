from __future__ import annotations

from dataclasses import dataclass

from .config import TrustConfig
from .models import DiscoveryAd


@dataclass
class TrustDecision:
    authorized: bool
    reason: str



def evaluate_discovery_ad(ad: DiscoveryAd, trust: TrustConfig) -> TrustDecision:
    device_fp = ad.device_key_fingerprint_hex.lower().strip()
    admin_fp = ad.admin_key_fingerprint_hex.lower().strip()
    cert_serial = ad.certificate_serial.strip()

    # explicit device allow always works
    if device_fp in trust.allow_device_fingerprints:
        return TrustDecision(True, "device_allowlist_match")

    # admin path requires both allowlist match and certification signal
    if admin_fp in trust.allow_admin_fingerprints:
        if trust.require_certificate_for_admin_auth and not cert_serial:
            return TrustDecision(False, "admin_allowlist_match_but_uncertified")
        return TrustDecision(True, "admin_allowlist_match_pending_verify")

    return TrustDecision(False, "no_allowlist_match")
