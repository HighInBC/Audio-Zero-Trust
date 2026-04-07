from __future__ import annotations

import asyncio
import base64
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
import urllib.request
import secrets
import hashlib
import ssl

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from .config import TrustConfig
from .models import DiscoveryAd


@dataclass
class VerifyResult:
    ok: bool
    reason: str
    authorized_consumers: tuple[str, ...] = ()


class TrustVerifier:
    def __init__(self, trust: TrustConfig) -> None:
        self._pubkeys: dict[str, bytes] = {}
        for item in trust.trusted_admin_keys:
            fp = str(item.get("fingerprint_hex", "")).strip().lower()
            if not fp:
                continue
            pub_raw: bytes | None = None
            pub_b64 = str(item.get("public_key_b64", "")).strip()
            if pub_b64:
                pub_raw = base64.b64decode(pub_b64)
            else:
                # Legacy PEM fallback (SPKI ed25519 public key)
                pem_path = str(item.get("public_key_pem_path", "")).strip()
                if pem_path:
                    pem = Path(pem_path).read_bytes()
                    pub = serialization.load_pem_public_key(pem)
                    pub_raw = pub.public_bytes(
                        serialization.Encoding.Raw,
                        serialization.PublicFormat.Raw,
                    )
            if pub_raw is None or len(pub_raw) != 32:
                continue
            calc_fp = hashlib.sha256(pub_raw).hexdigest()
            if calc_fp != fp:
                continue
            self._pubkeys[fp] = pub_raw
        self._cache: dict[tuple[str, str, str], VerifyResult] = {}

    async def verify_admin_certificate(self, ad: DiscoveryAd) -> VerifyResult:
        admin_fp = ad.admin_key_fingerprint_hex.strip().lower()
        cert_sn = ad.certificate_serial.strip()
        device_fp = ad.device_key_fingerprint_hex.strip().lower()

        if not admin_fp:
            return VerifyResult(False, "no_admin_fp")
        if not cert_sn:
            return VerifyResult(False, "no_certificate_serial")
        if admin_fp not in self._pubkeys:
            return VerifyResult(False, "admin_pubkey_unknown")

        ck = (device_fp, admin_fp, cert_sn)
        if ck in self._cache:
            return self._cache[ck]

        try:
            env = await asyncio.to_thread(self._fetch_cert_envelope, ad.api_https_url)
            payload_raw, sig_raw = self._parse_envelope(env)
            self._verify_signature(admin_fp, payload_raw, sig_raw)
            pobj = json.loads(payload_raw.decode("utf-8"))
            self._verify_payload_matches_ad(pobj, ad)
            self._verify_payload_time(pobj)
            self._verify_device_attestation(ad, pobj)
            consumers = self._authorized_consumers_from_payload(pobj)
            vr = VerifyResult(True, "certificate_and_attestation_verified", authorized_consumers=consumers)
        except Exception as e:
            vr = VerifyResult(False, f"certificate_verify_failed:{type(e).__name__}")

        self._cache[ck] = vr
        return vr

    @staticmethod
    def _fetch_cert_envelope(base_url: str) -> dict:
        insecure_tls = ssl._create_unverified_context()
        raw = urllib.request.urlopen(base_url + "/api/v0/device/certificate", timeout=8, context=insecure_tls).read().decode()
        doc = json.loads(raw)
        if not doc.get("ok"):
            raise ValueError("cert_get_not_ok")
        env = doc.get("certificate")
        if not isinstance(env, dict):
            raise ValueError("cert_env_missing")
        return env

    @staticmethod
    def _parse_envelope(env: dict) -> tuple[bytes, bytes]:
        if env.get("signature_algorithm") != "ed25519":
            raise ValueError("sig_alg_mismatch")
        payload_b64 = env.get("certificate_payload_b64")
        sig_b64 = env.get("signature_b64")
        if not isinstance(payload_b64, str) or not isinstance(sig_b64, str):
            raise ValueError("envelope_fields_missing")
        return base64.b64decode(payload_b64), base64.b64decode(sig_b64)

    def _verify_signature(self, admin_fp: str, payload_raw: bytes, sig_raw: bytes) -> None:
        pub_raw = self._pubkeys[admin_fp]
        ed25519.Ed25519PublicKey.from_public_bytes(pub_raw).verify(sig_raw, payload_raw)

    @staticmethod
    def _verify_payload_matches_ad(pobj: dict, ad: DiscoveryAd) -> None:
        if pobj.get("device_sign_fingerprint_hex", "").lower() != ad.device_key_fingerprint_hex.lower():
            raise ValueError("device_fp_mismatch")
        if pobj.get("admin_signer_fingerprint_hex", "").lower() != ad.admin_key_fingerprint_hex.lower():
            raise ValueError("admin_fp_mismatch")
        if str(pobj.get("certificate_serial", "")) != ad.certificate_serial:
            raise ValueError("cert_serial_mismatch")

    @staticmethod
    def _verify_payload_time(pobj: dict) -> None:
        issued_at = str(pobj.get("issued_at_utc", ""))
        vuntil = str(pobj.get("valid_until_utc", ""))
        t_issued = datetime.strptime(issued_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
        t_until = datetime.strptime(vuntil, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
        now = datetime.now(UTC)
        if t_issued > now:
            raise ValueError("cert_issued_in_future")
        if now > t_until:
            raise ValueError("cert_expired")

    @staticmethod
    def _authorized_consumers_from_payload(pobj: dict) -> tuple[str, ...]:
        vals = pobj.get("authorized_consumers", [])
        if not isinstance(vals, list):
            return ()
        out: list[str] = []
        for item in vals:
            if isinstance(item, str):
                tok = item.strip()
                if tok:
                    out.append(tok)
        return tuple(out)

    @staticmethod
    def _fetch_attestation(base_url: str, nonce: str) -> dict:
        insecure_tls = ssl._create_unverified_context()
        raw = urllib.request.urlopen(base_url + f"/api/v0/device/attestation?nonce={nonce}", timeout=8, context=insecure_tls).read().decode()
        doc = json.loads(raw)
        if not doc.get("ok"):
            raise ValueError("attestation_not_ok")
        return doc

    @staticmethod
    def _verify_device_attestation(ad: DiscoveryAd, cert_payload: dict) -> None:
        nonce = "rec-" + secrets.token_hex(12)
        att = TrustVerifier._fetch_attestation(ad.api_https_url, nonce)

        payload = att.get("payload")
        if not isinstance(payload, dict):
            raise ValueError("attestation_payload_missing")
        if payload.get("nonce") != nonce:
            raise ValueError("attestation_nonce_mismatch")
        if payload.get("device_sign_fingerprint_hex", "").lower() != ad.device_key_fingerprint_hex.lower():
            raise ValueError("attestation_device_fp_mismatch")
        if payload.get("device_sign_public_key_b64", "") != cert_payload.get("device_sign_public_key_b64", ""):
            raise ValueError("attestation_device_pubkey_mismatch")
        if att.get("signature_algorithm") != "ed25519":
            raise ValueError("attestation_sig_alg")

        sig = base64.b64decode(att.get("signature_b64", ""))
        pub_raw = base64.b64decode(payload.get("device_sign_public_key_b64", ""))
        msg = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        ed25519.Ed25519PublicKey.from_public_bytes(pub_raw).verify(sig, msg)
