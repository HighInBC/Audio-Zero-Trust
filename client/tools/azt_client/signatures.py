"""Explicit AZT signature profiles. RSA-PSS parameters are fixed by the profile name."""
from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa


@dataclass(frozen=True)
class SigningKey:
    algorithm: str
    key: ed25519.Ed25519PublicKey | rsa.RSAPublicKey

    @property
    def signature_size(self) -> int:
        return 64 if self.algorithm == "ed25519" else self.key.key_size // 8

    def verify(self, signature: bytes, message: bytes) -> None:
        if len(signature) != self.signature_size:
            raise ValueError("ERR_SIGNATURE_LENGTH")
        if self.algorithm == "ed25519":
            self.key.verify(signature, message)
        else:
            self.key.verify(signature, message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())


def stream_signing_key(outer: dict, inner: dict | None = None) -> SigningKey | None:
    finalize_domain(outer, inner)
    # Missing descriptors belong to historical Ed25519 files. Never infer RSA from key bytes.
    algorithm = outer.get("this_header_signature_alg", "ed25519")
    if algorithm not in ("ed25519", "rsa-pss-sha256"):
        raise ValueError("ERR_UNSUPPORTED_SIGNATURE_ALG")
    for header in (outer, inner or {}):
        if header.get("signature_checkpoint_alg", algorithm) != algorithm:
            raise ValueError("ERR_SIGNATURE_ALG_MISMATCH")
    outer_raw = outer.get("this_header_signing_key_b64")
    inner_raw = (inner or {}).get("device_sign_public_key_b64")
    if outer_raw and inner_raw and outer_raw != inner_raw:
        raise ValueError("ERR_SIGNING_KEY_MISMATCH")
    encoded = outer_raw or inner_raw
    if not encoded:
        if algorithm != "ed25519":
            raise ValueError("ERR_SIGNING_KEY_REQUIRED")
        return None
    raw = base64.b64decode(encoded, validate=True)
    if algorithm == "ed25519":
        key = ed25519.Ed25519PublicKey.from_public_bytes(raw)
        fingerprint_alg = "sha256-raw-ed25519-pub"
    else:
        key = serialization.load_der_public_key(raw)
        if not isinstance(key, rsa.RSAPublicKey) or key.key_size not in (2048, 3072, 4096):
            raise ValueError("ERR_RSA_SIGNING_KEY")
        canonical = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        if canonical != raw:
            raise ValueError("ERR_SIGNING_KEY_ENCODING")
        fingerprint_alg = "sha256-spki-der"
        if outer.get("this_header_signing_key_fingerprint_alg") != fingerprint_alg:
            raise ValueError("ERR_SIGNING_KEY_FP_ALG")
        if not outer.get("this_header_signing_key_fingerprint_hex"):
            raise ValueError("ERR_SIGNING_KEY_FP_REQUIRED")
    declared_alg = outer.get("this_header_signing_key_fingerprint_alg")
    if declared_alg is not None and declared_alg != fingerprint_alg:
        raise ValueError("ERR_SIGNING_KEY_FP_ALG")
    fingerprint = hashlib.sha256(raw).hexdigest()
    for value in (outer.get("this_header_signing_key_fingerprint_hex"), (inner or {}).get("device_sign_fingerprint_hex")):
        if value is not None and value != fingerprint:
            raise ValueError("ERR_SIGNING_KEY_FP_MISMATCH")
    return SigningKey(algorithm, key)


def signature_body_size(key: SigningKey | None) -> int:
    return 4 + (key.signature_size if key else 64)


FINALIZE_PROFILE = "azt-finalize-v1"
FINALIZE_DOMAIN_DESCRIPTION = "AZT1FINAL1||ref_seq_u32be||chain_v32"


def finalize_domain(outer: dict, inner: dict | None = None) -> bytes:
    """Select only from the authenticated header declaration, never signature fallback.

    Absence means legacy shared-domain signatures: valid prefix coverage, but no
    authenticated distinction between checkpoint and termination intent.
    """
    fields = ("finalize_signature_profile", "finalize_signature_domain")
    if not any(k in outer for k in fields):
        if inner is not None and any(k in inner for k in fields):
            raise ValueError("ERR_FINALIZE_PROFILE_MISMATCH")
        return b"AZT1SIG1"
    if outer.get(fields[0]) != FINALIZE_PROFILE or outer.get(fields[1]) != FINALIZE_DOMAIN_DESCRIPTION:
        raise ValueError("ERR_UNSUPPORTED_FINALIZE_PROFILE")
    if inner is not None:
        if any(inner.get(k) != outer[k] for k in fields):
            raise ValueError("ERR_FINALIZE_PROFILE_MISMATCH")
        # This revision explicitly requires agreement of duplicated header fields.
        if any(outer[k] != inner[k] for k in outer.keys() & inner.keys()):
            raise ValueError("ERR_DUPLICATED_HEADER_FIELD_MISMATCH")
    return b"AZT1FINAL1"


def finalization_info(domain: bytes, seen: bool, signature_verified: bool) -> dict:
    authenticated = bool(seen and signature_verified and domain == b"AZT1FINAL1")
    return {
        "finalize_seen": seen,  # Compatibility: marker presence, never a trust claim.
        "finalize_signature_verified": signature_verified,
        "finalization_intent_authenticated": authenticated,
        "finalize_signature_profile": FINALIZE_PROFILE if domain == b"AZT1FINAL1" else "legacy-shared-checkpoint-domain",
        "termination_status": "authenticated-finalize" if authenticated else
            "legacy-finalize-unbound" if seen and domain == b"AZT1SIG1" else
            "unverified-finalize" if seen else "unfinished",
        "finalization_warning": "Legacy finalizer does not authenticate termination intent; signed prefix coverage remains valid." if seen and domain == b"AZT1SIG1" else None,
    }


def load_container_json(raw: str | bytes) -> dict:
    """Reject ambiguous duplicate JSON keys in container headers/certificates."""
    import json
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("ERR_DUPLICATE_JSON_KEY")
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError("ERR_HEADER_JSON_OBJECT")
    return value
