from __future__ import annotations

import hashlib
import os
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID

REPO_ROOT = Path(__file__).resolve().parents[4]
PKI_DIR = REPO_ROOT / "client" / "tools" / "pki"
CA_KEY = PKI_DIR / "ca_private_key.pem"
CA_CERT = PKI_DIR / "ca_cert.pem"
TRUSTED_CA_CERT = PKI_DIR / "trusted_ca_cert.pem"


def _fingerprint_hex(cert_pem: bytes) -> str:
    cert = x509.load_pem_x509_certificate(cert_pem)
    return cert.fingerprint(__import__("cryptography.hazmat.primitives.hashes", fromlist=["SHA256"]).SHA256()).hex()


def tls_ca_init(*, common_name: str = "Audio-Zero-Trust Local CA", force: bool = False) -> dict:
    PKI_DIR.mkdir(parents=True, exist_ok=True)

    if CA_KEY.exists() and CA_CERT.exists() and not force:
        cert_pem = CA_CERT.read_bytes()
        return {
            "created": False,
            "ca_key_path": str(CA_KEY),
            "ca_cert_path": str(CA_CERT),
            "ca_fingerprint_hex": _fingerprint_hex(cert_pem),
        }

    key = ed25519.Ed25519PrivateKey.generate()

    now = datetime.now(timezone.utc)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=False, content_commitment=False,
                                     data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                     crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        .sign(private_key=key, algorithm=None)
    )

    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    CA_KEY.write_bytes(key_pem)
    CA_CERT.write_bytes(cert_pem)
    os.chmod(CA_KEY, 0o600)
    os.chmod(CA_CERT, 0o644)

    return {
        "created": True,
        "ca_key_path": str(CA_KEY),
        "ca_cert_path": str(CA_CERT),
        "ca_fingerprint_hex": _fingerprint_hex(cert_pem),
    }


def tls_ca_export(*, out_path: str) -> dict:
    if CA_CERT.exists():
        src = CA_CERT
    elif TRUSTED_CA_CERT.exists():
        src = TRUSTED_CA_CERT
    else:
        raise FileNotFoundError("no CA cert available; run tls-ca-init or tls-ca-import first")

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, out)
    return {
        "exported": True,
        "source": str(src),
        "out": str(out),
        "ca_fingerprint_hex": _fingerprint_hex(out.read_bytes()),
    }


def tls_ca_import(*, in_path: str) -> dict:
    src = Path(in_path)
    if not src.exists():
        raise FileNotFoundError(f"CA cert not found: {src}")

    pem = src.read_bytes()
    # validate cert parse
    _ = x509.load_pem_x509_certificate(pem)

    PKI_DIR.mkdir(parents=True, exist_ok=True)
    TRUSTED_CA_CERT.write_bytes(pem)
    os.chmod(TRUSTED_CA_CERT, 0o644)
    return {
        "imported": True,
        "in": str(src),
        "trusted_ca_cert_path": str(TRUSTED_CA_CERT),
        "ca_fingerprint_hex": _fingerprint_hex(pem),
    }


def tls_ca_status() -> dict:
    payload: dict = {
        "pki_dir": str(PKI_DIR),
        "has_ca_private_key": CA_KEY.exists(),
        "has_ca_cert": CA_CERT.exists(),
        "has_trusted_ca_cert": TRUSTED_CA_CERT.exists(),
    }
    if CA_CERT.exists():
        payload["active_ca_cert_path"] = str(CA_CERT)
        payload["active_ca_fingerprint_hex"] = _fingerprint_hex(CA_CERT.read_bytes())
    elif TRUSTED_CA_CERT.exists():
        payload["active_ca_cert_path"] = str(TRUSTED_CA_CERT)
        payload["active_ca_fingerprint_hex"] = _fingerprint_hex(TRUSTED_CA_CERT.read_bytes())
    else:
        payload["active_ca_cert_path"] = ""
        payload["active_ca_fingerprint_hex"] = ""
    return payload
