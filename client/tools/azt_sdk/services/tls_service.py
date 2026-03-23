from __future__ import annotations

import hashlib
import os
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
import base64
import json
import ipaddress

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID

from tools.azt_client.crypto import ed25519_fp_hex_from_private_key
from tools.azt_client.http import get_json, http_json
from tools.azt_sdk.services.url_service import base_url

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

    key = ec.generate_private_key(ec.SECP256R1())

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
        .sign(private_key=key, algorithm=hashes.SHA256())
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


def _load_ca_signer() -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    if not (CA_KEY.exists() and CA_CERT.exists()):
        tls_ca_init()
    key = serialization.load_pem_private_key(CA_KEY.read_bytes(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise RuntimeError("local CA private key is not EC")
    cert = x509.load_pem_x509_certificate(CA_CERT.read_bytes())
    return key, cert


def tls_cert_issue_and_install(*, host: str, port: int, timeout: int, admin_key_path: str, cert_serial: str, valid_days: int = 180) -> dict:
    ca_key, ca_cert = _load_ca_signer()

    b = base_url(host=host, port=port, scheme=os.getenv("AZT_SCHEME", "auto"))
    csr_res = get_json(f"{b}/api/v0/tls/csr", timeout=timeout)
    if not csr_res.get("ok"):
        raise RuntimeError(f"tls csr fetch failed: {csr_res}")

    public_key_pem = str(csr_res.get("public_key_pem") or "")
    dev_fp = str(csr_res.get("device_sign_fingerprint_hex") or "")
    chip_id = str(csr_res.get("device_chip_id_hex") or "")
    if not public_key_pem or not dev_fp or not chip_id:
        raise RuntimeError("tls csr response missing required fields")

    # Generate dedicated TLS server keypair (P-256). Device stores this private key.
    tls_key = ec.generate_private_key(ec.SECP256R1())
    pub = tls_key.public_key()

    now = datetime.now(timezone.utc)
    san_entries: list[x509.GeneralName] = []
    h = (host or "").strip()
    try:
        san_entries.append(x509.IPAddress(ipaddress.ip_address(h)))
    except Exception:
        if h:
            san_entries.append(x509.DNSName(h))

    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"azt-device-{chip_id}")]))
        .issuer_name(ca_cert.subject)
        .public_key(pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=max(1, int(valid_days))))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    if san_entries:
        builder = builder.add_extension(x509.SubjectAlternativeName(san_entries), critical=False)

    cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

    server_cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    server_key_pem = tls_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode("utf-8")
    ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    admin_fp = ed25519_fp_hex_from_private_key(Path(admin_key_path))
    admin_priv = serialization.load_pem_private_key(Path(admin_key_path).read_bytes(), password=None)
    if not isinstance(admin_priv, ed25519.Ed25519PrivateKey):
        raise RuntimeError("admin key must be Ed25519 private key")

    payload_obj = {
        "device_sign_fingerprint_hex": dev_fp,
        "device_chip_id_hex": chip_id,
        "admin_signer_fingerprint_hex": admin_fp,
        "tls_certificate_serial": cert_serial,
        "tls_server_certificate_pem": server_cert_pem,
        "tls_server_private_key_pem": server_key_pem,
        "tls_ca_certificate_pem": ca_cert_pem,
    }
    payload_raw = json.dumps(payload_obj, separators=(",", ":")).encode("utf-8")
    sig_b64 = base64.b64encode(admin_priv.sign(payload_raw)).decode("ascii")

    req = {
        "tls_payload_b64": base64.b64encode(payload_raw).decode("ascii"),
        "signature_algorithm": "ed25519",
        "signature_b64": sig_b64,
    }
    post = http_json("POST", f"{b}/api/v0/tls/cert", req, timeout=timeout)
    if not post.get("ok"):
        raise RuntimeError(f"tls cert post failed: {post}")

    tls_state = get_json(f"{b}/api/v0/tls/state", timeout=timeout)
    return {
        "csr": csr_res,
        "install_response": post,
        "tls_state": tls_state,
        "ca_cert_path": str(CA_CERT),
        "ca_fingerprint_hex": _fingerprint_hex(CA_CERT.read_bytes()),
        "https_usage_hint": {
            "scheme_env": "AZT_SCHEME=https",
            "ca_env": f"AZT_TLS_CA_CERT={CA_CERT}",
            "api_https_port": 8443,
            "api_http_port": 8080,
            "stream_http_port": 8081,
        },
    }
