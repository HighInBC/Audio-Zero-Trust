from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519


def gen_rsa_keypair_with_fingerprint(out_dir: Path) -> tuple[str, str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()

    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    pub_pem = pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    der = pub.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fp = hashlib.sha256(der).hexdigest()

    priv_path = out_dir / "private_key.pem"
    (out_dir / "public_key.pem").write_bytes(pub_pem)
    priv_path.write_bytes(priv_pem)
    (out_dir / "fingerprint.txt").write_text(fp + "\n")
    return pub_pem.decode("utf-8"), fp, priv_path


def gen_ed25519_keypair_with_fingerprint(out_dir: Path) -> tuple[str, str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()

    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_raw = pub.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    pub_b64 = base64.b64encode(pub_raw).decode("ascii")
    fp = hashlib.sha256(pub_raw).hexdigest()

    priv_path = out_dir / "private_key.pem"
    (out_dir / "public_key_b64.txt").write_text(pub_b64 + "\n")
    priv_path.write_bytes(priv_pem)
    (out_dir / "fingerprint.txt").write_text(fp + "\n")
    return pub_b64, fp, priv_path


def spki_fp_hex_from_private_key(priv_path: Path) -> str:
    priv = serialization.load_pem_private_key(priv_path.read_bytes(), password=None)
    pub_der = priv.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(pub_der).hexdigest()


def ed25519_fp_hex_from_private_key(priv_path: Path) -> str:
    priv = serialization.load_pem_private_key(priv_path.read_bytes(), password=None)
    pub_raw = priv.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(pub_raw).hexdigest()


def ed25519_public_b64_from_private_key(priv_path: Path) -> str:
    priv = serialization.load_pem_private_key(priv_path.read_bytes(), password=None)
    pub_raw = priv.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return base64.b64encode(pub_raw).decode("ascii")
