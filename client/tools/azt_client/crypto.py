from __future__ import annotations

import hashlib
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


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
    h = hashes.Hash(hashes.SHA256())
    h.update(der)
    fp = h.finalize().hex()

    priv_path = out_dir / "private_key.pem"
    (out_dir / "public_key.pem").write_bytes(pub_pem)
    priv_path.write_bytes(priv_pem)
    (out_dir / "fingerprint.txt").write_text(fp + "\n")
    return pub_pem.decode("utf-8"), fp, priv_path


def spki_fp_hex_from_private_key(priv_path: Path) -> str:
    priv = serialization.load_pem_private_key(priv_path.read_bytes(), password=None)
    pub_der = priv.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(pub_der).hexdigest()
