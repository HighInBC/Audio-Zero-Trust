from __future__ import annotations

import base64
import getpass
import hashlib
import json
import os
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

try:
    from argon2.low_level import Type as Argon2Type, hash_secret_raw as argon2_hash_secret_raw
except Exception:  # optional dependency for wrapped key KDF
    Argon2Type = None
    argon2_hash_secret_raw = None


def _prompt_password_twice() -> str:
    p1 = getpass.getpass("Enter private key password: ")
    p2 = getpass.getpass("Re-enter private key password: ")
    if p1 != p2:
        raise ValueError("passwords do not match")
    if not p1:
        raise ValueError("password must not be empty")
    return p1


def _derive_wrap_key_pbkdf2(password: str, salt: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    return kdf.derive(password.encode("utf-8"))


def _derive_wrap_key_argon2id(password: str, salt: bytes, *, memory_kib: int, time_cost: int, parallelism: int) -> bytes:
    if argon2_hash_secret_raw is None or Argon2Type is None:
        raise RuntimeError("argon2-cffi not installed; install with: pip install argon2-cffi")
    return argon2_hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_kib,
        parallelism=parallelism,
        hash_len=32,
        type=Argon2Type.ID,
    )


def wrap_private_key_pem(priv_pem: bytes, *, password: str) -> bytes:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    # OWASP-ish interactive profile; tune later if needed.
    memory_kib = 65536
    time_cost = 3
    parallelism = 1
    key = _derive_wrap_key_argon2id(password, salt, memory_kib=memory_kib, time_cost=time_cost, parallelism=parallelism)
    ct = AESGCM(key).encrypt(nonce, priv_pem, None)
    obj = {
        "schema": "azt.private_key_wrap.v1",
        "kdf": "argon2id",
        "argon2_memory_kib": memory_kib,
        "argon2_time_cost": time_cost,
        "argon2_parallelism": parallelism,
        "salt_b64": base64.b64encode(salt).decode("ascii"),
        "cipher": "aes-256-gcm",
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "wrapped_key_b64": base64.b64encode(ct).decode("ascii"),
        "key_format": "pem",
    }
    return (json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8")


def _unwrap_if_wrapped(data: bytes, *, purpose: str = "private key") -> bytes:
    try:
        obj = json.loads(data.decode("utf-8"))
    except Exception:
        return data
    if not isinstance(obj, dict) or obj.get("schema") != "azt.private_key_wrap.v1":
        return data
    salt = base64.b64decode(obj["salt_b64"])
    nonce = base64.b64decode(obj["nonce_b64"])
    ct = base64.b64decode(obj["wrapped_key_b64"])
    kdf_name = str(obj.get("kdf") or "pbkdf2-hmac-sha256")
    pw = getpass.getpass(f"Password for {purpose}: ")
    if kdf_name == "argon2id":
        key = _derive_wrap_key_argon2id(
            pw,
            salt,
            memory_kib=int(obj.get("argon2_memory_kib", 65536)),
            time_cost=int(obj.get("argon2_time_cost", 3)),
            parallelism=int(obj.get("argon2_parallelism", 1)),
        )
    elif kdf_name == "pbkdf2-hmac-sha256":
        iterations = int(obj.get("iterations", 200000))
        key = _derive_wrap_key_pbkdf2(pw, salt, iterations)
    else:
        raise ValueError(f"unsupported wrapped key kdf: {kdf_name}")
    try:
        return AESGCM(key).decrypt(nonce, ct, None)
    except Exception as e:
        raise ValueError("invalid password or wrapped key data") from e


def load_private_key_auto(source: Path | bytes, *, purpose: str = "private key"):
    data = source.read_bytes() if isinstance(source, Path) else source
    data = _unwrap_if_wrapped(data, purpose=purpose)
    try:
        return serialization.load_pem_private_key(data, password=None)
    except TypeError:
        # Encrypted PEM
        pw = getpass.getpass(f"Password for {purpose}: ")
        return serialization.load_pem_private_key(data, password=pw.encode("utf-8"))


def gen_rsa_keypair_with_fingerprint(out_dir: Path, *, password_protected: bool = False) -> tuple[str, str, Path]:
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
    if password_protected:
        priv_path.write_bytes(wrap_private_key_pem(priv_pem, password=_prompt_password_twice()))
    else:
        priv_path.write_bytes(priv_pem)
    (out_dir / "fingerprint.txt").write_text(fp + "\n")
    return pub_pem.decode("utf-8"), fp, priv_path


def gen_ed25519_keypair_with_fingerprint(out_dir: Path, *, password_protected: bool = False) -> tuple[str, str, Path]:
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
    if password_protected:
        priv_path.write_bytes(wrap_private_key_pem(priv_pem, password=_prompt_password_twice()))
    else:
        priv_path.write_bytes(priv_pem)
    (out_dir / "fingerprint.txt").write_text(fp + "\n")
    return pub_b64, fp, priv_path


def spki_fp_hex_from_private_key(priv_path: Path) -> str:
    priv = load_private_key_auto(priv_path, purpose=str(priv_path))
    pub_der = priv.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(pub_der).hexdigest()


def ed25519_fp_hex_from_private_key(priv_path: Path) -> str:
    priv = load_private_key_auto(priv_path, purpose=str(priv_path))
    pub_raw = priv.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(pub_raw).hexdigest()


def ed25519_public_b64_from_private_key(priv_path: Path) -> str:
    priv = load_private_key_auto(priv_path, purpose=str(priv_path))
    pub_raw = priv.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return base64.b64encode(pub_raw).decode("ascii")
