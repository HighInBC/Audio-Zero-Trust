from __future__ import annotations

import json
import time
from pathlib import Path

from tools.azt_client.config import make_signed_config
from tools.azt_client.crypto import (
    gen_ed25519_keypair_with_fingerprint,
    gen_rsa_keypair_with_fingerprint,
    ed25519_fp_hex_from_private_key,
)

CLIENT_ROOT = Path(__file__).resolve().parents[3]


def create_signing_credentials(*, identity: str | None, identity_prefix: str) -> dict:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    ident = identity or f"{identity_prefix}-{stamp}"
    out_dir = CLIENT_ROOT / "tools" / "provisioned" / ident
    _pub_b64, fp, key_path = gen_ed25519_keypair_with_fingerprint(out_dir)
    return {
        "identity": ident,
        "fingerprint": fp,
        "artifacts": str(out_dir),
        "private_key": str(key_path),
        "kind": "signing",
    }


def create_decoding_credentials(*, identity: str | None, identity_prefix: str) -> dict:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    ident = identity or f"{identity_prefix}-{stamp}"
    out_dir = CLIENT_ROOT / "tools" / "provisioned" / ident
    _pub_pem, fp, key_path = gen_rsa_keypair_with_fingerprint(out_dir)
    return {
        "identity": ident,
        "fingerprint": fp,
        "artifacts": str(out_dir),
        "private_key": str(key_path),
        "kind": "decoding",
    }


def sign_config_file(*, in_path: str, key_path: str, out_path: str, fingerprint: str) -> dict:
    inp = Path(in_path)
    keyp = Path(key_path)
    outp = Path(out_path)
    unsigned_cfg = json.loads(inp.read_text())
    fp = fingerprint.strip() or ed25519_fp_hex_from_private_key(keyp)
    signed_cfg = make_signed_config(unsigned_cfg, keyp.read_bytes(), fp)
    outp.parent.mkdir(parents=True, exist_ok=True)
    outp.write_text(json.dumps(signed_cfg, indent=2) + "\n")
    return {"in": str(inp), "out": str(outp), "fingerprint": fp}


def key_fingerprint_from_private_key(*, key_path: str) -> str:
    return ed25519_fp_hex_from_private_key(Path(key_path))
