from __future__ import annotations

import base64
import json
import struct
import wave
from pathlib import Path
from urllib.request import urlopen

from cryptography.hazmat.primitives import hashes, hmac, serialization
import hashlib
from cryptography.hazmat.primitives.asymmetric import ed25519, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from tools.azt_client.crypto import load_private_key_auto


def fetch_stream_sample(host: str, port: int, seconds: int, out_path: Path) -> dict:
    url = f"http://{host}:{port}/stream?seconds={seconds}"
    data = urlopen(url, timeout=30 + seconds).read()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(data)
    return {"url": url, "bytes": len(data), "out": str(out_path)}


def _b64d(s: str) -> bytes:
    return base64.b64decode(s, validate=True)


def _extract_auto_grants(plain: dict) -> dict:
    cert_consumers: set[str] = set()
    cert_doc = plain.get("device_certificate")
    if isinstance(cert_doc, dict):
        payload_b64 = cert_doc.get("certificate_payload_b64")
        if isinstance(payload_b64, str) and payload_b64:
            payload_raw = _b64d(payload_b64)
            payload = json.loads(payload_raw.decode("utf-8"))
            consumers = payload.get("authorized_consumers") or []
            if isinstance(consumers, list):
                for c in consumers:
                    if isinstance(c, str):
                        cert_consumers.add(c)

    header_auto_record = bool(plain.get("stream_header_auto_record") is True)
    header_auto_decode = bool(plain.get("stream_header_auto_decode") is True)

    cert_auto_record = "auto-record" in cert_consumers
    cert_auto_decode = "auto-decode" in cert_consumers

    return {
        "certificate_authorized_consumers": sorted(cert_consumers),
        "header_auto_record": header_auto_record,
        "header_auto_decode": header_auto_decode,
        "certificate_auto_record": cert_auto_record,
        "certificate_auto_decode": cert_auto_decode,
        "effective_auto_record": cert_auto_record and header_auto_record,
        "effective_auto_decode": cert_auto_decode and header_auto_decode,
    }


def validate_azt1_stream_chain(data: bytes, admin_private_key_pem: bytes | None = None) -> dict:
    priv = load_private_key_auto(admin_private_key_pem, purpose="stream private key") if admin_private_key_pem else None

    if not data.startswith(b"AZT1\n"):
        raise ValueError("ERR_MAGIC")
    off = 5
    nl = data.find(b"\n", off)
    if nl < 0:
        raise ValueError("ERR_HEADER_JSON")
    plain_line = data[off:nl]
    plain = json.loads(plain_line.decode("utf-8"))
    off = nl + 1

    sig_nl = data.find(b"\n", off)
    if sig_nl < 0:
        raise ValueError("ERR_HEADER_SIG_LINE")
    outer_sig_b64 = data[off:sig_nl].decode("utf-8")
    off = sig_nl + 1

    if plain.get("version") not in (0, 1):
        raise ValueError("ERR_VERSION")

    next_fp_hex = plain.get("next_header_recipient_key_fingerprint_hex", plain.get("header_key_fingerprint_hex"))
    if priv is not None:
        pub_der = priv.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        hh = hashes.Hash(hashes.SHA256())
        hh.update(pub_der)
        if next_fp_hex != hh.finalize().hex():
            raise ValueError("ERR_KEY_FP_MISMATCH")

    if plain.get("next_header_plaintext_hash_alg") != "sha256":
        raise ValueError("ERR_PLAIN_HEADER_HASH_ALG")

    enc_header_len = struct.unpack(">H", data[off : off + 2])[0]
    off += 2

    header_plaintext_hash_verified = False
    header_encrypted_block_hash_verified = False
    next_header_mode = "encrypted"
    dec = None
    header_ct = b""

    if enc_header_len == 0xFFFF:
        next_header_mode = "decoded"
        dec_nl = data.find(b"\n", off)
        if dec_nl < 0:
            raise ValueError("ERR_PLAINTEXT_NEXT_HEADER_FORMAT")
        header_pt = data[off:dec_nl]
        off = dec_nl + 1
        dec = json.loads(header_pt.decode("utf-8"))

        plain_hash_b64 = plain.get("next_header_plaintext_sha256_b64")
        if not isinstance(plain_hash_b64, str) or not plain_hash_b64:
            raise ValueError("ERR_PLAINTEXT_NEXT_HEADER_HASH_FIELD")
        hp = hashes.Hash(hashes.SHA256())
        hp.update(header_pt)
        if hp.finalize() != _b64d(plain_hash_b64):
            raise ValueError("ERR_PLAINTEXT_NEXT_HEADER_HASH")
        header_plaintext_hash_verified = True
    else:
        header_ct = data[off : off + enc_header_len]
        off += enc_header_len

        # Always verify encrypted next-header blob commitment from plaintext header.
        exp_len = plain.get("next_header_ciphertext_len")
        if isinstance(exp_len, int) and exp_len != len(header_ct):
            raise ValueError("ERR_ENCRYPTED_NEXT_HEADER_LEN")
        exp_ct_hash_b64 = plain.get("next_header_ciphertext_sha256_b64")
        if isinstance(exp_ct_hash_b64, str) and exp_ct_hash_b64:
            hh = hashes.Hash(hashes.SHA256())
            hh.update(header_ct)
            if hh.finalize() != _b64d(exp_ct_hash_b64):
                raise ValueError("ERR_ENCRYPTED_NEXT_HEADER_HASH")
            header_encrypted_block_hash_verified = True

        if priv is not None:
            wrapped = _b64d(plain.get("next_header_wrapped_key_b64", plain.get("wrapped_header_key_b64")))
            header_key = priv.decrypt(wrapped, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            header_nonce = _b64d(plain.get("next_header_nonce_b64", plain.get("header_nonce_b64")))
            header_tag = _b64d(plain.get("next_header_tag_b64", plain.get("header_tag_b64")))
            header_pt = AESGCM(header_key).decrypt(header_nonce, header_ct + header_tag, None)
            dec = json.loads(header_pt.decode("utf-8"))

            plain_hash_b64 = plain.get("next_header_plaintext_sha256_b64")
            if not isinstance(plain_hash_b64, str) or not plain_hash_b64:
                raise ValueError("ERR_PLAINTEXT_NEXT_HEADER_HASH_FIELD")
            hp = hashes.Hash(hashes.SHA256())
            hp.update(header_pt)
            if hp.finalize() != _b64d(plain_hash_b64):
                raise ValueError("ERR_PLAINTEXT_NEXT_HEADER_HASH")
            header_plaintext_hash_verified = True

    # Chain verification is over framed record bytes; can run without decrypt key.
    chain_alg = str((dec or plain).get("chain_alg", "sha256-link"))
    chain_domain = str((dec or plain).get("chain_domain", "AZT1-CHAIN-V1"))
    nonce_hash = hashlib.sha256(str(plain.get("stream_auth_nonce") or "").encode("utf-8")).digest()
    v_prev = None
    chain_key = _b64d(dec["chain_key_b64"]) if (dec is not None and "chain_key_b64" in dec) else None
    chain_genesis_secret = _b64d(dec["chain_genesis_secret_b64"]) if (dec is not None and "chain_genesis_secret_b64" in dec) else None
    require_block1_sig0 = bool((dec or plain).get("block1_must_be_signature_ref_seq0") is True)

    device_sign_pub = None
    if dec is not None and "device_sign_public_key_b64" in dec:
        device_sign_pub_raw = _b64d(dec["device_sign_public_key_b64"])
        device_sign_pub = ed25519.Ed25519PublicKey.from_public_bytes(device_sign_pub_raw)
    elif isinstance(plain.get("this_header_signing_key_b64"), str) and plain.get("this_header_signing_key_b64"):
        device_sign_pub_raw = _b64d(plain.get("this_header_signing_key_b64"))
        device_sign_pub = ed25519.Ed25519PublicKey.from_public_bytes(device_sign_pub_raw)

    header_sig_verified = False
    if device_sign_pub is not None:
        outer_sig = _b64d(outer_sig_b64)
        device_sign_pub.verify(outer_sig, plain_line)
        header_sig_verified = True

    # Optional certificate-in-header consistency checks (provenance binding).
    cert_in_header = isinstance(plain.get("device_certificate"), dict)
    if cert_in_header and dec is not None:
        cert_doc = plain.get("device_certificate")
        cert_payload_b64 = cert_doc.get("certificate_payload_b64")
        if not isinstance(cert_payload_b64, str) or not cert_payload_b64:
            raise ValueError("ERR_DEVICE_CERT_SCHEMA")
        cert_payload_raw = _b64d(cert_payload_b64)
        cert_payload = json.loads(cert_payload_raw.decode("utf-8"))
        if cert_payload.get("device_sign_public_key_b64") != dec.get("device_sign_public_key_b64"):
            raise ValueError("ERR_DEVICE_CERT_BINDING")
        cert_fp = cert_payload.get("device_sign_fingerprint_hex")
        if cert_fp is None:
            # Backward-compatible alias if older cert payloads used this name.
            cert_fp = cert_payload.get("device_sign_public_key_fingerprint_hex")
        if cert_fp != dec.get("device_sign_fingerprint_hex"):
            raise ValueError("ERR_DEVICE_CERT_BINDING")
        if cert_payload.get("device_chip_id_hex") != plain.get("device_chip_id_hex"):
            raise ValueError("ERR_DEVICE_CERT_BINDING")
        header_cert_serial = plain.get("device_certificate_serial")
        if isinstance(header_cert_serial, str) and header_cert_serial:
            if cert_payload.get("certificate_serial") != header_cert_serial:
                raise ValueError("ERR_DEVICE_CERT_SERIAL")

    audio_key = _b64d(dec["audio_key_b64"]) if dec is not None else None
    nonce_prefix = _b64d(dec["audio_nonce_prefix_b64"]) if dec is not None else None

    frames = pcm_bytes = pcm_blocks = sig_blocks = sig_verified = 0
    dropped_notice_blocks = dropped_frames_total = telemetry_blocks = 0
    seq_to_chain_v: dict[int, bytes] = {}
    max_verified_ref_seq = 0
    finalize_seen = False

    record_types: list[int] = []
    record_seqs: list[int] = []
    while off < len(data):
        if off + 10 > len(data):
            break
        seq = struct.unpack(">I", data[off : off + 4])[0]
        off += 4
        block_type = data[off]
        off += 1
        body_len = struct.unpack(">I", data[off : off + 4])[0]
        off += 4
        tag_len = data[off]
        off += 1
        if off + body_len + tag_len + 32 > len(data):
            break
        if finalize_seen:
            raise ValueError("ERR_FINALIZE_NOT_LAST")

        body = data[off : off + body_len]
        off += body_len
        tag = data[off : off + tag_len]
        off += tag_len
        v_cur = data[off : off + 32]
        off += 32

        record_seqs.append(seq)
        record_types.append(block_type)

        if require_block1_sig0 and seq == 1 and block_type != 0x01:
            raise ValueError("ERR_BLOCK1_MUST_BE_SIG")

        if chain_alg == "sha256-link":
            core = struct.pack(">I", seq) + bytes([block_type]) + struct.pack(">I", body_len) + bytes([tag_len]) + body + tag
            if chain_domain == "AZT1-CHAIN-V1-NONCE":
                if seq == 1:
                    v_calc = hashlib.sha256(b"AZT1-CHAIN-V1-NONCE" + nonce_hash + core).digest()
                else:
                    if v_prev is None:
                        raise ValueError("ERR_CHAIN_STATE")
                    v_calc = hashlib.sha256(b"AZT1-CHAIN-V1-NONCE" + nonce_hash + v_prev + core).digest()
            else:
                if seq == 1:
                    v_calc = hashlib.sha256(b"AZT1-CHAIN-V1" + core).digest()
                else:
                    if v_prev is None:
                        raise ValueError("ERR_CHAIN_STATE")
                    v_calc = hashlib.sha256(b"AZT1-CHAIN-V1" + v_prev + core).digest()
            if v_calc != v_cur:
                raise ValueError("ERR_CHAIN")
        elif chain_alg == "hmac-sha256-link":
            if chain_key is None:
                raise ValueError("ERR_CHAIN_STATE")
            hm = hmac.HMAC(chain_key, hashes.SHA256())
            hm.update(b"AZT1-CHAIN-V2")
            if seq > 1:
                if v_prev is None:
                    raise ValueError("ERR_CHAIN_STATE")
                hm.update(v_prev)
            hm.update(struct.pack(">I", seq))
            hm.update(bytes([block_type]))
            hm.update(struct.pack(">I", body_len))
            hm.update(bytes([tag_len]))
            hm.update(body)
            hm.update(tag)
            if hm.finalize() != v_cur:
                raise ValueError("ERR_CHAIN")
        else:
            raise ValueError("ERR_CHAIN_ALG")
        v_prev = v_cur
        seq_to_chain_v[seq] = v_cur

        if block_type in (0x00, 0x03):
            if tag_len != 16:
                raise ValueError("ERR_TAG_LEN")
            if audio_key is not None and nonce_prefix is not None:
                nonce = nonce_prefix + struct.pack(">I", seq) + b"\x00\x00\x00\x00"
                block_body = AESGCM(audio_key).decrypt(nonce, body + tag, None)
            else:
                block_body = b""
        elif block_type in (0x01, 0x02, 0x7E, 0x7F):
            if tag_len != 0:
                raise ValueError("ERR_TAG_LEN")
            block_body = body
        else:
            raise ValueError(f"ERR_BLOCK_TYPE:{block_type}")

        if block_type == 0x00:
            pcm_bytes += len(block_body)
            pcm_blocks += 1
        elif block_type == 0x01:
            sig_blocks += 1
            if require_block1_sig0 and seq == 1:
                if len(block_body) < 68:
                    raise ValueError("ERR_BLOCK1_SIG_FORMAT")
                first_ref = struct.unpack(">I", block_body[:4])[0]
                if first_ref != 0:
                    raise ValueError("ERR_BLOCK1_SIG_REF")
            if len(block_body) >= 68:
                ref_seq = struct.unpack(">I", block_body[:4])[0]
                sig = block_body[4:68]
                if device_sign_pub is not None:
                    if ref_seq == 0:
                        if chain_genesis_secret is None:
                            raise ValueError("ERR_GENESIS_SECRET_MISSING")
                        msg = b"AZT1SIG0" + chain_genesis_secret
                        device_sign_pub.verify(sig, msg)
                        sig_verified += 1
                    elif ref_seq in seq_to_chain_v:
                        msg = b"AZT1SIG1" + struct.pack(">I", ref_seq) + seq_to_chain_v[ref_seq]
                        device_sign_pub.verify(sig, msg)
                        sig_verified += 1
                        if ref_seq > max_verified_ref_seq:
                            max_verified_ref_seq = ref_seq
        elif block_type == 0x02:
            dropped_notice_blocks += 1
            if len(block_body) >= 2:
                dropped_frames_total += struct.unpack(">H", block_body[:2])[0]
        elif block_type == 0x03:
            telemetry_blocks += 1
        elif block_type == 0x7E:
            pass
        elif block_type == 0x7F:
            finalize_seen = True
            if len(block_body) < 68:
                raise ValueError("ERR_FINALIZE_FORMAT")
            ref_seq = struct.unpack(">I", block_body[:4])[0]
            sig = block_body[4:68]
            if ref_seq == 0 or ref_seq not in seq_to_chain_v:
                raise ValueError("ERR_FINALIZE_REF")
            if device_sign_pub is not None:
                msg = b"AZT1SIG1" + struct.pack(">I", ref_seq) + seq_to_chain_v[ref_seq]
                device_sign_pub.verify(sig, msg)
                sig_verified += 1
                if ref_seq > max_verified_ref_seq:
                    max_verified_ref_seq = ref_seq
        frames += 1

    frame_duration_ms = float((dec or plain).get("audio_frame_duration_ms", 0.0))
    estimated_frames = pcm_blocks + dropped_frames_total
    est = (estimated_frames * frame_duration_ms) / 1000.0 if frame_duration_ms > 0 else None

    unsigned_tail_bytes = max(0, len(data) - off)

    # Exact unsigned tail accounting by block type (tail after last verified checkpoint ref_seq).
    unsigned_tail_start_seq = (max_verified_ref_seq + 1) if max_verified_ref_seq > 0 else 1
    unsigned_tail_blocks = 0
    unsigned_tail_pcm_blocks = 0
    unsigned_tail_dropped_notice_blocks = 0
    unsigned_tail_dropped_frames = 0
    for s, t in zip(record_seqs, record_types):
        if s < unsigned_tail_start_seq:
            continue
        unsigned_tail_blocks += 1
        if t == 0x00:
            unsigned_tail_pcm_blocks += 1
        elif t == 0x02:
            unsigned_tail_dropped_notice_blocks += 1
            # dropped frame count already accounted globally; exact per-tail payload parsing
            # is not retained here, so derive from verified totals below when exposing seconds.

    # Use exact frame math from visible plaintext framing where possible.
    # unsigned tail frame estimate = unsigned pcm blocks + dropped frames that occurred after tail start.
    # Since dropped-frame payloads are plaintext, compute exact tail dropped-frame total in a second pass.
    unsigned_tail_dropped_frames = 0
    if unsigned_tail_blocks > 0:
        scan_off = 5
        nl = data.find(b"\n", scan_off)
        scan_off = nl + 1
        sig_nl = data.find(b"\n", scan_off)
        scan_off = sig_nl + 1
        enc_header_len = struct.unpack(">H", data[scan_off : scan_off + 2])[0]
        scan_off += 2
        if enc_header_len == 0xFFFF:
            dec_nl = data.find(b"\n", scan_off)
            scan_off = dec_nl + 1
        else:
            scan_off += enc_header_len
        while scan_off < len(data):
            if scan_off + 10 > len(data):
                break
            seq = struct.unpack(">I", data[scan_off : scan_off + 4])[0]
            scan_off += 4
            btype = data[scan_off]
            scan_off += 1
            body_len = struct.unpack(">I", data[scan_off : scan_off + 4])[0]
            scan_off += 4
            tag_len = data[scan_off]
            scan_off += 1
            if scan_off + body_len + tag_len + 32 > len(data):
                break
            body = data[scan_off : scan_off + body_len]
            scan_off += body_len
            scan_off += tag_len
            scan_off += 32
            if seq < unsigned_tail_start_seq:
                continue
            if btype == 0x02 and len(body) >= 2:
                unsigned_tail_dropped_frames += struct.unpack(">H", body[:2])[0]

    unsigned_tail_frames = unsigned_tail_pcm_blocks + unsigned_tail_dropped_frames
    unsigned_tail_seconds = (unsigned_tail_frames * frame_duration_ms) / 1000.0 if frame_duration_ms > 0 else None

    dec_or_plain = (dec or plain)
    auto_grants = _extract_auto_grants(plain)
    out = {
        "ok": True,
        "inner_header_mode": next_header_mode,
        "outer_header_signature_verified": header_sig_verified,
        "inner_header_plaintext_hash_verified": header_plaintext_hash_verified,
        "inner_header_encrypted_block_hash_verified": header_encrypted_block_hash_verified,
        "checkpoint_sig_verifiable": (device_sign_pub is not None),
        "device_certificate_in_header": cert_in_header,
        "frames": frames,
        "pcm_blocks": pcm_blocks,
        "sig_blocks": sig_blocks,
        "dropped_notice_blocks": dropped_notice_blocks,
        "dropped_frames_total": dropped_frames_total,
        "telemetry_blocks": telemetry_blocks,
        "estimated_frames": estimated_frames,
        "estimated_duration_seconds": est,
        "stream_sigs_verified": sig_verified,
        "recommended_decode_gain": float(dec_or_plain.get("recommended_decode_gain", 0.0)),
        "raw_capture_declared": any(isinstance(n, str) and "raw I2S capture" in n for n in (dec_or_plain.get("decoder_notes") or [])),
        "unsigned_tail_bytes": unsigned_tail_bytes,
        "unsigned_tail_start_seq": unsigned_tail_start_seq,
        "unsigned_tail_blocks": unsigned_tail_blocks,
        "unsigned_tail_pcm_blocks": unsigned_tail_pcm_blocks,
        "unsigned_tail_dropped_notice_blocks": unsigned_tail_dropped_notice_blocks,
        "unsigned_tail_dropped_frames": unsigned_tail_dropped_frames,
        "unsigned_tail_frames": unsigned_tail_frames,
        "unsigned_tail_seconds": unsigned_tail_seconds,
        "bytes_total": len(data),
        "bytes_consumed": off,
        **auto_grants,
    }
    if audio_key is not None and nonce_prefix is not None:
        out["pcm_bytes"] = pcm_bytes
    return out


def decode_azt1_stream_to_wav(
    *,
    data: bytes,
    out_wav_path: Path,
    admin_private_key_pem: bytes | None = None,
    apply_gain: bool = False,
    gain: float | None = None,
    preserve_tail: bool = False,
) -> dict:
    # Full-chain validation + decode to WAV in one pass.
    priv = load_private_key_auto(admin_private_key_pem, purpose="stream private key") if admin_private_key_pem else None

    if not data.startswith(b"AZT1\n"):
        raise ValueError("ERR_MAGIC")
    off = 5
    nl = data.find(b"\n", off)
    if nl < 0:
        raise ValueError("ERR_HEADER_JSON")
    plain_line = data[off:nl]
    plain = json.loads(plain_line.decode("utf-8"))
    off = nl + 1

    sig_nl = data.find(b"\n", off)
    if sig_nl < 0:
        raise ValueError("ERR_HEADER_SIG_LINE")
    outer_sig_b64 = data[off:sig_nl].decode("utf-8")
    off = sig_nl + 1

    if plain.get("version") not in (0, 1):
        raise ValueError("ERR_VERSION")

    next_fp_hex = plain.get("next_header_recipient_key_fingerprint_hex", plain.get("header_key_fingerprint_hex"))
    if priv is not None:
        pub_der = priv.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        hh = hashes.Hash(hashes.SHA256())
        hh.update(pub_der)
        if next_fp_hex != hh.finalize().hex():
            raise ValueError("ERR_KEY_FP_MISMATCH")

    if plain.get("next_header_plaintext_hash_alg") != "sha256":
        raise ValueError("ERR_PLAIN_HEADER_HASH_ALG")

    enc_header_len = struct.unpack(">H", data[off : off + 2])[0]
    off += 2

    header_plaintext_hash_verified = False
    header_encrypted_block_hash_verified = False
    next_header_mode = "encrypted"
    dec = None
    header_ct = b""

    if enc_header_len == 0xFFFF:
        next_header_mode = "decoded"
        dec_nl = data.find(b"\n", off)
        if dec_nl < 0:
            raise ValueError("ERR_PLAINTEXT_NEXT_HEADER_FORMAT")
        header_pt = data[off:dec_nl]
        off = dec_nl + 1
        dec = json.loads(header_pt.decode("utf-8"))

        plain_hash_b64 = plain.get("next_header_plaintext_sha256_b64")
        if not isinstance(plain_hash_b64, str) or not plain_hash_b64:
            raise ValueError("ERR_PLAINTEXT_NEXT_HEADER_HASH_FIELD")
        hp = hashes.Hash(hashes.SHA256())
        hp.update(header_pt)
        if hp.finalize() != _b64d(plain_hash_b64):
            raise ValueError("ERR_PLAINTEXT_NEXT_HEADER_HASH")
        header_plaintext_hash_verified = True
    else:
        header_ct = data[off : off + enc_header_len]
        off += enc_header_len

        exp_len = plain.get("next_header_ciphertext_len")
        if isinstance(exp_len, int) and exp_len != len(header_ct):
            raise ValueError("ERR_ENCRYPTED_NEXT_HEADER_LEN")
        exp_ct_hash_b64 = plain.get("next_header_ciphertext_sha256_b64")
        if isinstance(exp_ct_hash_b64, str) and exp_ct_hash_b64:
            hh = hashes.Hash(hashes.SHA256())
            hh.update(header_ct)
            if hh.finalize() != _b64d(exp_ct_hash_b64):
                raise ValueError("ERR_ENCRYPTED_NEXT_HEADER_HASH")
            header_encrypted_block_hash_verified = True

        if priv is not None:
            wrapped = _b64d(plain.get("next_header_wrapped_key_b64", plain.get("wrapped_header_key_b64")))
            header_key = priv.decrypt(wrapped, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            header_nonce = _b64d(plain.get("next_header_nonce_b64", plain.get("header_nonce_b64")))
            header_tag = _b64d(plain.get("next_header_tag_b64", plain.get("header_tag_b64")))
            header_pt = AESGCM(header_key).decrypt(header_nonce, header_ct + header_tag, None)
            dec = json.loads(header_pt.decode("utf-8"))

            plain_hash_b64 = plain.get("next_header_plaintext_sha256_b64")
            if not isinstance(plain_hash_b64, str) or not plain_hash_b64:
                raise ValueError("ERR_PLAINTEXT_NEXT_HEADER_HASH_FIELD")
            hp = hashes.Hash(hashes.SHA256())
            hp.update(header_pt)
            if hp.finalize() != _b64d(plain_hash_b64):
                raise ValueError("ERR_PLAINTEXT_NEXT_HEADER_HASH")
            header_plaintext_hash_verified = True

    chain_alg = str((dec or plain).get("chain_alg", "sha256-link"))
    chain_domain = str((dec or plain).get("chain_domain", "AZT1-CHAIN-V1"))
    nonce_hash = hashlib.sha256(str(plain.get("stream_auth_nonce") or "").encode("utf-8")).digest()
    v_prev = None
    chain_key = _b64d(dec["chain_key_b64"]) if (dec is not None and "chain_key_b64" in dec) else None
    chain_genesis_secret = _b64d(dec["chain_genesis_secret_b64"]) if (dec is not None and "chain_genesis_secret_b64" in dec) else None
    require_block1_sig0 = bool((dec or plain).get("block1_must_be_signature_ref_seq0") is True)

    device_sign_pub = None
    if dec is not None and "device_sign_public_key_b64" in dec:
        device_sign_pub_raw = _b64d(dec["device_sign_public_key_b64"])
        device_sign_pub = ed25519.Ed25519PublicKey.from_public_bytes(device_sign_pub_raw)
    elif isinstance(plain.get("this_header_signing_key_b64"), str) and plain.get("this_header_signing_key_b64"):
        device_sign_pub_raw = _b64d(plain.get("this_header_signing_key_b64"))
        device_sign_pub = ed25519.Ed25519PublicKey.from_public_bytes(device_sign_pub_raw)

    header_sig_verified = False
    if device_sign_pub is not None:
        outer_sig = _b64d(outer_sig_b64)
        device_sign_pub.verify(outer_sig, plain_line)
        header_sig_verified = True

    cert_in_header = isinstance(plain.get("device_certificate"), dict)
    if cert_in_header and dec is not None:
        cert_doc = plain.get("device_certificate")
        cert_payload_b64 = cert_doc.get("certificate_payload_b64")
        if not isinstance(cert_payload_b64, str) or not cert_payload_b64:
            raise ValueError("ERR_DEVICE_CERT_SCHEMA")
        cert_payload_raw = _b64d(cert_payload_b64)
        cert_payload = json.loads(cert_payload_raw.decode("utf-8"))
        if cert_payload.get("device_sign_public_key_b64") != dec.get("device_sign_public_key_b64"):
            raise ValueError("ERR_DEVICE_CERT_BINDING")
        cert_fp = cert_payload.get("device_sign_fingerprint_hex")
        if cert_fp is None:
            cert_fp = cert_payload.get("device_sign_public_key_fingerprint_hex")
        if cert_fp != dec.get("device_sign_fingerprint_hex"):
            raise ValueError("ERR_DEVICE_CERT_BINDING")
        if cert_payload.get("device_chip_id_hex") != plain.get("device_chip_id_hex"):
            raise ValueError("ERR_DEVICE_CERT_BINDING")
        header_cert_serial = plain.get("device_certificate_serial")
        if isinstance(header_cert_serial, str) and header_cert_serial:
            if cert_payload.get("certificate_serial") != header_cert_serial:
                raise ValueError("ERR_DEVICE_CERT_SERIAL")

    audio_key = _b64d(dec["audio_key_b64"]) if dec is not None else None
    nonce_prefix = _b64d(dec["audio_nonce_prefix_b64"]) if dec is not None else None
    if audio_key is None or nonce_prefix is None:
        raise ValueError("ERR_DECODE_KEY_REQUIRED")

    dec_or_plain = (dec or plain)
    sample_rate_hz = int(dec_or_plain.get("sample_rate_hz", 16000))
    channels = int(dec_or_plain.get("channels", 1))
    sample_width_bytes = int(dec_or_plain.get("sample_width_bytes", 2))
    if sample_width_bytes != 2:
        raise ValueError("ERR_UNSUPPORTED_SAMPLE_WIDTH")
    if channels != 1:
        raise ValueError("ERR_UNSUPPORTED_CHANNELS")

    recommended_gain = float(dec_or_plain.get("recommended_decode_gain", 1.0))
    frame_duration_ms = float(dec_or_plain.get("audio_frame_duration_ms", 0.0))
    gain_to_apply = float(gain) if gain is not None else (recommended_gain if apply_gain else 1.0)

    frames = pcm_bytes = pcm_blocks = sig_blocks = sig_verified = 0
    dropped_notice_blocks = dropped_frames_total = telemetry_blocks = 0
    close_message_text = ""
    close_message = None
    seq_to_chain_v: dict[int, bytes] = {}
    record_seqs: list[int] = []
    max_verified_ref_seq = 0
    finalize_seen = False
    pcm_chunks: list[tuple[int, bytes]] = []

    while off < len(data):
        if off + 10 > len(data):
            break
        seq = struct.unpack(">I", data[off : off + 4])[0]
        off += 4
        block_type = data[off]
        off += 1
        body_len = struct.unpack(">I", data[off : off + 4])[0]
        off += 4
        tag_len = data[off]
        off += 1
        if off + body_len + tag_len + 32 > len(data):
            break
        if finalize_seen:
            raise ValueError("ERR_FINALIZE_NOT_LAST")
        body = data[off : off + body_len]
        off += body_len
        tag = data[off : off + tag_len]
        off += tag_len
        v_cur = data[off : off + 32]
        off += 32

        record_seqs.append(seq)

        if require_block1_sig0 and seq == 1 and block_type != 0x01:
            raise ValueError("ERR_BLOCK1_MUST_BE_SIG")

        if chain_alg == "sha256-link":
            core = struct.pack(">I", seq) + bytes([block_type]) + struct.pack(">I", body_len) + bytes([tag_len]) + body + tag
            if chain_domain == "AZT1-CHAIN-V1-NONCE":
                if seq == 1:
                    v_calc = hashlib.sha256(b"AZT1-CHAIN-V1-NONCE" + nonce_hash + core).digest()
                else:
                    if v_prev is None:
                        raise ValueError("ERR_CHAIN_STATE")
                    v_calc = hashlib.sha256(b"AZT1-CHAIN-V1-NONCE" + nonce_hash + v_prev + core).digest()
            else:
                if seq == 1:
                    v_calc = hashlib.sha256(b"AZT1-CHAIN-V1" + core).digest()
                else:
                    if v_prev is None:
                        raise ValueError("ERR_CHAIN_STATE")
                    v_calc = hashlib.sha256(b"AZT1-CHAIN-V1" + v_prev + core).digest()
            if v_calc != v_cur:
                raise ValueError("ERR_CHAIN")
        elif chain_alg == "hmac-sha256-link":
            if chain_key is None:
                raise ValueError("ERR_CHAIN_STATE")
            hm = hmac.HMAC(chain_key, hashes.SHA256())
            hm.update(b"AZT1-CHAIN-V2")
            if seq > 1:
                if v_prev is None:
                    raise ValueError("ERR_CHAIN_STATE")
                hm.update(v_prev)
            hm.update(struct.pack(">I", seq))
            hm.update(bytes([block_type]))
            hm.update(struct.pack(">I", body_len))
            hm.update(bytes([tag_len]))
            hm.update(body)
            hm.update(tag)
            if hm.finalize() != v_cur:
                raise ValueError("ERR_CHAIN")
        else:
            raise ValueError("ERR_CHAIN_ALG")
        v_prev = v_cur
        seq_to_chain_v[seq] = v_cur

        if block_type in (0x00, 0x03):
            if tag_len != 16:
                raise ValueError("ERR_TAG_LEN")
            nonce = nonce_prefix + struct.pack(">I", seq) + b"\x00\x00\x00\x00"
            block_body = AESGCM(audio_key).decrypt(nonce, body + tag, None)
        elif block_type in (0x01, 0x02, 0x7E, 0x7F):
            if tag_len != 0:
                raise ValueError("ERR_TAG_LEN")
            block_body = body
        else:
            raise ValueError(f"ERR_BLOCK_TYPE:{block_type}")

        if block_type == 0x00:
            pcm_bytes += len(block_body)
            pcm_blocks += 1
            if gain_to_apply == 1.0:
                pcm_chunks.append((seq, block_body))
            else:
                chunk = bytearray()
                for i in range(0, len(block_body), 2):
                    s = int.from_bytes(block_body[i : i + 2], "little", signed=True)
                    sg = int(round(s * gain_to_apply))
                    if sg > 32767:
                        sg = 32767
                    elif sg < -32768:
                        sg = -32768
                    chunk.extend(int(sg).to_bytes(2, "little", signed=True))
                pcm_chunks.append((seq, bytes(chunk)))
        elif block_type == 0x01:
            sig_blocks += 1
            if require_block1_sig0 and seq == 1:
                if len(block_body) < 68:
                    raise ValueError("ERR_BLOCK1_SIG_FORMAT")
                first_ref = struct.unpack(">I", block_body[:4])[0]
                if first_ref != 0:
                    raise ValueError("ERR_BLOCK1_SIG_REF")
            if len(block_body) >= 68:
                ref_seq = struct.unpack(">I", block_body[:4])[0]
                sig = block_body[4:68]
                if device_sign_pub is not None:
                    if ref_seq == 0:
                        if chain_genesis_secret is None:
                            raise ValueError("ERR_GENESIS_SECRET_MISSING")
                        msg = b"AZT1SIG0" + chain_genesis_secret
                        device_sign_pub.verify(sig, msg)
                        sig_verified += 1
                    elif ref_seq in seq_to_chain_v:
                        msg = b"AZT1SIG1" + struct.pack(">I", ref_seq) + seq_to_chain_v[ref_seq]
                        device_sign_pub.verify(sig, msg)
                        sig_verified += 1
                        if ref_seq > max_verified_ref_seq:
                            max_verified_ref_seq = ref_seq
        elif block_type == 0x02:
            dropped_notice_blocks += 1
            if len(block_body) >= 2:
                dropped_frames_total += struct.unpack(">H", block_body[:2])[0]
        elif block_type == 0x03:
            telemetry_blocks += 1
        elif block_type == 0x7E:
            try:
                close_message_text = block_body.decode("utf-8", errors="replace").strip()
            except Exception:
                close_message_text = ""
            if close_message_text:
                try:
                    parsed_close = json.loads(close_message_text)
                    if isinstance(parsed_close, dict):
                        close_message = parsed_close
                except Exception:
                    close_message = None
        elif block_type == 0x7F:
            finalize_seen = True
            if len(block_body) < 68:
                raise ValueError("ERR_FINALIZE_FORMAT")
            ref_seq = struct.unpack(">I", block_body[:4])[0]
            sig = block_body[4:68]
            if ref_seq == 0 or ref_seq not in seq_to_chain_v:
                raise ValueError("ERR_FINALIZE_REF")
            if device_sign_pub is not None:
                msg = b"AZT1SIG1" + struct.pack(">I", ref_seq) + seq_to_chain_v[ref_seq]
                device_sign_pub.verify(sig, msg)
                sig_verified += 1
                if ref_seq > max_verified_ref_seq:
                    max_verified_ref_seq = ref_seq
        frames += 1

    unsigned_tail_start_seq = (max_verified_ref_seq + 1) if max_verified_ref_seq > 0 else 1

    signed_pcm_chunks = [chunk for seq, chunk in pcm_chunks if seq < unsigned_tail_start_seq]
    all_pcm_chunks = [chunk for _, chunk in pcm_chunks]

    unsigned_tail_trimmed = (not preserve_tail)
    pcm_out_bytes = b"".join(all_pcm_chunks if preserve_tail else signed_pcm_chunks)

    out_wav_path.parent.mkdir(parents=True, exist_ok=True)
    with wave.open(str(out_wav_path), "wb") as wf:
        wf.setnchannels(channels)
        wf.setsampwidth(sample_width_bytes)
        wf.setframerate(sample_rate_hz)
        wf.writeframes(pcm_out_bytes)

    unsigned_tail_blocks = sum(1 for s in record_seqs if s >= unsigned_tail_start_seq)
    unsigned_tail_bytes = max(0, len(data) - off)

    # Compute unsigned-tail audio-equivalent duration (pcm blocks + dropped-frame notices)
    unsigned_tail_pcm_blocks = 0
    unsigned_tail_dropped_frames = 0
    scan_off = 5
    nl2 = data.find(b"\n", scan_off)
    scan_off = nl2 + 1
    sig_nl2 = data.find(b"\n", scan_off)
    scan_off = sig_nl2 + 1
    enc_header_len2 = struct.unpack(">H", data[scan_off : scan_off + 2])[0]
    scan_off += 2
    if enc_header_len2 == 0xFFFF:
        dec_nl2 = data.find(b"\n", scan_off)
        scan_off = dec_nl2 + 1
    else:
        scan_off += enc_header_len2
    while scan_off < len(data):
        if scan_off + 10 > len(data):
            break
        seq2 = struct.unpack(">I", data[scan_off : scan_off + 4])[0]
        scan_off += 4
        btype2 = data[scan_off]
        scan_off += 1
        body_len2 = struct.unpack(">I", data[scan_off : scan_off + 4])[0]
        scan_off += 4
        tag_len2 = data[scan_off]
        scan_off += 1
        if scan_off + body_len2 + tag_len2 + 32 > len(data):
            break
        body2 = data[scan_off : scan_off + body_len2]
        scan_off += body_len2
        scan_off += tag_len2
        scan_off += 32
        if seq2 < unsigned_tail_start_seq:
            continue
        if btype2 == 0x00:
            unsigned_tail_pcm_blocks += 1
        elif btype2 == 0x02 and len(body2) >= 2:
            unsigned_tail_dropped_frames += struct.unpack(">H", body2[:2])[0]

    unsigned_tail_frames = unsigned_tail_pcm_blocks + unsigned_tail_dropped_frames
    unsigned_tail_seconds = (unsigned_tail_frames * frame_duration_ms) / 1000.0 if frame_duration_ms > 0 else None

    auto_grants = _extract_auto_grants(plain)

    warnings: list[str] = []
    if unsigned_tail_frames > 0:
        if unsigned_tail_seconds is not None:
            if unsigned_tail_trimmed:
                warnings.append(
                    f"{unsigned_tail_frames} frame(s) ({unsigned_tail_seconds:.3f} seconds) of unsigned audio has been trimmed. Use --preserve-tail to keep."
                )
            else:
                warnings.append(
                    f"{unsigned_tail_frames} frame(s) ({unsigned_tail_seconds:.3f} seconds) of unsigned audio is not signed and is subject to tampering."
                )
        else:
            if unsigned_tail_trimmed:
                warnings.append(
                    f"{unsigned_tail_frames} frame(s) of unsigned audio has been trimmed. Use --preserve-tail to keep."
                )
            else:
                warnings.append(
                    f"{unsigned_tail_frames} frame(s) of unsigned audio is not signed and is subject to tampering."
                )

    messages = [{"level": "caution", "code": "UNSIGNED_AUDIO_TAIL", "text": w} for w in warnings]
    if close_message_text:
        close_cause = close_message.get("cause") if isinstance(close_message, dict) else ""
        msg_text = f"Stream close reason: {close_cause}" if isinstance(close_cause, str) and close_cause else f"Stream close message: {close_message_text}"
        messages.append({"level": "info", "code": "STREAM_CLOSE_REASON", "text": msg_text})

    return {
        "ok": True,
        "inner_header_mode": next_header_mode,
        "outer_header_signature_verified": header_sig_verified,
        "inner_header_plaintext_hash_verified": header_plaintext_hash_verified,
        "inner_header_encrypted_block_hash_verified": header_encrypted_block_hash_verified,
        "checkpoint_sig_verifiable": (device_sign_pub is not None),
        "stream_sigs_verified": sig_verified,
        "frames": frames,
        "pcm_blocks": pcm_blocks,
        "pcm_bytes": pcm_bytes,
        "dropped_notice_blocks": dropped_notice_blocks,
        "dropped_frames_total": dropped_frames_total,
        "telemetry_blocks": telemetry_blocks,
        "recommended_decode_gain": recommended_gain,
        "gain_applied": gain_to_apply,
        "sample_rate_hz": sample_rate_hz,
        "channels": channels,
        "sample_width_bytes": sample_width_bytes,
        "wav_out": str(out_wav_path),
        "wav_bytes": len(pcm_out_bytes),
        "bytes_total": len(data),
        "bytes_consumed": off,
        "unsigned_tail_start_seq": unsigned_tail_start_seq,
        "unsigned_tail_blocks": unsigned_tail_blocks,
        "unsigned_tail_pcm_blocks": unsigned_tail_pcm_blocks,
        "unsigned_tail_dropped_frames": unsigned_tail_dropped_frames,
        "unsigned_tail_frames": unsigned_tail_frames,
        "unsigned_tail_seconds": unsigned_tail_seconds,
        "unsigned_tail_bytes": unsigned_tail_bytes,
        "unsigned_tail_trimmed": unsigned_tail_trimmed and (unsigned_tail_frames > 0),
        "unsigned_tail_preserved": preserve_tail and (unsigned_tail_frames > 0),
        "close_message_text": close_message_text,
        "close_message": close_message,
        "close_reason_cause": (close_message.get("cause") if isinstance(close_message, dict) else None),
        "messages": messages,
        **auto_grants,
    }
