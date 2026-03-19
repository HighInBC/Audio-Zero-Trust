#!/usr/bin/env python3
"""
AZT1 file-format validator (normative expectations for current format revision).

Focuses on container/format semantics:
- plaintext header schema + signature
- encrypted header schema
- chunk framing schema
- block encryption class expectations (PCM/TELEM encrypted, SIG/DROPPED plaintext)
- chain verification
"""

from __future__ import annotations
import argparse, base64, json, struct, sys, hashlib
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class SpecError(Exception):
    def __init__(self, category: str, detail: str):
        super().__init__(f"{category}: {detail}")
        self.category = category
        self.detail = detail


def fail(category: str, detail: str):
    raise SpecError(category, detail)


def b64d(v: str, field: str) -> bytes:
    try:
        return base64.b64decode(v, validate=True)
    except Exception as e:
        fail("ERR_HEADER_FIELD", f"invalid base64 in {field}: {e}")


def reqs(o: dict, k: str) -> str:
    v = o.get(k)
    if not isinstance(v, str):
        fail("ERR_HEADER_FIELD", f"{k} must be string")
    return v


def reqi(o: dict, k: str) -> int:
    v = o.get(k)
    if not isinstance(v, int):
        fail("ERR_HEADER_FIELD", f"{k} must be integer")
    return v


def reqb(o: dict, k: str) -> bool:
    v = o.get(k)
    if not isinstance(v, bool):
        fail("ERR_HEADER_FIELD", f"{k} must be boolean")
    return v


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--infile", required=True)
    ap.add_argument("--key", default="", help="Optional recorder private key PEM; required only for encrypted next-header mode")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    try:
        data = Path(args.infile).read_bytes()
        priv = serialization.load_pem_private_key(Path(args.key).read_bytes(), password=None) if str(args.key).strip() else None

        if not data.startswith(b"AZT1\n"):
            fail("ERR_MAGIC", "missing AZT1 magic")
        off = 5

        nl = data.find(b"\n", off)
        if nl < 0:
            fail("ERR_HEADER_JSON", "missing plaintext header newline")
        plain_line = data[off:nl]
        plain = json.loads(plain_line.decode("utf-8"))
        off = nl + 1

        # Plain-header expectations
        if reqi(plain, "version") != 0:
            fail("ERR_HEADER_FIELD", "version must be 0")
        if reqi(plain, "container_major") != 0:
            fail("ERR_HEADER_FIELD", "container_major must be 0")
        cminor = reqi(plain, "container_minor")
        if cminor is None or cminor < 0:
            fail("ERR_HEADER_FIELD", "container_minor must be >= 0")
        if reqs(plain, "next_header_key_wrap") != "rsa-oaep-sha256":
            fail("ERR_HEADER_FIELD", "next_header_key_wrap mismatch")
        if reqs(plain, "next_header_cipher") != "aes-256-gcm":
            fail("ERR_HEADER_FIELD", "next_header_cipher mismatch")
        if reqs(plain, "next_header_aad_mode") != "none":
            fail("ERR_HEADER_FIELD", "next_header_aad_mode must be none")
        if reqs(plain, "next_header_recipient_key_fingerprint_alg") != "sha256-spki-der":
            fail("ERR_HEADER_FIELD", "recipient key fp alg mismatch")
        if reqs(plain, "next_header_ciphertext_hash_alg") != "sha256":
            fail("ERR_HEADER_FIELD", "next_header_ciphertext_hash_alg must be sha256")

        if reqs(plain, "chain_alg") != "sha256-link":
            fail("ERR_HEADER_FIELD", "public_chain_alg must be sha256-link")
        if reqs(plain, "chain_domain") != "AZT1-CHAIN-V1":
            fail("ERR_HEADER_FIELD", "public_chain_domain mismatch")
        if reqs(plain, "chain_root_mode") != "first-record-hash":
            fail("ERR_HEADER_FIELD", "public_chain_root_mode mismatch")
        if reqs(plain, "chunk_record_format") != "seq_u32be|block_type_u8|body_len_u32be|tag_len_u8|body|tag|chain_v32":
            fail("ERR_HEADER_FIELD", "public_chunk_record_format mismatch")
        if reqs(plain, "estimated_frames_formula") != "COUNT(block_type=0) + SUM(block_type=2.missed_frames_u16be)":
            fail("ERR_HEADER_FIELD", "estimated_frames_formula mismatch")
        if reqs(plain, "estimated_duration_ms_formula") != "(COUNT(block_type=0) + SUM(block_type=2.missed_frames_u16be)) * audio_frame_duration_ms":
            fail("ERR_HEADER_FIELD", "estimated_duration_ms_formula mismatch")
        if not reqb(plain, "pcm_blocks_are_single_frame"):
            fail("ERR_HEADER_FIELD", "public_pcm_blocks_are_single_frame must be true")

        enc_types = plain.get("encrypted_block_types")
        pt_types = plain.get("plaintext_block_types")
        if enc_types != [0, 3] or pt_types != [1, 2]:
            fail("ERR_HEADER_FIELD", "block type encryption classes mismatch")

        # this-header signature line
        sig_nl = data.find(b"\n", off)
        if sig_nl < 0:
            fail("ERR_HEADER_SIG_LINE", "missing header signature line")
        outer_sig = b64d(data[off:sig_nl].decode("utf-8"), "this_header_signature_line")
        off = sig_nl + 1

        sign_pub_raw = b64d(reqs(plain, "this_header_signing_key_b64"), "this_header_signing_key_b64") if "this_header_signing_key_b64" in plain else None
        if sign_pub_raw is None:
            # fallback to device_sign key from encrypted header after decrypt if not present
            pass

        if reqs(plain, "next_header_plaintext_hash_alg") != "sha256":
            fail("ERR_HEADER_FIELD", "next_header_plaintext_hash_alg must be sha256")

        # encrypted header len + blob (0xFFFF sentinel => plaintext next header JSON line)
        if off + 2 > len(data):
            fail("ERR_ENC_HEADER_LENGTH", "missing encrypted header length")
        enc_header_len = struct.unpack(">H", data[off:off+2])[0]
        off += 2

        if enc_header_len == 0xFFFF:
            dec_nl = data.find(b"\n", off)
            if dec_nl < 0:
                fail("ERR_ENC_HEADER_LENGTH", "plaintext next header sentinel set but missing newline-terminated JSON")
            header_pt = data[off:dec_nl]
            off = dec_nl + 1
            dec = json.loads(header_pt.decode("utf-8"))
        else:
            if off + enc_header_len > len(data):
                fail("ERR_ENC_HEADER_LENGTH", "truncated encrypted header")
            header_ct = data[off:off+enc_header_len]
            off += enc_header_len

            if reqi(plain, "next_header_ciphertext_len") != len(header_ct):
                fail("ERR_ENC_HEADER_LENGTH", "next_header_ciphertext_len mismatch")

            hh2 = hashes.Hash(hashes.SHA256())
            hh2.update(header_ct)
            if hh2.finalize() != b64d(reqs(plain, "next_header_ciphertext_sha256_b64"), "next_header_ciphertext_sha256_b64"):
                fail("ERR_ENC_HEADER_LENGTH", "next_header ciphertext hash mismatch")

            wrapped = b64d(reqs(plain, "next_header_wrapped_key_b64"), "next_header_wrapped_key_b64")
            header_nonce = b64d(reqs(plain, "next_header_nonce_b64"), "next_header_nonce_b64")
            header_tag = b64d(reqs(plain, "next_header_tag_b64"), "next_header_tag_b64")
            if len(header_nonce) != 12 or len(header_tag) != 16:
                fail("ERR_HEADER_FIELD", "next header nonce/tag sizes invalid")

            if priv is None:
                fail("ERR_ENC_HEADER_DECRYPT", "private key required for encrypted next-header mode")
            try:
                header_key = priv.decrypt(wrapped, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            except Exception as e:
                fail("ERR_ENC_HEADER_DECRYPT", f"RSA unwrap failed: {e}")

            try:
                header_pt = AESGCM(header_key).decrypt(header_nonce, header_ct + header_tag, None)
            except Exception as e:
                fail("ERR_ENC_HEADER_DECRYPT", f"header aes-gcm failed: {e}")

            dec = json.loads(header_pt.decode("utf-8"))

        hh_plain = hashes.Hash(hashes.SHA256())
        hh_plain.update(header_pt)
        if hh_plain.finalize() != b64d(reqs(plain, "next_header_plaintext_sha256_b64"), "next_header_plaintext_sha256_b64"):
            fail("ERR_ENC_HEADER_LENGTH", "next_header plaintext hash mismatch")

        # encrypted-header expectations
        if reqs(dec, "chain_alg") != "sha256-link":
            fail("ERR_ENC_HEADER_JSON", "chain_alg must be sha256-link")

        # Optional device certificate included in plaintext header for portable provenance.
        cert_doc = plain.get("device_certificate")
        if cert_doc is not None:
            if not isinstance(cert_doc, dict):
                fail("ERR_HEADER_FIELD", "device_certificate must be object")
            cert_payload_b64 = reqs(cert_doc, "certificate_payload_b64")
            cert_payload_raw = b64d(cert_payload_b64, "device_certificate.certificate_payload_b64")
            try:
                cert_payload = json.loads(cert_payload_raw.decode("utf-8"))
            except Exception as e:
                fail("ERR_HEADER_FIELD", f"device_certificate payload json invalid: {e}")
            if not isinstance(cert_payload, dict):
                fail("ERR_HEADER_FIELD", "device_certificate payload must be json object")
            cert_dev_pub = cert_payload.get("device_sign_public_key_b64")
            cert_dev_fp = cert_payload.get("device_sign_public_key_fingerprint_hex")
            cert_chip = cert_payload.get("device_chip_id_hex")
            if cert_dev_pub != dec.get("device_sign_public_key_b64"):
                fail("ERR_HEADER_FIELD", "device_certificate device_sign_public_key_b64 mismatch")
            if cert_dev_fp != dec.get("device_sign_fingerprint_hex"):
                fail("ERR_HEADER_FIELD", "device_certificate device_sign_public_key_fingerprint_hex mismatch")
            if cert_chip != plain.get("device_chip_id_hex"):
                fail("ERR_HEADER_FIELD", "device_certificate device_chip_id_hex mismatch")
            cert_serial = cert_payload.get("certificate_serial")
            header_cert_serial = plain.get("device_certificate_serial")
            if isinstance(header_cert_serial, str) and len(header_cert_serial) > 0 and cert_serial != header_cert_serial:
                fail("ERR_HEADER_FIELD", "device_certificate_serial mismatch")
        if reqs(dec, "chunk_record_format") != "seq_u32be|block_type_u8|body_len_u32be|tag_len_u8|body|tag|chain_v32":
            fail("ERR_ENC_HEADER_JSON", "chunk_record_format mismatch")
        if dec.get("encrypted_block_types") != [0, 3] or dec.get("plaintext_block_types") != [1, 2]:
            fail("ERR_ENC_HEADER_JSON", "encrypted/plaintext block type sets mismatch")

        audio_key = b64d(reqs(dec, "audio_key_b64"), "audio_key_b64")
        nonce_prefix = b64d(reqs(dec, "audio_nonce_prefix_b64"), "audio_nonce_prefix_b64")
        if len(audio_key) != 32 or len(nonce_prefix) != 4:
            fail("ERR_ENC_HEADER_JSON", "invalid key/nonce fields")

        device_sign_pub_raw = b64d(reqs(dec, "device_sign_public_key_b64"), "device_sign_public_key_b64")
        device_sign_pub = ed25519.Ed25519PublicKey.from_public_bytes(device_sign_pub_raw)
        # verify outer header signature over raw plain header json bytes
        device_sign_pub.verify(outer_sig, plain_line)

        frames = 0
        pcm_blocks = 0
        dropped_notice_blocks = 0
        dropped_frames_total = 0
        sig_blocks = 0
        sig_verified = 0
        telemetry_blocks = 0
        pcm_bytes = 0
        consumed = off
        trailing_partial_bytes = 0
        v_prev = None
        seq_to_chain_v: dict[int, bytes] = {}

        while consumed < len(data):
            if consumed + 10 > len(data):
                trailing_partial_bytes = len(data) - consumed
                break

            seq = struct.unpack(">I", data[consumed:consumed+4])[0]
            consumed += 4
            block_type = data[consumed]
            consumed += 1
            body_len = struct.unpack(">I", data[consumed:consumed+4])[0]
            consumed += 4
            tag_len = data[consumed]
            consumed += 1

            need = body_len + tag_len + 32
            if consumed + need > len(data):
                trailing_partial_bytes = len(data) - (consumed - 10)
                consumed = len(data)
                break

            body = data[consumed:consumed+body_len]
            consumed += body_len
            tag = data[consumed:consumed+tag_len]
            consumed += tag_len
            v_cur = data[consumed:consumed+32]
            consumed += 32

            # verify chain
            core = struct.pack(">I", seq) + bytes([block_type]) + struct.pack(">I", body_len) + bytes([tag_len]) + body + tag
            if seq == 1:
                v_calc = hashlib.sha256(b"AZT1-CHAIN-V1" + core).digest()
            else:
                if v_prev is None:
                    fail("ERR_CHAIN", "missing prior chain value for seq>1")
                v_calc = hashlib.sha256(b"AZT1-CHAIN-V1" + v_prev + core).digest()
            if v_calc != v_cur:
                fail("ERR_CHAIN", f"chain mismatch at seq={seq}")
            v_prev = v_cur
            seq_to_chain_v[seq] = v_cur

            # encryption class expectations
            if block_type in (0, 3):
                if tag_len != 16:
                    fail("ERR_PACKETIZATION", f"encrypted block_type={block_type} must have tag_len=16")
                nonce = nonce_prefix + struct.pack(">I", seq) + b"\x00\x00\x00\x00"
                try:
                    pt = AESGCM(audio_key).decrypt(nonce, body + tag, None)
                except Exception as e:
                    fail("ERR_AUDIO_DECRYPT", f"decrypt failed at seq={seq}: {e}")
                if block_type == 0:
                    pcm_blocks += 1
                    pcm_bytes += len(pt)
                else:
                    telemetry_blocks += 1
            elif block_type in (1, 2):
                if tag_len != 0:
                    fail("ERR_PACKETIZATION", f"plaintext block_type={block_type} must have tag_len=0")
                if block_type == 1:
                    sig_blocks += 1
                    if len(body) != 68:
                        fail("ERR_PACKETIZATION", f"signature block len must be 68, got {len(body)}")
                    ref_seq = struct.unpack(">I", body[:4])[0]
                    sig = body[4:]
                    ref_v = seq_to_chain_v.get(ref_seq)
                    if ref_v is None:
                        fail("ERR_PACKETIZATION", f"signature ref_seq={ref_seq} not seen yet")
                    msg = b"AZT1SIG1" + struct.pack(">I", ref_seq) + ref_v
                    try:
                        device_sign_pub.verify(sig, msg)
                    except Exception as e:
                        fail("ERR_SIGNATURE", f"checkpoint signature verify failed at seq={seq}: {e}")
                    sig_verified += 1
                else:
                    dropped_notice_blocks += 1
                    if len(body) != 2:
                        fail("ERR_PACKETIZATION", f"dropped block len must be 2, got {len(body)}")
                    dropped_frames_total += struct.unpack(">H", body)[0]
            else:
                fail("ERR_PACKETIZATION", f"unknown block_type={block_type}")

            frames += 1

        # duration estimation expectation
        frame_duration_ms = float(dec.get("audio_frame_duration_ms", 0.0))
        estimated_frames = pcm_blocks + dropped_frames_total
        estimated_duration_seconds = (estimated_frames * frame_duration_ms) / 1000.0 if frame_duration_ms > 0 else None

        out = {
            "ok": True,
            "infile": args.infile,
            "frames": frames,
            "pcm_blocks": pcm_blocks,
            "sig_blocks": sig_blocks,
            "sig_verified": sig_verified,
            "dropped_notice_blocks": dropped_notice_blocks,
            "dropped_frames_total": dropped_frames_total,
            "telemetry_blocks": telemetry_blocks,
            "estimated_frames": estimated_frames,
            "estimated_duration_seconds": estimated_duration_seconds,
            "pcm_bytes": pcm_bytes,
            "bytes_total": len(data),
            "trailing_partial_bytes": trailing_partial_bytes,
            "bytes_consumed": consumed,
        }
        print(json.dumps(out, indent=2) if args.json else out)
        return 0

    except SpecError as e:
        out = {"ok": False, "error": e.category, "detail": e.detail}
        print(json.dumps(out, indent=2) if args.json else f"{e.category}: {e.detail}", file=sys.stdout if args.json else sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
