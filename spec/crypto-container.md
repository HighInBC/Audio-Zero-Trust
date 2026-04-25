# AZT1 Crypto Container (current v1 profile)

This document is normative for the currently passing AZT1 file-analysis/validation flow (`client/tools/validate_azt1.py` and `client/tools/azt_client/stream.py`). If implementation and this spec diverge, update this spec in the same change.

## 1) Scope

AZT1 v1 defines a self-describing encrypted audio capture container with:

1. plaintext outer header JSON line,
2. outer-header detached signature line,
3. 2-byte next-header length,
4. encrypted or plaintext next-header JSON,
5. framed chunk stream.

All integers are unsigned big-endian.

---

## 2) Exact byte layout

File bytes are:

1. `magic_line`
2. `outer_header_json_line`
3. `outer_header_signature_line`
4. `next_header_len_u16`
5. `next_header_blob_or_line`
6. `chunk_stream`

Where:

- `magic_line` = ASCII `AZT1` + LF (`0x0A`) exactly 5 bytes.
- `outer_header_json_line` = UTF-8 JSON object, single line, LF-terminated.
- `outer_header_signature_line` = base64 Ed25519 signature over **raw outer_header JSON bytes** (not including LF), LF-terminated.
- `next_header_len_u16`:
  - `N != 0xFFFF`: read exactly `N` bytes of encrypted next-header ciphertext.
  - `N == 0xFFFF`: next header is plaintext UTF-8 JSON line; read until LF.
- `chunk_stream` = remaining bytes, parsed as framed chunk records until EOF.

Trailing partial chunk bytes MAY exist (live capture truncation); validators may accept data up to last complete frame.

---

## 3) Outer (plaintext) header schema

Required keys used by current validators/generator:

- `version` = `0`
- `container_major` = `0`
- `container_minor` = non-negative integer (currently `0`)
- `next_header_key_wrap` = `"rsa-oaep-sha256"`
- `next_header_cipher` = `"aes-256-gcm"`
- `next_header_wrapped_key_b64` (base64)
- `next_header_nonce_b64` (base64, 12 bytes)
- `next_header_tag_b64` (base64, 16 bytes)
- `next_header_aad_mode` = `"none"`
- `next_header_recipient_key_fingerprint_alg` = `"sha256-spki-der"`
- `next_header_recipient_key_fingerprint_hex` (64 lowercase hex)
- `next_header_ciphertext_hash_alg` = `"sha256"`
- `next_header_ciphertext_sha256_b64` (base64 SHA-256 of encrypted next-header ciphertext)
- `next_header_ciphertext_len` (int; byte length of encrypted next-header ciphertext)
- `next_header_plaintext_hash_alg` = `"sha256"`
- `next_header_plaintext_sha256_b64` (base64 SHA-256 of decrypted/plaintext next-header JSON bytes)
- `this_header_signature_alg` = `"ed25519"`
- `this_header_signature_domain` = `"this_header_json_utf8"`
- `this_header_signing_key_fingerprint_alg` = `"sha256-raw-ed25519-pub"`
- `this_header_signing_key_fingerprint_hex`
- `this_header_signing_key_b64`
- `device_certificate_serial` (string, optional but recommended when certified)
- `device_certificate` (JSON object, optional; full signed certificate document as returned by `/api/v0/device/certificate`)
- `stream_auth_nonce` (string; single-use stream challenge nonce bound to stream-start authorization)
- `ntp_time_since_last_sync_seconds` (integer; elapsed seconds since the device last synchronized time with the configured NTP time source, not a clock offset/drift value)
- `chunk_record_format` = `"seq_u32be|block_type_u8|body_len_u32be|tag_len_u8|body|tag|chain_v32"`
- `chain_alg` = `"sha256-link"`
- `chain_domain` = `"AZT1-CHAIN-V1-NONCE"`
- `chain_root_mode` = `"genesis-signature-block"`
- `encrypted_block_types` = `[0,3]`
- `plaintext_block_types` = `[1,2,126,127]`
- `signature_checkpoint_alg` = `"ed25519"`
- `signature_checkpoint_domain` = `"AZT1SIG1||ref_seq_u32be||chain_v32 (ref_seq>0) ; AZT1SIG0||chain_genesis_secret32 (ref_seq=0)"`
- `block1_must_be_signature_ref_seq0` = `true`
- `pcm_blocks_are_single_frame` = `true`
- `audio_frame_duration_ms` (number)
- `estimated_frames_formula` = `"COUNT(block_type=0) + SUM(block_type=2.missed_frames_u16be)"`
- `estimated_duration_ms_formula` = `"(COUNT(block_type=0) + SUM(block_type=2.missed_frames_u16be)) * audio_frame_duration_ms"`
- `next_header_decrypt_procedure` (array of strings; human/machine guidance)
- `certificate_verification_procedure` (array of strings; human/machine guidance)
- `notes` (array of strings; include guidance to silently discard trailing partial chunks and warn when unsigned tail blocks exist)

When `device_certificate` is present, it should contain at minimum:

- `certificate_payload_b64`
- `signature_algorithm` = `"ed25519"`
- `signature_b64`

and the decoded payload should bind the signing key identity in the stream (device sign pubkey/fingerprint/chip id), enabling offline provenance verification against trusted admin public keys.

Additional fields are allowed.

---

## 4) Next-header (decrypted JSON) schema

Current profile expects:

- `audio_cipher` = `"aes-256-gcm-mixed-blocks-sha256-chain"`
- `audio_key_b64` (base64, 32 bytes)
- `audio_nonce_prefix_b64` (base64, 4 bytes)
- `audio_tag_len` = `16`
- `audio_aad_mode` = `"none"`
- `audio_format` = `"pcm_s16le"`
- `sample_rate_hz` (int > 0)
- `channels` (int > 0)
- `sample_width_bytes` = `2`
- `packetization` = `"none"`
- `payload_block_types` map including ids `0..3`
- `encrypted_block_types` = `[0,3]`
- `plaintext_block_types` = `[1,2,126,127]`
- `signature_checkpoint_alg` = `"ed25519"`
- `signature_checkpoint_domain` = `"AZT1SIG1||ref_seq_u32be||chain_v32 (ref_seq>0) ; AZT1SIG0||chain_genesis_secret32 (ref_seq=0)"`
- `device_sign_public_key_b64` (base64 Ed25519 pubkey, 32 bytes)
- `device_sign_fingerprint_hex`
- `chain_alg` = `"sha256-link"`
- `chain_domain` = `"AZT1-CHAIN-V1-NONCE"`
- `chain_genesis_secret_b64` (base64, 32 bytes)
- `block1_must_be_signature_ref_seq0` = `true`
- `chain_root_mode` = `"genesis-signature-block"`
- `chunk_record_format` = `"seq_u32be|block_type_u8|body_len_u32be|tag_len_u8|body|tag|chain_v32"`
- `signature_block_body_format` = `"ref_seq_u32be|sig_ed25519_64"`
- `dropped_frames_block_body_format` = `"missed_frames_u16be"`
- `telemetry_block_body_format` (string format descriptor)
- `audio_frame_duration_ms` (number)
- optional `recommended_decode_gain`

Additional metadata is allowed.

---

## 5) Chunk stream framing and semantics

Each chunk record:

- `seq_u32be`
- `block_type_u8`
- `body_len_u32be`
- `tag_len_u8`
- `body` (`body_len` bytes)
- `tag` (`tag_len` bytes)
- `chain_v32` (32-byte SHA-256 link)

Chain rule (`sha256-link` with nonce domain binding):

- `nonce_hash = SHA256(stream_auth_nonce_utf8)`
- `seq == 1`: `V = SHA256("AZT1-CHAIN-V1-NONCE" || nonce_hash || record_bytes)`
- `seq > 1`: `V = SHA256("AZT1-CHAIN-V1-NONCE" || nonce_hash || prev_V || record_bytes)`
- `record_bytes = seq_u32be || block_type_u8 || body_len_u32be || tag_len_u8 || body || tag`

`block_type` classes:

- `0x00` PCM audio block (**encrypted**, `tag_len=16`)
- `0x01` checkpoint signature block (**plaintext**, `tag_len=0`, body len 68 expected by strict validator)
- `0x02` dropped-frames notice (**plaintext**, `tag_len=0`, body len 2 expected by strict validator)
- `0x03` telemetry snapshot (**encrypted**, `tag_len=16`)

Encrypted block nonce:

- `nonce = audio_nonce_prefix(4B) || seq_u32be || 0x00000000`

Signature block verification message:

- If `ref_seq == 0`: `AZT1SIG0 || chain_genesis_secret32`
- If `ref_seq > 0`: `AZT1SIG1 || ref_seq_u32be || chain_v32(ref_seq)`

Mandatory genesis anchor rule:

- `seq == 1` MUST be `block_type == 0x01` (signature block)
- block 1 MUST set `ref_seq == 0`
- this signs encrypted-only genesis secret and prevents blind re-signing by actors without inner-header decrypt capability.

---

## 6) Decoder/validator behavior (current)

1. Verify `AZT1\n` magic.
2. Parse outer header JSON line.
3. Parse outer signature line (base64 Ed25519 signature over raw outer JSON bytes).
4. Read `next_header_len_u16`.
5. If `N == 0xFFFF`, parse plaintext next-header line and verify `next_header_plaintext_sha256_b64`.
6. If `N != 0xFFFF`, verify ciphertext length/hash commitments from outer header.
7. If private key provided, unwrap/decrypt next header and verify plaintext hash commitment.
8. Parse chunk records to EOF (allow trailing partial bytes).
9. Verify chain link per record (`sha256-link`, domain `AZT1-CHAIN-V1-NONCE`, nonce-bound).
10. Enforce genesis-anchor rule: first record must be signature block with `ref_seq=0`.
11. For encrypted block types `(0,3)`, enforce `tag_len=16` and decrypt when audio key is available.
12. For plaintext block types `(1,2)`, enforce `tag_len=0`.
13. For type `0x01`, verify Ed25519 checkpoint signatures (`AZT1SIG0` for `ref_seq=0`, `AZT1SIG1` otherwise) when signing key is available.

---

## 7) Error categories used by strict file validator

Current `client/tools/validate_azt1.py` categories include:

- `ERR_MAGIC`
- `ERR_HEADER_JSON`
- `ERR_HEADER_FIELD`
- `ERR_HEADER_SIG_LINE`
- `ERR_ENC_HEADER_LENGTH`
- `ERR_ENC_HEADER_DECRYPT`
- `ERR_ENC_HEADER_JSON`
- `ERR_CHAIN`
- `ERR_CHAIN_STATE`
- `ERR_AUDIO_DECRYPT`
- `ERR_PACKETIZATION`
- `ERR_SIGNATURE`

---

## 8) Compatibility notes

- `version != 0` is unsupported (current pre-release major baseline).
- Unknown JSON fields should be ignored unless they contradict required fields.
- `0xFFFF` next-header sentinel mode is supported and used for detached/decode workflows.
- This document describes current passing behavior; keep synchronized with validator + firmware header builder.
- Repository-wide compatibility governance is defined in `spec/compatibility-policy.md`.
