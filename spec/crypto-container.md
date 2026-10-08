# AZT1 Crypto Container (current v1 profile, MSB-encryption block-type encoding)

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
- `outer_header_signature_line` = base64 signature (algorithm selected by `this_header_signature_alg`) over **raw outer_header JSON bytes** (not including LF), LF-terminated.
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
- `container_minor` = non-negative integer (`0` for the historical Ed25519 writer, `1` for the original Android RSA-PSS profile, `2` for current authenticated-finalization writers)
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
- `this_header_signature_alg` = `"ed25519"` or `"rsa-pss-sha256"` (see signature profiles below)
- `this_header_signature_domain` = `"this_header_json_utf8"`
- `this_header_signing_key_fingerprint_alg` = `"sha256-raw-ed25519-pub"` for Ed25519, `"sha256-spki-der"` for RSA
- `this_header_signing_key_fingerprint_hex`
- `this_header_signing_key_b64`
- `device_certificate_serial` (string, optional but recommended when certified)
- `device_certificate` (JSON object, optional; full signed certificate document as returned by `/api/v0/device/certificate`)
- `stream_auth_nonce` (string; single-use stream challenge nonce bound to stream-start authorization)
- `ntp_time_since_last_sync_seconds` (integer; elapsed seconds since the device last synchronized time with the configured NTP time source, not a clock offset/drift value)
- `chunk_record_format` = `"seq_u32be|block_flags_type_u8|body_len_u32be|tag_len_u8|body|tag|chain_v32"`
- `block_type_encoding` = `"msb_encryption_flag_v1"`
- `block_type_encrypted_mask` = `128`
- `block_type_id_mask` = `127`
- `chain_alg` = `"sha256-link"`
- `chain_domain` = `"AZT1-CHAIN-V1-NONCE"`
- `chain_root_mode` = `"genesis-signature-block"`
- `signature_checkpoint_alg` = the same profile as `this_header_signature_alg`
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
- `payload_block_types` map including logical type ids `0..127`
- `block_type_encoding` = `"msb_encryption_flag_v1"`
- `block_type_encrypted_mask` = `128`
- `block_type_id_mask` = `127`
- `signature_checkpoint_alg` = the same profile as `this_header_signature_alg`
- `signature_checkpoint_domain` = `"AZT1SIG1||ref_seq_u32be||chain_v32 (ref_seq>0) ; AZT1SIG0||chain_genesis_secret32 (ref_seq=0)"`
- `device_sign_public_key_b64` (base64 profile-specific public key; raw 32-byte Ed25519 or RSA SPKI DER)
- `device_sign_fingerprint_hex`
- `chain_alg` = `"sha256-link"`
- `chain_domain` = `"AZT1-CHAIN-V1-NONCE"`
- `chain_genesis_secret_b64` (base64, 32 bytes)
- `block1_must_be_signature_ref_seq0` = `true`
- `chain_root_mode` = `"genesis-signature-block"`
- `chunk_record_format` = `"seq_u32be|block_flags_type_u8|body_len_u32be|tag_len_u8|body|tag|chain_v32"`
- `signature_block_body_format` = `"ref_seq_u32be|sig_ed25519_64"` for Ed25519, `"ref_seq_u32be|signature"` for RSA
- `dropped_frames_block_body_format` = `"missed_frames_u16be"`
- `telemetry_block_body_format` (string format descriptor)
- `audio_frame_duration_ms` (number)
- optional `recommended_decode_gain`

Additional metadata is allowed.

---

## 5) Chunk stream framing and semantics

Each chunk record:

- `seq_u32be`
- `block_flags_type_u8` (`is_encrypted = (byte & 0x80) != 0`; `type_id = byte & 0x7F`)
- `body_len_u32be`
- `tag_len_u8`
- `body` (`body_len` bytes)
- `tag` (`tag_len` bytes)
- `chain_v32` (32-byte SHA-256 link)

Record sequence numbers MUST start at 1 and increase by exactly one for every
complete record, regardless of type or encryption. Readers MUST reject zero,
gaps, duplicates, decreases, and wraparound before chain verification or audio
processing. Genesis is permitted only at the start of a recording; a later
`seq == 1` MUST NOT reset the chain. Incomplete trailing records retain the
crash-recovery behavior described below.

Chain rule (`sha256-link` with nonce domain binding):

- `nonce_hash = SHA256(stream_auth_nonce_utf8)`
- `seq == 1`: `V = SHA256("AZT1-CHAIN-V1-NONCE" || nonce_hash || record_bytes)`
- `seq > 1`: `V = SHA256("AZT1-CHAIN-V1-NONCE" || nonce_hash || prev_V || record_bytes)`
- `record_bytes = seq_u32be || block_flags_type_u8 || body_len_u32be || tag_len_u8 || body || tag`

`block_type` encoding and classes:

- `wire_byte = (is_encrypted ? 0x80 : 0x00) | type_id`
- `type_id = wire_byte & 0x7F`
- `is_encrypted = (wire_byte & 0x80) != 0`

Current logical type IDs:

- `type_id=0` PCM audio block (normally emitted encrypted; `tag_len=16` when encrypted)
- `type_id=1` checkpoint signature block (plaintext; `tag_len=0`, body length = 4 + signature size for the declared profile)
- `type_id=2` dropped-frames notice (plaintext; `tag_len=0`, body len 2 expected by strict validator)
- `type_id=3` telemetry snapshot (normally emitted encrypted; `tag_len=16` when encrypted)

Tag rule is flag-driven:

- if `is_encrypted == true`, `tag_len` MUST equal `16`
- if `is_encrypted == false`, `tag_len` MUST equal `0`

Encrypted block nonce:

- `nonce = audio_nonce_prefix(4B) || seq_u32be || 0x00000000`

Signature block verification message:

- If `ref_seq == 0`: `AZT1SIG0 || chain_genesis_secret32`
- If `ref_seq > 0`: `AZT1SIG1 || ref_seq_u32be || chain_v32(ref_seq)`

Mandatory genesis anchor rule:

- `seq == 1` MUST be a signature block (`type_id == 1` and `is_encrypted == false`)
- block 1 MUST set `ref_seq == 0`
- this signs encrypted-only genesis secret and prevents blind re-signing by actors without inner-header decrypt capability.

---

## 6) Decoder/validator behavior (current)

1. Verify `AZT1\n` magic.
2. Parse outer header JSON line.
3. Parse outer signature line (base64 signature (algorithm selected by `this_header_signature_alg`) over raw outer JSON bytes).
4. Read `next_header_len_u16`.
5. If `N == 0xFFFF`, parse plaintext next-header line and verify `next_header_plaintext_sha256_b64`.
6. If `N != 0xFFFF`, verify ciphertext length/hash commitments from outer header.
7. If private key provided, unwrap/decrypt next header and verify plaintext hash commitment.
8. Parse chunk records to EOF (allow trailing partial bytes).
9. Verify chain link per record (`sha256-link`, domain `AZT1-CHAIN-V1-NONCE`, nonce-bound).
10. Enforce genesis-anchor rule: first record must be signature block with `ref_seq=0`.
11. Derive `is_encrypted` and `type_id` from `block_flags_type_u8` (`is_encrypted=(b&0x80)!=0`, `type_id=b&0x7F`).
12. Enforce tag-length invariant from flag: encrypted => `tag_len=16`; plaintext => `tag_len=0`.
13. For encrypted records, decrypt when audio key is available.
14. For signature logical type (`type_id=1`), verify checkpoint signatures using the declared signature profile (`AZT1SIG0` for `ref_seq=0`, `AZT1SIG1` otherwise) when signing key is available.

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


## Signature profiles and Android writer (container 0.1)

This is an algorithm extension within existing AZT1 framing. AES-GCM, RSA-OAEP
recipient wrapping (SHA-256 with MGF1-SHA256), hash-chain inputs, signing domains,
and truncation semantics are unchanged. Historical container 0.0 remains readable.
The original Android writer emits 0.1 and historical firmware emits 0.0; current
writers emit 0.2 with the authenticated-finalization extension below.

| Profile | Public key bytes | Signature bytes | Checkpoint/finalize body bytes |
| --- | --- | --- | --- |
| `ed25519` | 32-byte raw public key | 64 | 68 |
| `rsa-pss-sha256` | Canonical DER SubjectPublicKeyInfo, RSA 2048/3072/4096 | modulus size / 8 | 4 + modulus size / 8 |

RSA-PSS uses SHA-256, MGF1-SHA256, exactly 32 salt bytes, and the standard PSS
trailer. The profile fixes these parameters; they are not inferred from the key
or signature. RSA fingerprints are SHA-256 of SPKI DER. Outer and inner signing
keys/fingerprints must agree, and checkpoint algorithm declarations must agree
with the outer-header algorithm. Missing algorithm declarations retain their
historical Ed25519 meaning; unknown or mismatched algorithms are rejected.
Administrator certificate signatures remain governed by their own certificate
profile; this extension does not issue or change administrator certificates.

Finalize records (`type_id=127`, plaintext, no tag) use the same signature body
as checkpoints and authenticate the preceding chain value using `AZT1SIG1`.
A missing finalize record is valid evidence of an unfinished recording. SDK
reports expose `finalize_seen` and `last_verified_ref_seq` alongside unsigned-tail
counts. Partial-record byte counts include the incomplete record's header.

Android local captures generate a fresh random stream nonce and declare
`stream_auth_mode=local-capture-random-nonce`; this is not a server-issued freshness
challenge. Their wall clock is explicitly unverified. The prototype pins its
Keystore identity locally and does not yet include an administrator certificate.

Recovery MUST preserve existing files unchanged. It MUST NOT append, sign an old
unsigned tail, or synthesize a finalize record. A new recording uses a new file,
RAM-only AES key, nonce prefix, genesis secret, and stream nonce. Finalized or
unfinished source AZT bytes are never rewritten by decoding.

Regression fixtures: `client/test/unit_sdk/fixtures/signature_profiles/`, exercised
by `test_signature_profiles.py` (encrypted and decoded-header forms, both profiles).


## Authenticated finalization extension: `azt-finalize-v1` (October 2026)

The shared checkpoint/finalize domain described above is legacy. It does not
authenticate termination intent: truncating at a checkpoint, changing its type to
127 and recomputing its terminal public chain preserves the signature. Valid
legacy prefix signatures remain evidence of that prefix, not of normal termination.

New Android and firmware writers declare BOTH `finalize_signature_profile="azt-finalize-v1"`
and `finalize_signature_domain="AZT1FINAL1||ref_seq_u32be||chain_v32"` in the
signed outer and committed inner headers. Type 127 MUST verify over literal ASCII
`AZT1FINAL1` followed by the four big-endian reference bytes and 32 referenced chain
bytes. The reference must be positive and exactly the immediately previous record.
Body framing, genesis and checkpoint domains are unchanged. Never retry a legacy
domain on failure. Both declarations must agree; unknown or partial declarations
are errors. Absence in both headers selects legacy, never authenticated finalization.
Current Android and firmware writers report container 0.2, but the named signed
profile controls the cryptographic semantics. Historical firmware output remains
legacy. Older decoders need updating to accept new finalizers.

SDK reports retain `finalize_seen` as marker presence and add
`finalize_signature_verified`, `finalization_intent_authenticated`,
`finalize_signature_profile`, `termination_status` and `finalization_warning`.
Only new-profile verified finalizers set authenticated intent. Legacy records use
`legacy-finalize-unbound`; valid audio still decodes. Missing finalizers are unfinished
recordings with recoverable signed prefixes, not automatically invalid evidence.
A verified ending does not establish trusted capture time or why recording stopped.

New-profile duplicate outer/inner fields must agree; container/certificate JSON
parsing rejects duplicate keys. Signed messages always use original bytes. Public
synthetic vectors and attacker-style tests are in
`client/test/unit_sdk/fixtures/finalization_v1/` and
`client/test/unit_sdk/test_finalization_profiles.py`.

### Firmware migration and compatibility

Firmware now writes container 0.2 with `azt-finalize-v1` in both headers and signs
finalizers with `AZT1FINAL1`. Checkpoint and genesis messages are unchanged.

| Writer output | Reader requirement | Termination evidence |
| --- | --- | --- |
| Historical firmware 0.0 | Historical or current reader | Legacy marker, no authenticated ending intent |
| Current firmware 0.2 | Reader supporting `azt-finalize-v1` | Verified finalizer authenticates ending intent |

Update readers before deploying this firmware. Readers must retain historical
read support without presenting legacy finalizers as authenticated endings. No
API version changes are introduced by this named container-profile extension.

Genesis uses a fresh 32-byte `esp_fill_random` secret per stream, committed by the
signed outer header through the inner-header hashes. The initial zeroed `v_prev`
is not included in record 1's hash input. The obsolete zero-filled `chain_key`
field was unused and has been removed; this does not change wire bytes.

### Firmware stream lifetime limit

Firmware ends each stream after at most three 365-day years (94,608,000 seconds)
of monotonic elapsed streaming time. A shorter requested duration still applies.
At the limit it sends a type 126 closing message with cause
`stream_lifetime_limit`, followed by the authenticated type 127 finalizer and
closes the HTTP stream. Delivery requires a working connection; a failed delivery
still leaves an unfinished recording, not a fabricated successful finalization.

Independently, ordinary records stop at sequence `0xFFFFFFFD`. The remaining two
sequence values are reserved for a closing message and finalizer; this earlier
ending reports `stream_record_limit`. Record generation rejects counter overflow
before encryption. A subsequent stream starts with fresh key material. This is a
firmware writer policy and does not invalidate longer historical recordings.
