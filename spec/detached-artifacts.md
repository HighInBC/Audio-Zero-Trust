# AZT Detached Artifacts (`.azt.request` / `.azt.key`) — current v1 profiles

This document is normative for the current detached-header workflows implemented by:

- `client/tools/azt_sdk/services/operations_service.py`
- CLI wrappers in `client/tools/azt_tool.py`:
  - `detached-headers-export`
  - `detached-headers-decode`
  - `detached-headers-combine`

If implementation and this spec diverge, update this spec in the same change.

---

## 1) Scope

Detached artifacts exist to support split workflows where next-header decryption is performed independently from full `.azt` processing.

- `.azt.request` carries detached header material extracted from an AZT1 file.
- `.azt.key` carries decrypted next-header plaintext material (keying/config needed for decode).

Both are UTF-8 JSON documents written with trailing newline by current tooling.

---

## 2) `.azt.request` format (`azt.header-separation.v1`)

### 2.1 File type

A `.azt.request` file is a UTF-8 JSON object with:

- `schema` exactly `"azt.header-separation.v1"`

### 2.2 Top-level fields emitted by export

Current exporter emits:

- `schema` (string, required)
- `source_file` (string, required; local input path as provided to exporter)
- `original_base_name` (string, required)
- `plain_header_json_utf8` (string, required)
- `plain_header_signature_line_b64` (string, required)
- `next_header_len_u16` (integer, required)
- `next_header_plaintext_sha256_b64` (string, expected)
- `next_header_plaintext_hash_alg` (string, expected; current profile `"sha256"`)
- `next_header_mode` (string, required; `"encrypted"` or `"plaintext"`)
- `payload_offset_bytes` (integer, required)
- `payload_len_bytes` (integer, required)
- `payload_sha256_hex` (string, required; SHA-256 over remaining payload bytes)
- `detached_decode_certificate_mode` (string, required; `"auto"|"always"|"none"`)
- `header_effective_auto_decode` (boolean, required)
- `detached_decode_certificate_attached` (boolean, required)

Mode-specific:

- if `next_header_mode == "encrypted"`:
  - `next_header_ciphertext_b64` (string, required)
- if `next_header_mode == "plaintext"`:
  - `next_header_plaintext_json_utf8` (string, required)

Conditional:

- if `detached_decode_certificate_attached == true`:
  - `detached_decode_certificate` (object, required)

### 2.3 Optional detached decode certificate object

When attached, `detached_decode_certificate` has:

- `signature_algorithm` = `"ed25519"`
- `signer_fingerprint_hex` (string)
- `certificate_payload_b64` (string; base64 of canonical JSON payload)
- `signature_b64` (string; Ed25519 signature over raw `certificate_payload_b64` decoded bytes)

Decoded certificate payload JSON (current writer format):

- `schema` = `"azt.detached-decode-cert.v1"`
- `certificate_type` = `"detached_decode_authorization"`
- `grant` object:
  - `action` = `"decode"`
  - `bind_by` = `"plain_header_signature_line_b64"`
  - `plain_header_signature_line_b64` (string)
  - `original_base_name` (string)
- `issuer` object:
  - `signer_alg` = `"ed25519"`
  - `signer_fingerprint_hex` (string)

Payload serialization at signing time is canonicalized by current exporter as:
- UTF-8 JSON with `sort_keys=true` and compact separators `(',', ':')`.

### 2.4 Detached certificate attachment behavior (export)

Exporter supports `detached_decode_cert_mode`:

- `none`: never attach certificate
- `always`: always attach certificate
- `auto` (default): attach only when `header_effective_auto_decode == false`

`header_effective_auto_decode` is evaluated from outer-header material as logical AND:

- `stream_header_auto_decode == true` in plaintext outer header, and
- embedded device certificate `authorized_consumers` contains `"auto-decode"`.

If attachment is required by mode (`always` or `auto` with ineffective auto-decode), exporter requires admin signing key input; otherwise export fails.

### 2.5 `original_base_name` derivation

Current exporter derives `original_base_name` from input filename by removing the first matching suffix in this ordered set:

1. `.azt.request`
2. `.request`
3. `.azt.key`
4. `.key`
5. `.azt`

If no suffix matches, basename is used unchanged.

### 2.6 Request consumer requirements (`decode` path)

For detached decode input, consumer must:

1. parse JSON object,
2. require `schema == "azt.header-separation.v1"`,
3. require `next_header_mode == "encrypted"`,
4. read `plain_header_json_utf8` and parse as JSON,
5. read `next_header_ciphertext_b64` and base64-decode ciphertext bytes.

Current decode path does not require detached certificate fields to decrypt next header; policy enforcement is caller/system responsibility.

Legacy compatibility (name propagation only):

- when resolving base name metadata, consumer checks in order:
  1. `original_base_name`
  2. `source_original_filename` (legacy)
  3. `original_filename` (legacy)
  4. derived basename fallback

---

## 3) `.azt.key` format (`azt.detached-key.v1`)

### 3.1 File type

Current writer emits `.azt.key` as UTF-8 JSON object:

- `schema` exactly `"azt.detached-key.v1"`
- `original_base_name` (string)
- `next_header_plaintext_b64` (string; base64 of decrypted next-header plaintext bytes)

### 3.2 Semantics

`next_header_plaintext_b64` decodes to the raw next-header plaintext JSON bytes that were encrypted in the source AZT container.

This payload contains decode keying material (including audio/session keys) and is the authoritative detached key material for combine/decode workflows.

---

## 4) Backward compatibility for key input

`detached-headers-combine` accepts either:

1. new JSON key package (`schema == "azt.detached-key.v1"`) with `next_header_plaintext_b64`, or
2. legacy raw bytes file containing plaintext next-header bytes directly.

Behavior:

- if key input parses as valid detached-key JSON, use decoded `next_header_plaintext_b64`.
- otherwise treat file bytes as plaintext next-header bytes.

---

## 5) Validation and reconstruction rules

When combining detached artifacts back into decoded AZT:

1. request package schema must match `azt.header-separation.v1`.
2. source `.azt` signature line must match `plain_header_signature_line_b64` from request package.
3. source payload range must match `payload_offset_bytes` + `payload_len_bytes`.
4. source payload SHA-256 must match `payload_sha256_hex`.
5. outer header must declare `next_header_plaintext_hash_alg == "sha256"`.
6. SHA-256 of supplied plaintext next header must equal `next_header_plaintext_sha256_b64`.
7. output AZT must be reconstructed in decoded-next-header sentinel mode:
   - magic `AZT1\n`
   - plaintext outer header line
   - signature line
   - next-header len = `0xFFFF`
   - plaintext next-header line + `\n`
   - original payload bytes

---

## 6) Error categories (current detached workflows)

Current operations use (non-exhaustive) error codes including:

- `ERR_MAGIC`
- `ERR_HEADER_JSON`
- `ERR_HEADER_SIG`
- `ERR_NEXT_HEADER_LEN`
- `ERR_PLAINTEXT_NEXT_HEADER`
- `ERR_ENCRYPTED_NEXT_HEADER`
- `ERR_DETACHED_MODE`
- `ERR_DETACHED_PLAIN_HEADER`
- `ERR_DETACHED_CIPHERTEXT`
- `ERR_DETACHED_CERT_MODE`
- `ERR_DETACHED_CERT_KEY_REQUIRED`
- `ERR_ENC_HEADER_LENGTH`
- `ERR_ENC_HEADER_TRUNCATED`
- `ERR_ALREADY_DECODED_NEXT_HEADER`
- `ERR_PLAIN_HASH_ALG`
- `ERR_PLAIN_HASH_MISMATCH`
- `ERR_HEADER_PACKAGE_SCHEMA`
- `ERR_SIGNATURE_LINE_MISMATCH`
- `ERR_INPUT_PAYLOAD_RANGE`
- `ERR_INPUT_PAYLOAD_MISMATCH`
- `ERR_DECODED_NEXT_HEADER_REQUIRED`
- `ERR_PLAIN_HASH_FIELD`

---

## 7) Notes

- `.azt.request` and `.azt.key` are naming conventions; tool behavior is schema-driven.
- Unknown additional JSON fields are tolerated by current parser paths unless explicitly required for an operation.
- Compatibility governance remains defined by `spec/compatibility-policy.md`.
