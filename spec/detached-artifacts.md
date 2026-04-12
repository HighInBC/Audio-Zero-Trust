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

Mode-specific:

- if `next_header_mode == "encrypted"`:
  - `next_header_ciphertext_b64` (string, required)
- if `next_header_mode == "plaintext"`:
  - `next_header_plaintext_json_utf8` (string, required)

### 2.3 `original_base_name` derivation

Current exporter derives `original_base_name` from input filename by removing the first matching suffix in this ordered set:

1. `.azt.request`
2. `.request`
3. `.azt.key`
4. `.key`
5. `.azt`

If no suffix matches, basename is used unchanged.

### 2.4 Request consumer requirements (`decode` path)

For detached decode input, consumer must:

1. parse JSON object,
2. require `schema == "azt.header-separation.v1"`,
3. require `next_header_mode == "encrypted"`,
4. read `plain_header_json_utf8` and parse as JSON,
5. read `next_header_ciphertext_b64` and base64-decode ciphertext bytes.

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
