# Error Contract

This project emits a stable envelope for all CLI commands when `--json` is used:

```json
{
  "ok": false,
  "command": "apply-config",
  "error": "APPLY_CONFIG_POST_FAILED",
  "detail": null,
  "payload": {
    "error": "APPLY_CONFIG_POST_FAILED",
    "detail": {
      "where": "operations_service.apply_config.post",
      "exception_type": "URLError",
      "message": "<raw exception message>",
      "url": "https://host:8443/api/v0/config"
    }
  }
}
```

## Rules

1. Top-level envelope keys are always present:
   - `ok`, `command`, `error`, `detail`, `payload`
2. On failure, `error` is a stable machine-readable code.
3. Exception failures use structured detail objects with:
   - `where`, `exception_type`, `message`
   - plus actionable context like `url` when applicable.
4. Human-readable diagnostics are preserved in `detail.message` and payload fields.
5. Error code names are defined centrally in:
   - `client/tools/azt_sdk/errors.py`

## Common failure families

- Config apply/patch network failures:
  - `APPLY_CONFIG_POST_FAILED`
  - `APPLY_CONFIG_STATE_GET_FAILED`
  - `CONFIG_PATCH_POST_FAILED`
  - `CONFIG_PATCH_STATE_GET_FAILED`
- Device endpoint failures:
  - `STATE_GET_V0_FAILED`
  - `ATTESTATION_GET_FAILED`
  - `CERTIFICATE_POST_FAILED`
- Stream/device transport and auth failures:
  - `STREAM_CHALLENGE_FAILED`
  - `STREAM_AUTH_KEY_REQUIRED`
  - `STREAM_AUTH_KEY`
  - `STREAM_READ_REQUEST_FAILED`
  - `STREAM_READ_ITERATION_FAILED`
- Firmware stream auth responses (from `/stream`):
  - `ERR_STREAM_NONCE_REQUIRED`
  - `ERR_STREAM_AUTH_REQUIRED`
  - `ERR_STREAM_AUTH_VERIFY`
