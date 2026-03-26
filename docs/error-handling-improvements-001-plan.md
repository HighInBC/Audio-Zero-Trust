# Error Handling Improvements 001 - Methodical Rollout Plan

## Policy Targets

1. Errors are actionable (include target URL/path/operation when relevant)
2. No ambiguous bundled failures
3. No unhandled exceptions
4. Origin is unambiguous (`where` + stable error code)
5. Human + machine readable output in all CLI responses

## Envelope Detail Shape

For exceptions, use:

```json
{
  "where": "module.function or command.run",
  "exception_type": "TypeName",
  "message": "raw exception message",
  "context": { "optional": "structured context" }
}
```

## Rollout Phases

- [x] Phase 1: Create central registry scaffold (`client/tools/azt_sdk/errors.py`)
- [x] Phase 2: Normalize CLI top-level exception details to structured format
- [x] Phase 3: Ensure tool entrypoint (`azt_tool.py`) uses structured unhandled exception detail
- [x] Phase 4: Add actionable `configure-device` state probe network context (URL + where)
- [~] Phase 5: Service-layer network calls (`operations_service`, `device_service`, `tls_service`) include attempted URL/endpoint on failures (in progress: core request paths updated + apply/config-patch + primary device-service endpoints covered)
- [~] Phase 6: Replace ambiguous combined validation failures with one-code-per-condition in remaining high-traffic paths (in progress: configure-device/provisioning split + targeted service branches)
- [~] Phase 7: Add negative-path tests asserting error code + `where` + key context fields (in progress: CLI contract smoke now checks structured `detail` on failure)

## Current Scope Completed

- Added `exception_detail(...)` helper in `client/tools/azt_cli/output.py`
- Updated all CLI command modules that had broad `except Exception` wrappers to emit structured detail
- Updated `configure-device` service probe failure payload to include:
  - error code
  - where
  - URL
  - exception type/message

## Remaining Gaps Checklist

- [ ] Add explicit regression tests for service-layer failure codes:
  - `APPLY_CONFIG_POST_FAILED`, `APPLY_CONFIG_STATE_GET_FAILED`
  - `CONFIG_PATCH_POST_FAILED`, `CONFIG_PATCH_STATE_GET_FAILED`
  - `STATE_GET_V0_FAILED`, `ATTESTATION_GET_FAILED`, `CERTIFICATE_POST_FAILED`
- [ ] Normalize remaining broad command-level `*_ERROR` wrappers into more specific families where practical.
- [ ] Add a short `docs/error-contract.md` with canonical failure-detail object examples.
- [ ] Optional: enforce known-code usage in CI (lint against unknown error constants).

## Next Priority

1. Add focused negative tests for the new service-layer error codes.
2. Split any remaining broad command-level error wrappers if they hide multiple causes.
3. Document the contract in a dedicated short doc and lock with CI checks.
