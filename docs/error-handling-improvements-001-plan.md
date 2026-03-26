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
- [ ] Phase 5: Service-layer network calls (`operations_service`, `device_service`, `tls_service`) include attempted URL/endpoint on failures
- [ ] Phase 6: Replace ambiguous combined validation failures with one-code-per-condition in remaining high-traffic paths
- [ ] Phase 7: Add negative-path tests asserting error code + `where` + key context fields

## Current Scope Completed

- Added `exception_detail(...)` helper in `client/tools/azt_cli/output.py`
- Updated all CLI command modules that had broad `except Exception` wrappers to emit structured detail
- Updated `configure-device` service probe failure payload to include:
  - error code
  - where
  - URL
  - exception type/message

## Next Priority

Focus service-layer paths where users most frequently hit network/provisioning issues:

1. `client/tools/azt_sdk/services/operations_service.py`
2. `client/tools/azt_sdk/services/device_service.py`
3. `client/tools/azt_sdk/services/tls_service.py`

Add URL/path context in every caught request failure and ensure each branch has a distinct stable error code.
