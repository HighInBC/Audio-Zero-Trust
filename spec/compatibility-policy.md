# Compatibility Policy

This project uses explicit, versioned compatibility rules across file format, API, SDK, and firmware.

## 1) File format compatibility (AZT container)

### Policy
- **Read compatibility is preserved for all historical container versions**.
- New writers emit only the current format version.
- Old-version parsing code must be isolated from current code paths.

### Implementation rules
- Each container version gets its own parser module (example: `format/v1`, `format/v2`, ...).
- A strict version dispatcher selects parser by declared version fields.
- No heuristic cross-version parsing fallbacks.
- Every supported version has golden fixtures and regression tests that stay in CI permanently.

## 2) API compatibility (client SDK ↔ firmware)

### Policy
- **Major versions must match** for client and firmware.
- Minor mismatches are allowed.

### Behavior on minor mismatch
- Client may attempt newer features.
- Firmware must return a structured unsupported response when a feature is unavailable.
- Client SDK must gracefully degrade (or emit a clear actionable error) when feature is unsupported.

### Required error behavior
- Use explicit, structured errors for unsupported features (for example `ERR_UNSUPPORTED_FEATURE`).
- Do not return generic/internal errors for capability mismatch.

## 3) Capability discovery

Firmware must expose a capability surface that includes at minimum:
- `api_major`
- `api_minor`
- supported feature set (boolean flags and/or named feature list)

Client SDK must query capabilities before feature-dependent operations and branch behavior accordingly.

## 4) Change management requirements

Any breaking change must include, in the same PR:
1. Version bump (relevant major)
2. Compatibility matrix update
3. Migration note (developer-facing)
4. Tests for new behavior and retained compatibility obligations

## 5) Compatibility matrix expectations

Maintain a simple matrix in docs showing supported combinations:
- SDK major/minor ↔ Firmware major/minor
- Container read support versions
- Feature gates for minor-version differences

---

This policy is normative for protocol and interface evolution in this repository.
