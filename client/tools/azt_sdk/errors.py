from __future__ import annotations

"""Central error-code registry and shared helpers.

Policy:
- Keep canonical error names centralized here.
- Keep contextual detail generation at call-sites.
- Use shared helpers only for logic reused in multiple places.
"""

from typing import Any


ERROR_CODES: dict[str, str] = {
    # configure-device family
    "CONFIGURE_DEVICE_ERROR": "Top-level unhandled exception in configure-device command handler.",
    "CONFIGURE_DEVICE_INVALID_OTA_VERSION_CODE": "Invalid or missing OTA version-code combination.",
    "CONFIGURE_DEVICE_INVALID_AUDIO_PREAMP_GAIN": "Audio preamp gain outside valid range.",
    "CONFIGURE_DEVICE_INVALID_AUDIO_ADC_GAIN": "Audio ADC gain outside valid range.",
    "CONFIGURE_DEVICE_HTTP_STATE_PROBE_FAILED": "HTTP state probe failed before config apply.",
}


def is_known_error(code: str) -> bool:
    return code in ERROR_CODES


def ensure_known_error(code: str) -> str:
    if code not in ERROR_CODES:
        raise ValueError(f"unknown error code: {code}")
    return code


def exception_detail(*, where: str, exc: Exception, context: dict[str, Any] | None = None) -> dict[str, Any]:
    detail: dict[str, Any] = {
        "where": where,
        "exception_type": type(exc).__name__,
        "message": str(exc),
    }
    if context:
        detail["context"] = context
    return detail
