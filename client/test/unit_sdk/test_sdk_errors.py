from __future__ import annotations

import pytest

from tools.azt_sdk import errors


def test_known_error_registry_contains_core_codes():
    assert errors.is_known_error("APPLY_CONFIG_POST_FAILED") is True
    assert errors.is_known_error("NOT_A_REAL_CODE") is False


def test_ensure_known_error_raises_for_unknown():
    with pytest.raises(ValueError):
        errors.ensure_known_error("NOPE")


def test_exception_detail_contains_expected_fields():
    d = errors.exception_detail(where="x", exc=RuntimeError("boom"), context={"a": 1})
    assert d["where"] == "x"
    assert d["exception_type"] == "RuntimeError"
    assert d["context"]["a"] == 1


def test_ensure_known_error_happy_path_returns_code():
    code = "APPLY_CONFIG_POST_FAILED"
    assert errors.ensure_known_error(code) == code
