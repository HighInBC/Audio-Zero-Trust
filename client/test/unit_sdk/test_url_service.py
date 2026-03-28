from __future__ import annotations

from tools.azt_sdk.services import url_service


def test_base_url_preserves_explicit_scheme():
    assert url_service.base_url(host="https://device.local:8443", port=8080) == "https://device.local:8443"


def test_base_url_auto_uses_http_without_local_tls(monkeypatch):
    monkeypatch.setattr(url_service, "_has_local_tls_trust", lambda: False)
    assert url_service.base_url(host="10.0.0.2", port=8080, scheme="auto") == "http://10.0.0.2:8080"


def test_base_url_auto_uses_https_and_port_upgrade(monkeypatch):
    monkeypatch.setattr(url_service, "_has_local_tls_trust", lambda: True)
    assert url_service.base_url(host="10.0.0.2", port=8080, scheme="auto") == "https://10.0.0.2:8443"


def test_base_url_explicit_scheme_keeps_given_port():
    assert url_service.base_url(host="10.0.0.2", port=8080, scheme="https") == "https://10.0.0.2:8080"
