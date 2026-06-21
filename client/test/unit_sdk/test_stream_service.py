from __future__ import annotations

from pathlib import Path

from tools.azt_sdk.services import stream_service


def test_fetch_sample_delegates(monkeypatch, tmp_path):
    called = {}

    def fake_fetch(host, port, seconds, out_path):
        called["args"] = (host, port, seconds, out_path)
        return {"ok": True}

    monkeypatch.setattr(stream_service, "fetch_stream_sample", fake_fetch)
    out = stream_service.fetch_sample(host="h", port=8081, seconds=2, out_path=str(tmp_path / "s.bin"))
    assert out["ok"] is True
    assert called["args"][0] == "h"


def test_stream_validate_reads_input_and_optional_key(monkeypatch, tmp_path):
    in_path = tmp_path / "in.bin"
    in_path.write_bytes(b"stream-data")
    key_path = tmp_path / "key.pem"
    key_path.write_bytes(b"pem")

    monkeypatch.setattr(
        stream_service,
        "validate_azt1_stream_chain",
        lambda data, admin_private_key_pem: {"ok": True, "len": len(data), "has_key": admin_private_key_pem == b"pem"},
    )

    out = stream_service.stream_validate(in_path=str(in_path), key_path=str(key_path))
    assert out["ok"] is True and out["has_key"] is True


def test_stream_decode_passes_flags(monkeypatch, tmp_path):
    in_path = tmp_path / "in.bin"
    in_path.write_bytes(b"stream-data")
    out_path = tmp_path / "out.wav"

    captured = {}

    def fake_decode(**kwargs):
        captured.update(kwargs)
        return {"ok": True}

    monkeypatch.setattr(stream_service, "decode_azt1_stream_to_wav", fake_decode)

    out = stream_service.stream_decode(
        in_path=str(in_path),
        key_path="",
        out_path=str(out_path),
        apply_gain=True,
        gain=1.5,
        preserve_tail=False,
    )

    assert out["ok"] is True
    assert captured["apply_gain"] is True
    assert captured["gain"] == 1.5
    assert captured["out_wav_path"] == Path(out_path)


def test_stream_listen_delegates(monkeypatch):
    captured = {}

    def fake_listen(**kwargs):
        captured.update(kwargs)
        return True, {"pcm_bytes": 4}

    monkeypatch.setattr(stream_service, "device_stream_listen", fake_listen)

    ok, payload = stream_service.stream_listen(
        host="h",
        port=8080,
        seconds=1.0,
        timeout=2,
        key_path="listener.pem",
        auth_key_path="auth.pem",
        apply_gain=True,
        gain=2.0,
        pcm_callback=lambda pcm, header: None,
    )

    assert ok is True
    assert payload["pcm_bytes"] == 4
    assert captured["key_path"] == "listener.pem"
    assert captured["auth_key_path"] == "auth.pem"
    assert captured["apply_gain"] is True
