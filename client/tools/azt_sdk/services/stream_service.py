from __future__ import annotations

from pathlib import Path

from tools.azt_client.stream import fetch_stream_sample, validate_azt1_stream_chain, decode_azt1_stream_to_wav
from tools.azt_sdk.services.device_service import stream_listen as device_stream_listen


def fetch_sample(*, host: str, port: int, seconds: int, out_path: str) -> dict:
    return fetch_stream_sample(host, port, seconds, Path(out_path))


def stream_validate(*, in_path: str, key_path: str) -> dict:
    key_raw = Path(key_path).read_bytes() if str(key_path).strip() else None
    return validate_azt1_stream_chain(
        data=Path(in_path).read_bytes(),
        admin_private_key_pem=key_raw,
    )


def stream_decode(*, in_path: str, key_path: str, out_path: str, apply_gain: bool, gain: float | None, preserve_tail: bool) -> dict:
    key_raw = Path(key_path).read_bytes() if str(key_path).strip() else None
    return decode_azt1_stream_to_wav(
        data=Path(in_path).read_bytes(),
        out_wav_path=Path(out_path),
        admin_private_key_pem=key_raw,
        apply_gain=apply_gain,
        gain=gain,
        preserve_tail=preserve_tail,
    )


def stream_listen(*, host: str, port: int, seconds: float | None, timeout: int, key_path: str, auth_key_path: str | None = None, apply_gain: bool = False, gain: float | None = None, pcm_callback=None) -> tuple[bool, dict]:
    return device_stream_listen(
        host=host,
        port=port,
        seconds=seconds,
        timeout=timeout,
        key_path=key_path,
        auth_key_path=auth_key_path,
        apply_gain=apply_gain,
        gain=gain,
        pcm_callback=pcm_callback,
    )
