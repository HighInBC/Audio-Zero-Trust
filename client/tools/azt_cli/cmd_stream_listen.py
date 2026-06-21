from __future__ import annotations

import argparse
import contextlib
import sys
from pathlib import Path

from tools.azt_cli.output import emit_envelope, exception_detail
from tools.azt_sdk.services.stream_service import stream_listen


def run(args: argparse.Namespace) -> int:
    command_name = str(getattr(args, "command_name", "stream-listen"))
    out_file = None
    audio_stream = None
    try:
        key_path = (getattr(args, "key_path", "") or "").strip()
        raw_out = (getattr(args, "raw_out", "") or "").strip()
        raw_stdout = raw_out == "-"

        def emit(**kwargs) -> None:
            if raw_stdout:
                with contextlib.redirect_stdout(sys.stderr):
                    emit_envelope(**kwargs)
            else:
                emit_envelope(**kwargs)

        if not key_path:
            emit(command=command_name, ok=False, error="STREAM_LISTEN_ARGS", detail="provide --key <listener_private_key.pem>", as_json=bool(getattr(args, "as_json", False)))
            return 1

        play = not bool(getattr(args, "no_play", False))
        if not play and not raw_out:
            emit(command=command_name, ok=False, error="STREAM_LISTEN_ARGS", detail="provide a sink: playback enabled by default, or use --raw-out <file|->", as_json=bool(getattr(args, "as_json", False)))
            return 1

        if raw_stdout:
            out_file = sys.stdout.buffer
        elif raw_out:
            p = Path(raw_out)
            p.parent.mkdir(parents=True, exist_ok=True)
            out_file = p.open("wb")

        def pcm_sink(pcm: bytes, header: dict) -> None:
            nonlocal audio_stream
            if out_file is not None:
                out_file.write(pcm)
            if play:
                if audio_stream is None:
                    try:
                        import sounddevice as sd
                    except ImportError as e:
                        raise RuntimeError("live playback requires optional Python package 'sounddevice'; install it or use --no-play --raw-out <file>") from e
                    audio_stream = sd.RawOutputStream(
                        samplerate=int(header.get("sample_rate_hz", 16000)),
                        channels=int(header.get("channels", 1)),
                        dtype="int16",
                        blocksize=0,
                    )
                    audio_stream.start()
                audio_stream.write(pcm)

        seconds = None if getattr(args, "seconds", None) is None else float(args.seconds)
        ok, payload = stream_listen(
            host=args.host,
            port=int(args.port),
            seconds=seconds,
            timeout=int(args.timeout),
            key_path=key_path,
            auth_key_path=((getattr(args, "auth_key_path", "") or "").strip() or None),
            apply_gain=bool(getattr(args, "apply_gain", False)),
            gain=(None if getattr(args, "gain", None) is None else float(args.gain)),
            pcm_callback=pcm_sink,
        )
        if out_file is not None:
            out_file.flush()
        emit(command=command_name, ok=ok, error=None if ok else "STREAM_LISTEN_EMPTY", payload=payload, as_json=bool(getattr(args, "as_json", False)))
        return 0 if ok else 1
    except Exception as e:
        raw_stdout = (getattr(args, "raw_out", "") or "").strip() == "-"
        if raw_stdout:
            with contextlib.redirect_stdout(sys.stderr):
                emit_envelope(command=command_name, ok=False, error="STREAM_LISTEN_ERROR", detail=exception_detail("cmd_stream_listen.run", e), as_json=bool(getattr(args, "as_json", False)))
        else:
            emit_envelope(command=command_name, ok=False, error="STREAM_LISTEN_ERROR", detail=exception_detail("cmd_stream_listen.run", e), as_json=bool(getattr(args, "as_json", False)))
        return 1
    finally:
        if audio_stream is not None:
            audio_stream.stop()
            audio_stream.close()
        if out_file is not None and out_file is not sys.stdout.buffer:
            out_file.close()
