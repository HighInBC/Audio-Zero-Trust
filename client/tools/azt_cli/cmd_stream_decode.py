from __future__ import annotations

import argparse
from pathlib import Path

from tools.azt_cli.output import emit_envelope
from tools.azt_sdk.services.stream_service import stream_decode


def run(args: argparse.Namespace) -> int:
    try:
        in_paths = [str(p) for p in (getattr(args, "in_path", []) or [])]
        if not in_paths:
            emit_envelope(
                command="stream-decode",
                ok=False,
                error="STREAM_DECODE_ARGS",
                detail="at least one --in path is required",
                payload={},
                as_json=bool(getattr(args, "as_json", False)),
            )
            return 1

        out_arg = str(getattr(args, "out_path", "") or "").strip()
        multi = len(in_paths) > 1
        if multi and out_arg:
            emit_envelope(
                command="stream-decode",
                ok=False,
                error="STREAM_DECODE_ARGS",
                detail="--out cannot be used with multiple --in files; outputs default to <in>.wav",
                payload={},
                as_json=bool(getattr(args, "as_json", False)),
            )
            return 1

        results = []
        all_ok = True
        for in_path in in_paths:
            out_path = out_arg if (not multi and out_arg) else (in_path + ".wav")
            out_path = str(Path(out_path))
            try:
                out = stream_decode(
                    in_path=in_path,
                    key_path=args.key_path,
                    out_path=out_path,
                    apply_gain=bool(getattr(args, "apply_gain", False)),
                    gain=(float(args.gain) if getattr(args, "gain", None) is not None else None),
                )
                ok = bool(out.get("ok"))
                all_ok = all_ok and ok
                if isinstance(out, dict):
                    out.setdefault("in", in_path)
                    out.setdefault("out", out_path)
                results.append(out)
            except Exception as e:
                all_ok = False
                results.append({"ok": False, "in": in_path, "out": out_path, "error": "STREAM_DECODE_EXCEPTION", "detail": str(e)})

        payload = results[0] if len(results) == 1 else {"ok": all_ok, "results": results}
        emit_envelope(
            command="stream-decode",
            ok=all_ok,
            error=None if all_ok else "STREAM_DECODE_FAILED",
            payload=payload,
            as_json=bool(getattr(args, "as_json", False)),
        )
        return 0 if all_ok else 1
    except Exception as e:
        emit_envelope(
            command="stream-decode",
            ok=False,
            error="STREAM_DECODE_EXCEPTION",
            detail=str(e),
            payload={},
            as_json=bool(getattr(args, "as_json", False)),
        )
        return 1
