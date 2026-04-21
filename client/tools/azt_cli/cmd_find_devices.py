from __future__ import annotations

import argparse

from tools.azt_cli.output import emit_envelope, exception_detail
from tools.azt_sdk.services.device_service import find_devices


def run(args: argparse.Namespace) -> int:
    try:
        seconds = float(getattr(args, "seconds", 20.0) or 20.0)
        listen_port = int(getattr(args, "listen_port", 33333) or 33333)
        if seconds <= 0:
            emit_envelope(
                command="find-devices",
                ok=False,
                error="FIND_DEVICES_ARGS",
                payload={"detail": "--seconds must be > 0"},
                as_json=bool(getattr(args, "as_json", False)),
            )
            return 1

        ok, payload = find_devices(seconds=seconds, listen_port=listen_port)
        as_json = bool(getattr(args, "as_json", False))

        if as_json:
            emit_envelope(
                command="find-devices",
                ok=ok,
                error=None if ok else "FIND_DEVICES_FAILED",
                payload=payload,
                as_json=True,
            )
            return 0 if ok else 1

        if not ok:
            emit_envelope(
                command="find-devices",
                ok=False,
                error=str(payload.get("error") or "FIND_DEVICES_FAILED") if isinstance(payload, dict) else "FIND_DEVICES_FAILED",
                payload=payload if isinstance(payload, dict) else {"detail": str(payload)},
                as_json=False,
            )
            return 1

        devices = payload.get("devices") if isinstance(payload, dict) else []
        if not isinstance(devices, list):
            devices = []

        print(f"Detected {len(devices)} device(s) from discovery advertisements")
        for idx, d in enumerate(devices, start=1):
            name = str(d.get("device_name") or "-")
            fp = str(d.get("device_key_fingerprint_hex") or d.get("id") or "-")
            ip = str(d.get("source_ip") or "-")
            http_port = d.get("http_port")
            serial = str(d.get("certificate_serial") or "")
            print(f"[{idx}] {name} | {fp} | {ip}:{http_port if http_port is not None else '-'}")
            print(
                f"     admin={d.get('admin_key_fingerprint_hex') or '-'} listener={d.get('listener_key_fingerprint_hex') or '-'} recorder={d.get('recorder_auth_fingerprint_hex') or '-'}"
            )
            print(
                f"     cert_serial={serial or '-'} auto_record={bool(d.get('cert_auto_record'))} auto_decode={bool(d.get('cert_auto_decode'))} seen={int(d.get('seen_count') or 1)}"
            )
        return 0
    except Exception as e:
        emit_envelope(
            command="find-devices",
            ok=False,
            error="FIND_DEVICES_FAILED",
            detail=exception_detail("cmd_find_devices.run", e),
            as_json=bool(getattr(args, "as_json", False)),
        )
        return 1
