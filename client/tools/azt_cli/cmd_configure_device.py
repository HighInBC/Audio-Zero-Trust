from __future__ import annotations

import argparse
from pathlib import Path
from tools.azt_cli.output import emit_envelope
from tools.azt_sdk.services.provisioning_service import configure_device


def run(args: argparse.Namespace) -> int:
    try:
        admin_dir = args.admin_creds_dir
        recorder_dir = args.recorder_creds_dir or admin_dir
        ota_ver_raw = (getattr(args, "ota_version_code", "") or "").strip().lower()
        ota_ver = None
        if ota_ver_raw:
            if ota_ver_raw == "timestamp":
                from datetime import datetime, timezone
                ota_ver = int(datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S"))
            else:
                ota_ver = int(ota_ver_raw)

        ota_floor_raw = (getattr(args, "ota_min_version_code", "") or "").strip().lower()
        ota_floor = None
        if ota_floor_raw:
            if ota_floor_raw == "same":
                if ota_ver is None:
                    emit_envelope(command="configure-device", ok=False, error="INVALID_OTA_VERSION_CODE", payload={"detail": "--ota-version-code is required when --ota-min-version-code=same"}, as_json=bool(getattr(args, "as_json", False)))
                    return 1
                ota_floor = ota_ver
            else:
                ota_floor = int(ota_floor_raw)

        if ota_floor is not None and ota_ver is None:
            emit_envelope(command="configure-device", ok=False, error="INVALID_OTA_VERSION_CODE", payload={"detail": "--ota-version-code is required when setting --ota-min-version-code"}, as_json=bool(getattr(args, "as_json", False)))
            return 1
        ota_signer_pem = ""
        ota_signer_path = (getattr(args, "ota_signer_public_key_pem", "") or "").strip()
        if ota_signer_path:
            ota_signer_pem = Path(ota_signer_path).read_text(encoding="utf-8")
        code, ok, err, payload = configure_device(
            admin_creds_dir=admin_dir,
            recorder_creds_dir=recorder_dir,
            identity=args.identity,
            wifi_ssid=args.wifi_ssid,
            wifi_password=args.wifi_password,
            authorized_listener_ips=list(args.authorized_listener_ip or []),
            time_servers=list(args.time_server or []),
            no_time=bool(args.no_time),
            port=args.port,
            ip=(args.ip or None),
            baud=int(args.baud),
            ip_timeout=int(args.ip_timeout),
            no_auto_ip=bool(args.no_auto_ip),
            allow_serial_bootstrap=bool(args.allow_serial_bootstrap),
            ota_version_code=ota_ver,
            ota_min_version_code=ota_floor,
            ota_min_version_code_clear=bool(getattr(args, "ota_min_version_code_clear", False)),
            ota_signer_public_key_pem=ota_signer_pem,
            ota_signer_clear=bool(getattr(args, "ota_signer_clear", False)),
            mdns_enabled=bool(getattr(args, "mdns_enabled", False)),
            mdns_hostname=(getattr(args, "mdns_hostname", "") or ""),
        )
        emit_envelope(
            command="configure-device",
            ok=ok,
            error=err,
            detail=payload.get("detail") if isinstance(payload, dict) else None,
            payload=(payload if isinstance(payload, dict) else {}),
            as_json=bool(getattr(args, "as_json", False)),
        )
        return int(code)
    except Exception as e:
        emit_envelope(
            command="configure-device",
            ok=False,
            error="CONFIGURE_DEVICE_ERROR",
            detail=str(e),
            as_json=bool(getattr(args, "as_json", False)),
        )
        return 2
