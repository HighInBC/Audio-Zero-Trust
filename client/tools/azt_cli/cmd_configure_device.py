from __future__ import annotations

import argparse
from pathlib import Path
from tools.azt_cli.output import emit_envelope
from tools.azt_sdk.errors import exception_detail
from tools.azt_sdk.services.provisioning_service import configure_device


def run(args: argparse.Namespace) -> int:
    try:
        admin_dir = (args.admin_creds_dir or "").strip()
        listener_dir = (args.listener_creds_dir or "").strip() or admin_dir
        recorder_auth_dir = (getattr(args, "recorder_auth_creds_dir", "") or "").strip() or None

        missing: list[str] = []
        if not admin_dir:
            missing.append("--admin-creds-dir")
        if not (getattr(args, "identity", "") or "").strip():
            missing.append("--identity")
        wifi_mode = (getattr(args, "wifi_mode", "sta") or "sta").strip().lower()
        if wifi_mode == "ap":
            if not (getattr(args, "wifi_ap_ssid", "") or "").strip():
                missing.append("--wifi-ap-ssid")
            if len((getattr(args, "wifi_ap_password", "") or "").strip()) < 8:
                missing.append("--wifi-ap-password (min 8 chars)")
        else:
            if not (getattr(args, "wifi_ssid", "") or "").strip():
                missing.append("--wifi-ssid")
            if not (getattr(args, "wifi_password", "") or "").strip():
                missing.append("--wifi-password")
        if missing:
            emit_envelope(
                command="configure-device",
                ok=False,
                error="CONFIGURE_DEVICE_ARGS",
                payload={"detail": f"missing required options: {', '.join(missing)}"},
                as_json=bool(getattr(args, "as_json", False)),
            )
            return 1
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
                    emit_envelope(command="configure-device", ok=False, error="INVALID_OTA_VERSION_CODE_REQUIRED_FOR_SAME_FLOOR", payload={"detail": "--ota-version-code is required when --ota-min-version-code=same", "where": "cmd_configure_device.run.ota_floor_same"}, as_json=bool(getattr(args, "as_json", False)))
                    return 1
                ota_floor = ota_ver
            else:
                ota_floor = int(ota_floor_raw)

        if ota_floor is not None and ota_ver is None:
            emit_envelope(command="configure-device", ok=False, error="INVALID_OTA_VERSION_CODE_REQUIRED_FOR_MIN_FLOOR", payload={"detail": "--ota-version-code is required when setting --ota-min-version-code", "where": "cmd_configure_device.run.ota_floor_requires_version"}, as_json=bool(getattr(args, "as_json", False)))
            return 1
        ota_signer_pem = ""
        ota_signer_path = (getattr(args, "ota_signer_public_key_pem", "") or "").strip()
        if ota_signer_path:
            ota_signer_pem = Path(ota_signer_path).read_text(encoding="utf-8")
        audio_preamp_gain = getattr(args, "audio_preamp_gain", None)
        audio_adc_gain = getattr(args, "audio_adc_gain", None)
        if audio_preamp_gain is not None and not (1 <= int(audio_preamp_gain) <= 8):
            emit_envelope(command="configure-device", ok=False, error="INVALID_AUDIO_PREAMP_GAIN", payload={"detail": "--audio-preamp-gain must be 1..8"}, as_json=bool(getattr(args, "as_json", False)))
            return 1
        if audio_adc_gain is not None and not (0 <= int(audio_adc_gain) <= 255):
            emit_envelope(command="configure-device", ok=False, error="INVALID_AUDIO_ADC_GAIN", payload={"detail": "--audio-adc-gain must be 0..255"}, as_json=bool(getattr(args, "as_json", False)))
            return 1

        host = (getattr(args, "host", "") or "").strip()
        ip_alias = (getattr(args, "ip", "") or "").strip()
        target_host = host or ip_alias or None

        code, ok, err, payload = configure_device(
            admin_creds_dir=admin_dir,
            listener_creds_dir=listener_dir,
            recorder_auth_creds_dir=recorder_auth_dir,
            identity=args.identity,
            wifi_ssid=args.wifi_ssid,
            wifi_password=args.wifi_password,
            wifi_mode=(getattr(args, "wifi_mode", "sta") or "sta"),
            wifi_ap_ssid=(getattr(args, "wifi_ap_ssid", "") or ""),
            wifi_ap_password=(getattr(args, "wifi_ap_password", "") or ""),
            authorized_listener_ips=list(args.authorized_listener_ip or []),
            time_servers=list(args.time_server or []),
            no_time=bool(args.no_time),
            port=args.port,
            ip=target_host,
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
            audio_preamp_gain=(int(audio_preamp_gain) if audio_preamp_gain is not None else None),
            audio_adc_gain=(int(audio_adc_gain) if audio_adc_gain is not None else None),
            tls_bootstrap=bool(getattr(args, "tls_bootstrap", True)),
            tls_valid_days=int(getattr(args, "tls_valid_days", 180)),
        )
        out_payload = (payload if isinstance(payload, dict) else {})

        emit_envelope(
            command="configure-device",
            ok=ok,
            error=err,
            detail=out_payload.get("detail") if isinstance(out_payload, dict) else None,
            payload=out_payload,
            as_json=bool(getattr(args, "as_json", False)),
        )
        return int(code)
    except Exception as e:
        emit_envelope(
            command="configure-device",
            ok=False,
            error="CONFIGURE_DEVICE_ERROR",
            detail=exception_detail(
                where="cmd_configure_device.run",
                exc=e,
                context={
                    "admin_creds_dir": str(getattr(args, "admin_creds_dir", "") or ""),
                    "listener_creds_dir": str(getattr(args, "listener_creds_dir", "") or ""),
                    "host": str(getattr(args, "host", "") or ""),
                    "ip": str(getattr(args, "ip", "") or ""),
                    "port": str(getattr(args, "port", "") or ""),
                },
            ),
            as_json=bool(getattr(args, "as_json", False)),
        )
        return 2
