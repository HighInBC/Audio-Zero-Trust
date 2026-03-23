from __future__ import annotations

import argparse
import time
from pathlib import Path
from tools.azt_cli.output import emit_envelope
from tools.azt_client.http import http_json
from tools.azt_sdk.services.url_service import base_url
from tools.azt_sdk.services.provisioning_service import configure_device
from tools.azt_sdk.services.tls_service import tls_bootstrap


def _wait_http_ready(http_base: str, *, max_wait_s: int = 30) -> tuple[bool, str | None]:
    end_at = time.time() + max(1, int(max_wait_s))
    last_err = None
    while time.time() < end_at:
        try:
            probe = http_json("GET", f"{http_base}/api/v0/config/state", timeout=3)
            if isinstance(probe, dict) and probe.get("ok"):
                return True, None
        except Exception as e:
            last_err = str(e)
        time.sleep(1.0)
    return False, last_err


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
        out_payload = (payload if isinstance(payload, dict) else {})

        # Optional automatic TLS bootstrap: only run when device is reachable and TLS is not already configured.
        if ok and bool(getattr(args, "tls_bootstrap", True)):
            device_ip = str(out_payload.get("ip") or "").strip()
            if device_ip:
                tls_state = None
                tls_state_error = None
                http_base = base_url(host=device_ip, port=8080, scheme="http")

                # Device often reports IP before HTTP API is fully ready; wait for readiness.
                ready, ready_err = _wait_http_ready(http_base, max_wait_s=45)
                if not ready:
                    tls_state_error = ready_err or "HTTP API not ready after wait"

                try:
                    tls_state = http_json("GET", f"{http_base}/api/v0/tls/state", timeout=15)
                except Exception as e:
                    tls_state_error = str(e)

                tls_already_configured = bool(
                    isinstance(tls_state, dict)
                    and tls_state.get("ok")
                    and tls_state.get("tls_server_cert_configured")
                    and tls_state.get("tls_server_key_configured")
                    and tls_state.get("tls_ca_cert_configured")
                )

                if tls_already_configured:
                    out_payload["tls_bootstrap"] = {
                        "attempted": False,
                        "skipped": True,
                        "reason": "already_configured",
                        "tls_state": tls_state,
                    }
                else:
                    admin_key_path = Path(admin_dir)
                    if admin_key_path.is_dir():
                        keyp = admin_key_path / "private_key.pem"
                        if not keyp.exists():
                            keyp = admin_key_path / "admin_private_key.pem"
                    else:
                        keyp = admin_key_path

                    san_hosts = [device_ip]
                    mdns_name = str(getattr(args, "mdns_hostname", "") or "").strip()
                    if mdns_name:
                        san_hosts.append(mdns_name)
                        if not mdns_name.endswith(".local"):
                            san_hosts.append(f"{mdns_name}.local")

                    tls_result = None
                    tls_bootstrap_error = None
                    for _ in range(8):
                        # Re-check readiness each attempt to handle AP/STA transitions after config apply.
                        _wait_http_ready(http_base, max_wait_s=6)
                        try:
                            tls_result = tls_bootstrap(
                                host=device_ip,
                                admin_key_path=str(keyp),
                                http_port=8080,
                                https_port=8443,
                                timeout=15,
                                valid_days=int(getattr(args, "tls_valid_days", 180)),
                                reboot_on_https_failure=True,
                                reboot_wait_seconds=int(getattr(args, "tls_reboot_wait_seconds", 8)),
                                san_hosts=san_hosts,
                                verify_host=(f"{mdns_name}.local" if mdns_name else device_ip),
                            )
                            tls_bootstrap_error = None
                            break
                        except Exception as e:
                            tls_bootstrap_error = str(e)
                            time.sleep(2.0)

                    if tls_result is None:
                        err_text = str(tls_bootstrap_error or "TLS bootstrap failed")
                        if "Connection refused" in err_text or "Errno 111" in err_text:
                            verify_host_value = (f"{mdns_name}.local" if mdns_name else device_ip)
                            https_base = base_url(host=verify_host_value, port=8443, scheme="https")
                            http_targets = [
                                f"{http_base}/api/v0/config/state",
                                f"{http_base}/api/v0/tls/state",
                                f"{http_base}/api/v0/tls/csr",
                                f"{http_base}/api/v0/tls/cert",
                            ]
                            detail_lines = [
                                "TLS bootstrap connection refused.",
                                f"device_ip={device_ip}",
                                f"verify_host={verify_host_value}",
                                "http_targets=" + ", ".join(http_targets),
                                f"https_verify_target={https_base}/api/v0/config/state",
                            ]
                            if tls_state_error:
                                detail_lines.append(f"precheck_error={tls_state_error}")
                            detail_lines.append(f"last_error={err_text}")
                            raise RuntimeError(" | ".join(detail_lines))
                        raise RuntimeError(err_text)

                    out_payload["tls_bootstrap"] = {
                        "attempted": True,
                        **tls_result,
                        "precheck_tls_state": tls_state,
                        "precheck_error": tls_state_error,
                    }

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
            detail=str(e),
            as_json=bool(getattr(args, "as_json", False)),
        )
        return 2
