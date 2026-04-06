#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
from pathlib import Path

CLIENT_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(CLIENT_ROOT) not in sys.path:
    sys.path.insert(0, str(CLIENT_ROOT))

from tools.azt_cli import argparsing as cli_argparsing
from tools.azt_cli import handler_map as cli_handler_map
from tools.azt_cli.output import emit_envelope, exception_detail
from tools.azt_sdk import config as sdk_config
from tools.azt_sdk.services import operations_service as ops
from tools.azt_client.crypto import ed25519_public_b64_from_private_key, ed25519_fp_hex_from_private_key


_MDNS_HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _is_valid_mdns_hostname(host: str) -> bool:
    h = (host or "").strip().lower()
    if not h:
        return True
    return bool(_MDNS_HOST_RE.fullmatch(h))


def _prompt_default(label: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    val = input(f"{label}{suffix}: ").strip()
    return val or default


def _prompt_bool(label: str, default: bool = False) -> bool:
    d = "Y/n" if default else "y/N"
    val = input(f"{label} [{d}]: ").strip().lower()
    if not val:
        return default
    return val in {"y", "yes", "1", "true", "on"}


def cmd_apply_config(args: argparse.Namespace) -> int:
    if bool(getattr(args, "interactive", False)):
        args.host = _prompt_default("Host", args.host or "")
        args.in_path = _prompt_default("Unsigned config path", args.in_path or "")
        args.key_path = _prompt_default("Admin private key PEM", args.key_path or "")

    if not (args.host and args.in_path and args.key_path):
        emit_envelope(command="apply-config", ok=False, error="APPLY_CONFIG_ARGS", payload={"detail": "host, --in and --key are required (or use --interactive)"}, as_json=bool(getattr(args, "as_json", False)))
        return 1

    key_path = Path(str(args.key_path))
    if not key_path.exists() or key_path.is_dir():
        emit_envelope(command="apply-config", ok=False, error="APPLY_CONFIG_ARGS", payload={"detail": f"--key must point to a private key PEM file: {args.key_path}"}, as_json=bool(getattr(args, "as_json", False)))
        return 1

    ok, payload = ops.apply_config(
        in_path=args.in_path,
        key_path=args.key_path,
        host=args.host,
        port=int(args.port),
        timeout=int(args.timeout),
        fingerprint=args.fingerprint,
    )
    fail_code = "APPLY_CONFIG_FAILED"
    if not ok and isinstance(payload, dict) and isinstance(payload.get("error"), str) and payload.get("error"):
        fail_code = str(payload.get("error"))
    emit_envelope(command="apply-config", ok=ok, error=None if ok else fail_code, payload=payload, as_json=bool(getattr(args, "as_json", False)))
    return 0 if ok else 1


def cmd_config_patch(args: argparse.Namespace) -> int:
    if bool(getattr(args, "interactive", False)):
        args.host = _prompt_default("Host", args.host or "")
        args.key_path = _prompt_default("Admin private key PEM", args.key_path or "")
        if not (getattr(args, "patch_path", "") or "").strip():
            use_file = _prompt_bool("Use patch JSON file", False)
            if use_file:
                args.patch_path = _prompt_default("Patch JSON path", "")
        if not bool(getattr(args, "mdns_enabled", False)) and not bool(getattr(args, "mdns_disabled", False)):
            mdns_choice = _prompt_default("mDNS mode (enable/disable/skip)", "skip").lower()
            if mdns_choice in {"enable", "on", "true", "1"}:
                args.mdns_enabled = True
            elif mdns_choice in {"disable", "off", "false", "0"}:
                args.mdns_disabled = True
        if not (getattr(args, "mdns_hostname", "") or "").strip() and bool(getattr(args, "mdns_enabled", False)):
            args.mdns_hostname = _prompt_default("mDNS hostname", "")

    if not (args.host and args.key_path):
        emit_envelope(command="config-patch", ok=False, error="CONFIG_PATCH_ARGS", payload={"detail": "host and --key are required (or use --interactive)"}, as_json=bool(getattr(args, "as_json", False)))
        return 1

    patch_obj = None
    patch_path = (getattr(args, "patch_path", "") or "").strip()
    if patch_path:
        patch_obj = json.loads(Path(patch_path).read_text())
        if not isinstance(patch_obj, dict):
            emit_envelope(command="config-patch", ok=False, error="CONFIG_PATCH_ARGS", payload={"detail": "--patch must contain a JSON object"}, as_json=bool(getattr(args, "as_json", False)))
            return 1

    def _ensure_obj(parent: dict, key: str) -> dict:
        cur = parent.get(key)
        if not isinstance(cur, dict):
            cur = {}
            parent[key] = cur
        return cur

    if patch_obj is None:
        patch_obj = {}

    mdns_hostname = (getattr(args, "mdns_hostname", "") or "").strip().lower()
    mdns_enabled = bool(getattr(args, "mdns_enabled", False))
    mdns_disabled = bool(getattr(args, "mdns_disabled", False))

    if mdns_enabled and mdns_disabled:
        emit_envelope(command="config-patch", ok=False, error="CONFIG_PATCH_ARGS", payload={"detail": "cannot set both --mdns-enabled and --mdns-disabled"}, as_json=bool(getattr(args, "as_json", False)))
        return 1
    if mdns_enabled or mdns_disabled or mdns_hostname:
        if not _is_valid_mdns_hostname(mdns_hostname):
            emit_envelope(command="config-patch", ok=False, error="CONFIG_PATCH_ARGS", payload={"detail": f"invalid --mdns-hostname '{mdns_hostname}' (must match ^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$)"}, as_json=bool(getattr(args, "as_json", False)))
            return 1
        pm = _ensure_obj(patch_obj, "mdns")
        if mdns_enabled:
            pm["enabled"] = True
        if mdns_disabled:
            pm["enabled"] = False
        if mdns_hostname:
            pm["hostname"] = mdns_hostname

    device_label = (getattr(args, "device_label", "") or "").strip()
    if device_label:
        patch_obj["device_label"] = device_label

    wifi_ssid = (getattr(args, "wifi_ssid", "") or "").strip()
    wifi_pass = (getattr(args, "wifi_pass", "") or "").strip()
    wifi_mode = (getattr(args, "wifi_mode", "") or "").strip().lower()
    wifi_ap_ssid = (getattr(args, "wifi_ap_ssid", "") or "").strip()
    wifi_ap_password = (getattr(args, "wifi_ap_password", "") or "").strip()
    if wifi_mode not in {"", "sta", "ap"}:
        emit_envelope(command="config-patch", ok=False, error="CONFIG_PATCH_ARGS", payload={"detail": "--wifi-mode must be sta or ap"}, as_json=bool(getattr(args, "as_json", False)))
        return 1
    if wifi_ssid or wifi_pass or wifi_mode or wifi_ap_ssid or wifi_ap_password:
        pw = _ensure_obj(patch_obj, "wifi")
        if wifi_mode:
            pw["mode"] = wifi_mode
        if wifi_ssid:
            pw["ssid"] = wifi_ssid
        if wifi_pass:
            pw["pass"] = wifi_pass
        if wifi_ap_ssid:
            pw["ap_ssid"] = wifi_ap_ssid
        if wifi_ap_password:
            pw["ap_password"] = wifi_ap_password

    auth_ips = [str(x).strip() for x in (getattr(args, "authorized_listener_ips", []) or []) if str(x).strip()]
    if auth_ips:
        patch_obj["authorized_listener_ips"] = auth_ips

    time_servers = [str(x).strip() for x in (getattr(args, "time_servers", []) or []) if str(x).strip()]
    if time_servers:
        patch_obj["time"] = time_servers

    listener_key_pem_path = (getattr(args, "listener_key_pem", "") or "").strip()
    if listener_key_pem_path:
        patch_obj["listener_key"] = {"public_key_pem": Path(listener_key_pem_path).read_text()}

    recorder_auth_key_path = (getattr(args, "recorder_auth_key_path", "") or "").strip()
    if recorder_auth_key_path:
        kp = Path(recorder_auth_key_path)
        pub_b64 = ""
        fp_hex = ""

        if kp.is_dir():
            pub_txt = kp / "public_key_b64.txt"
            if pub_txt.exists():
                pub_b64 = pub_txt.read_text(encoding="utf-8").strip()
                try:
                    pub_raw = base64.b64decode(pub_b64, validate=True)
                    fp_hex = hashlib.sha256(pub_raw).hexdigest()
                except Exception:
                    emit_envelope(command="config-patch", ok=False, error="CONFIG_PATCH_ARGS", payload={"detail": f"invalid recorder auth public key file: {pub_txt}"}, as_json=bool(getattr(args, "as_json", False)))
                    return 1
            else:
                cand = kp / "private_key.pem"
                if not cand.exists():
                    cand = kp / "admin_private_key.pem"
                kp = cand

        if not pub_b64:
            pub_b64 = ed25519_public_b64_from_private_key(kp)
            fp_hex = ed25519_fp_hex_from_private_key(kp)

        patch_obj["recorder_auth_key"] = {
            "alg": "ed25519",
            "public_key_b64": pub_b64,
            "fingerprint_alg": "sha256-raw-ed25519-pub",
            "fingerprint_hex": fp_hex,
        }

    audio_preamp = getattr(args, "audio_preamp_gain", None)
    audio_adc = getattr(args, "audio_adc_gain", None)
    if audio_preamp is not None or audio_adc is not None:
        pa = patch_obj.get("audio") if isinstance(patch_obj.get("audio"), dict) else {}
        if audio_preamp is not None:
            if int(audio_preamp) < 1 or int(audio_preamp) > 8:
                emit_envelope(command="config-patch", ok=False, error="CONFIG_PATCH_ARGS", payload={"detail": "--audio-preamp-gain must be 1..8"}, as_json=bool(getattr(args, "as_json", False)))
                return 1
            pa["preamp_gain"] = int(audio_preamp)
        if audio_adc is not None:
            if int(audio_adc) < 0 or int(audio_adc) > 255:
                emit_envelope(command="config-patch", ok=False, error="CONFIG_PATCH_ARGS", payload={"detail": "--audio-adc-gain must be 0..255"}, as_json=bool(getattr(args, "as_json", False)))
                return 1
            pa["adc_gain"] = int(audio_adc)
        patch_obj["audio"] = pa

    if not patch_obj:
        emit_envelope(command="config-patch", ok=False, error="CONFIG_PATCH_ARGS", payload={"detail": "provide --patch or patch flags (device/wifi/authorized listeners/time/mdns/listener-key/recorder-auth-key)"}, as_json=bool(getattr(args, "as_json", False)))
        return 1

    if_version = int(args.if_version)
    if if_version < 0:
        try:
            st = ops.get_json(f"http://{args.host}:{int(args.port)}/api/v0/config/state", timeout=int(args.timeout))
        except Exception as e:
            emit_envelope(
                command="config-patch",
                ok=False,
                error="CONFIG_PATCH_STATE_FETCH_FAILED",
                payload={"detail": exception_detail("config_patch.state_get", e, context={"host": args.host, "port": int(args.port)})},
                as_json=bool(getattr(args, "as_json", False)),
            )
            return 1
        if not st.get("ok"):
            emit_envelope(command="config-patch", ok=False, error="CONFIG_PATCH_STATE_FETCH_FAILED", payload={"state": st}, as_json=bool(getattr(args, "as_json", False)))
            return 1
        cv = st.get("config_revision") if isinstance(st, dict) else None
        if_version = int(cv) if cv is not None else -1
        if if_version < 0:
            payload = st.get("payload") if isinstance(st, dict) else None
            state_obj = payload.get("state") if isinstance(payload, dict) else None
            if isinstance(state_obj, dict):
                cv2 = state_obj.get("config_revision")
                if_version = int(cv2) if cv2 is not None else -1
        if if_version < 0:
            emit_envelope(command="config-patch", ok=False, error="CONFIG_PATCH_STATE_VERSION_MISSING", payload={"state": st}, as_json=bool(getattr(args, "as_json", False)))
            return 1

    ok, payload = ops.config_patch(
        patch_path=args.patch_path,
        patch_obj=patch_obj,
        if_version=if_version,
        key_path=args.key_path,
        host=args.host,
        port=int(args.port),
        timeout=int(args.timeout),
        fingerprint=args.fingerprint,
    )
    fail_code = "CONFIG_PATCH_FAILED"
    if not ok and isinstance(payload, dict) and isinstance(payload.get("error"), str) and payload.get("error"):
        fail_code = str(payload.get("error"))
    emit_envelope(command="config-patch", ok=ok, error=None if ok else fail_code, payload=payload, as_json=bool(getattr(args, "as_json", False)))
    return 0 if ok else 1

def cmd_certify_issue(args: argparse.Namespace) -> int:
    ok, err, payload = ops.certify_issue(
        host=args.host,
        port=int(args.port),
        timeout=int(args.timeout),
        key_path=args.key_path,
        serial=args.serial,
        issue_id=args.issue_id,
        title=args.title,
        expected=args.expected,
        actual=args.actual,
        repro=args.repro,
        evidence=args.evidence,
        meta=args.meta,
        nonce=args.nonce,
        cert_serial=args.cert_serial,
        no_upload_device_cert=bool(args.no_upload_device_cert),
        out_path=args.out_path,
    )
    emit_envelope(command="certify-issue", ok=ok, error=err, payload=payload, as_json=bool(getattr(args, "as_json", False)))
    return 0 if ok else 1
def cmd_verify_certification(args: argparse.Namespace) -> int:
    ok, payload = ops.verify_certification(in_path=args.in_path, key_path=args.key_path)
    emit_envelope(command="verify-certification", ok=ok, error=None if ok else "VERIFY_CERTIFICATION_FAILED", payload=payload, as_json=bool(getattr(args, "as_json", False)))
    return 0 if ok else 1
def _resolve_firmware_bin(path_str: str, env: str) -> Path:
    firmware_path = Path(path_str)
    if firmware_path.exists():
        return firmware_path

    cmd = [
        str(Path.home() / ".platformio" / "penv" / "bin" / "pio"),
        "run",
        "-d",
        str(REPO_ROOT / "firmware" / "audio_zero_trust"),
        "-e",
        env,
    ]
    p = subprocess.run(cmd, text=True, capture_output=True)
    if p.returncode != 0:
        raise SystemExit(f"ERR_OTA_BUILD: {p.stdout}\n{p.stderr}")

    if not firmware_path.exists():
        raise SystemExit(f"ERR_OTA_FIRMWARE_NOT_FOUND: {firmware_path}")
    return firmware_path


def _resolve_ota_env(target: str) -> str:
    t = (target or "").strip().lower()
    if t == "atom-echo":
        return "atom-echo"
    if t == "atom-echos3r":
        return "atom-echos3r"
    raise RuntimeError("ERR_OTA_TARGET_REQUIRED")


def cmd_ota_bundle_create(args: argparse.Namespace) -> int:
    if bool(getattr(args, "interactive", False)):
        args.firmware_key_path = _prompt_default("Firmware signer private key PEM", args.firmware_key_path or "")
        if not (getattr(args, "target", "") or "").strip():
            args.target = _prompt_default("Target (atom-echo|atom-echos3r)", "")
        args.version_code = _prompt_default("Version code", str(args.version_code or "timestamp"))
        if not (args.version or "").strip():
            args.version = _prompt_default("Version label (blank uses version-code)", "")
        if not (args.out_path or "").strip():
            args.out_path = _prompt_default("Output bundle path", "ota.bin")
        if not bool(getattr(args, "post_upgrade", False)):
            args.post_upgrade = _prompt_bool("POST to device after create", False)
        if bool(getattr(args, "post_upgrade", False)) and not (args.host or "").strip():
            args.host = _prompt_default("Host", args.host or "")
        if bool(getattr(args, "post_upgrade", False)) and not (args.admin_key_path or "").strip():
            args.admin_key_path = _prompt_default("Admin private key PEM", args.admin_key_path or "")

    if bool(getattr(args, "post_upgrade", False)) and not (args.out_path or "").strip():
        import time
        auto_out = Path("/tmp") / f"azt-ota-{int(time.time())}.otabundle"
        args.out_path = str(auto_out)

    if not (args.firmware_key_path and args.target and args.version_code and args.out_path):
        emit_envelope(command="ota-bundle-create", ok=False, error="OTA_BUNDLE_CREATE_ARGS", payload={"detail": "--firmware-key, --target, and --version-code are required; --out is required unless --post is used (or use --interactive)"}, as_json=bool(getattr(args, "as_json", False)))
        return 1

    vc_raw = (str(args.version_code).strip().lower())
    if vc_raw == "timestamp":
        from datetime import datetime, timezone
        version_code = int(datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S"))
    else:
        version_code = int(vc_raw)

    version_label = (args.version or "").strip() or str(version_code)

    rf_raw = (getattr(args, "rollback_floor_code", "same") or "same").strip().lower()
    rollback_floor_code = None
    if rf_raw == "same" or rf_raw == "":
        rollback_floor_code = version_code
    else:
        rollback_floor_code = int(rf_raw)

    target = str(getattr(args, "target", "") or "").strip().lower()
    env = _resolve_ota_env(target)

    ok, payload = ops.ota_bundle_create(
        repo_root=REPO_ROOT,
        key_path=args.firmware_key_path,
        out_path=args.out_path,
        firmware_path=args.firmware_path,
        env=env,
        target=target,
        channel=args.channel,
        version=version_label,
        version_code=version_code,
        rollback_floor_code=rollback_floor_code,
    )
    if not ok:
        emit_envelope(command="ota-bundle-create", ok=False, error="OTA_BUNDLE_CREATE_FAILED", payload=payload, as_json=bool(getattr(args, "as_json", False)))
        return 1

    post_response = None
    if bool(getattr(args, "post_upgrade", False)):
        if not getattr(args, "host", ""):
            emit_envelope(command="ota-bundle-create", ok=False, error="ERR_OTA_POST_HOST_REQUIRED", payload=payload, as_json=bool(getattr(args, "as_json", False)))
            return 1
        if not (getattr(args, "admin_key_path", "") or "").strip():
            emit_envelope(command="ota-bundle-create", ok=False, error="ERR_OTA_POST_ADMIN_KEY_REQUIRED", payload=payload, as_json=bool(getattr(args, "as_json", False)))
            return 1
        ok_post, err_post, post_payload = ops.ota_bundle_post(
            in_path=args.out_path,
            host=args.host,
            port=int(args.port),
            upgrade_path=args.upgrade_path,
            timeout=int(args.timeout),
            key_path=str(getattr(args, "admin_key_path", "") or ""),
        )
        post_response = post_payload
        payload = {**payload, "post_response": post_response}
        if not ok_post:
            emit_envelope(command="ota-bundle-create", ok=False, error=err_post or "ERR_OTA_BUNDLE_POST_FAILED", payload=payload, as_json=bool(getattr(args, "as_json", False)))
            return 1

    emit_envelope(command="ota-bundle-create", ok=True, error=None, payload=payload, as_json=bool(getattr(args, "as_json", False)))
    return 0
def cmd_ota_bundle_post(args: argparse.Namespace) -> int:
    if bool(getattr(args, "interactive", False)):
        args.host = _prompt_default("Host", args.host or "")
        args.in_path = _prompt_default("Input bundle path", args.in_path or "")
        args.admin_key_path = _prompt_default("Admin private key PEM", args.admin_key_path or "")

    if not (args.host and args.in_path and args.admin_key_path):
        emit_envelope(command="ota-bundle-post", ok=False, error="OTA_BUNDLE_POST_ARGS", payload={"detail": "--host, --in, and --admin-key are required (or use --interactive)"}, as_json=bool(getattr(args, "as_json", False)))
        return 1

    ok, err, payload = ops.ota_bundle_post(
        in_path=args.in_path,
        host=args.host,
        port=int(args.port),
        upgrade_path=args.upgrade_path,
        timeout=int(args.timeout),
        key_path=str(getattr(args, "admin_key_path", "") or ""),
        wake_window_seconds=int(getattr(args, "wake_window_seconds", 30) or 30),
        wake_allow_self=bool(getattr(args, "wake_allow_self", True)),
        wake_allowed_ip=str(getattr(args, "wake_allowed_ip", "") or ""),
    )
    emit_envelope(command="ota-bundle-post", ok=ok, error=err, payload=payload, as_json=bool(getattr(args, "as_json", False)))
    return 0 if ok else 1


def cmd_separate_headers(args: argparse.Namespace) -> int:
    in_path = str(args.in_path)
    out_headers = (getattr(args, "out_headers", "") or "").strip() or (in_path + ".request")
    ok, payload = ops.separate_headers(in_path=in_path, out_headers=out_headers)
    emit_envelope(command="detached-headers-export", ok=ok, error=None if ok else "SEPARATE_HEADERS_FAILED", payload=payload, as_json=bool(getattr(args, "as_json", False)))
    return 0 if ok else 1


def cmd_decode_next_header(args: argparse.Namespace) -> int:
    in_path = str(args.in_path)
    in_is_request = in_path.endswith(".request")
    out_path = (getattr(args, "out_path", "") or "").strip()
    if not out_path and not in_is_request:
        out_path = in_path + ".decoded"
    out_key = (getattr(args, "out_decoded_next_header_path", "") or "").strip() or ((in_path[:-8] + ".key") if in_is_request else (in_path + ".key"))
    ok, payload = ops.decode_next_header(
        in_path=in_path,
        key_path=args.key_path,
        out_path=out_path,
        out_decoded_next_header_path=out_key,
    )
    emit_envelope(command="detached-headers-decode", ok=ok, error=None if ok else "DECODE_NEXT_HEADER_FAILED", payload=payload, as_json=bool(getattr(args, "as_json", False)))
    return 0 if ok else 1


def cmd_combine_headers(args: argparse.Namespace) -> int:
    in_path = str(args.in_path)
    headers_path = (getattr(args, "headers_path", "") or "").strip() or (in_path + ".request")
    key_file = (getattr(args, "decoded_next_header_path", "") or "").strip() or (in_path + ".key")
    out_path = (getattr(args, "out_path", "") or "").strip() or (in_path + ".decoded")
    ok, payload = ops.combine_headers(
        in_path=in_path,
        headers_path=headers_path,
        decoded_next_header_path=key_file,
        out_path=out_path,
    )
    emit_envelope(command="detached-headers-combine", ok=ok, error=None if ok else "COMBINE_HEADERS_FAILED", payload=payload, as_json=bool(getattr(args, "as_json", False)))
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    handlers = cli_handler_map.build_handler_namespace(
        cmd_apply_config=cmd_apply_config,
        cmd_config_patch=cmd_config_patch,
        cmd_ota_bundle_create=cmd_ota_bundle_create,
        cmd_ota_bundle_post=cmd_ota_bundle_post,
        cmd_certify_issue=cmd_certify_issue,
        cmd_verify_certification=cmd_verify_certification,
        cmd_separate_headers=cmd_separate_headers,
        cmd_decode_next_header=cmd_decode_next_header,
        cmd_combine_headers=cmd_combine_headers,
    )
    return cli_argparsing.build_parser(handlers)


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        sdk_config.apply_runtime_defaults(args, repo_root=REPO_ROOT)
        return int(args.func(args))
    except Exception as e:
        if bool(getattr(args, "as_json", False)):
            emit_envelope(
                command=str(getattr(args, "command", "unknown")),
                ok=False,
                error="UNHANDLED_EXCEPTION",
                detail=exception_detail("azt_tool.main", e, context={"command": str(getattr(args, "command", "unknown"))}),
                as_json=True,
            )
            return 2
        raise


if __name__ == "__main__":
    raise SystemExit(main())
