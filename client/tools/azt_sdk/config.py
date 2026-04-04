from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        import yaml  # type: ignore
    except Exception as exc:  # pragma: no cover
        raise RuntimeError("CONFIG_YAML_UNAVAILABLE") from exc

    data = yaml.safe_load(path.read_text())
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise RuntimeError("CONFIG_INVALID_ROOT")
    return data


def load_defaults(config_path: str | Path) -> dict[str, Any]:
    p = Path(config_path)
    if not p.exists():
        return {}
    doc = _load_yaml(p)
    defaults = doc.get("defaults")
    if defaults is None:
        return {}
    if not isinstance(defaults, dict):
        raise RuntimeError("CONFIG_DEFAULTS_NOT_OBJECT")
    return defaults


def _has_attr(args: argparse.Namespace, name: str) -> bool:
    return hasattr(args, name)


def _is_unset(args: argparse.Namespace, arg_name: str) -> bool:
    if not _has_attr(args, arg_name):
        return False
    v = getattr(args, arg_name)
    if v is None:
        return True
    if isinstance(v, str):
        return v.strip() == ""
    if isinstance(v, (list, tuple, dict, set)):
        return len(v) == 0
    if isinstance(v, bool):
        return v is False
    return False


def _set_if_unset(args: argparse.Namespace, arg_name: str, value: Any) -> None:
    if _is_unset(args, arg_name):
        setattr(args, arg_name, value)


def _set_if_matches(args: argparse.Namespace, arg_name: str, value: Any, defaults: set[Any]) -> None:
    if not _has_attr(args, arg_name):
        return
    cur = getattr(args, arg_name)
    if cur in defaults:
        setattr(args, arg_name, value)


def _expand_template(template: str, args: argparse.Namespace) -> str:
    identity = str(getattr(args, "identity", "") or "").strip()
    device_label = str(getattr(args, "device_label", "") or "").strip()
    return template.replace("{identity}", identity or device_label)


def apply_defaults_to_args(args: argparse.Namespace, conf_defaults: dict[str, Any]) -> None:
    command = str(getattr(args, "command", "") or "")

    if "json_output" in conf_defaults:
        _set_if_unset(args, "as_json", bool(conf_defaults["json_output"]))

    # Common HTTP-ish defaults
    if command in {
        "apply-config",
        "config-patch",
        "state-get",
        "attestation-get",
        "certificate-get",
        "certificate-issue",
        "certificate-post",
        "key-match-check",
        "reboot-device",
        "signing-key-check",
        "attestation-verify",
        "stream-redirect-check",
        "stream-read",
        "tls-cert-issue",
        "tls-status",
        "tls-bootstrap",
        "mdns-fqdn-get",
        "ota-bundle-post",
        "certificate-revoke",
    }:
        if "host" in conf_defaults:
            _set_if_unset(args, "host", str(conf_defaults["host"]))
        if "http_port" in conf_defaults:
            _set_if_matches(args, "port", int(conf_defaults["http_port"]), {8080})
        if "timeout_seconds" in conf_defaults:
            _set_if_matches(args, "timeout", int(conf_defaults["timeout_seconds"]), {10, 15, 45})

    if command == "tls-bootstrap" and "https_port" in conf_defaults:
        _set_if_unset(args, "https_port", int(conf_defaults["https_port"]))

    if command == "stream-redirect-check" and "stream_port" in conf_defaults:
        _set_if_unset(args, "stream_port", int(conf_defaults["stream_port"]))

    if command in {"apply-config", "config-patch", "certificate-issue", "certificate-revoke", "key-match-check", "reboot-device", "tls-cert-issue", "tls-bootstrap", "ota-bundle-create"}:
        if "admin_key_path" in conf_defaults:
            _set_if_unset(args, "key_path", str(conf_defaults["admin_key_path"]))
        elif "admin_creds_dir" in conf_defaults and _is_unset(args, "key_path"):
            _set_if_unset(args, "key_path", str(Path(str(conf_defaults["admin_creds_dir"])) / "private_key.pem"))

    if command in {"erase-device", "flash-device", "configure-device", "ip-detect", "provision-unit"}:
        if "serial_port" in conf_defaults:
            _set_if_matches(args, "port", str(conf_defaults["serial_port"]), {"", "/dev/ttyUSB0"})

    if command in {"erase-device", "flash-device", "ota-bundle-create"} and "target" in conf_defaults:
        _set_if_unset(args, "target", str(conf_defaults["target"]))

    if command == "configure-device":
        for ck, an in [
            ("admin_creds_dir", "admin_creds_dir"),
            ("recorder_creds_dir", "recorder_creds_dir"),
            ("wifi_ssid", "wifi_ssid"),
            ("wifi_password", "wifi_password"),
            ("host", "host"),
            ("audio_preamp_gain", "audio_preamp_gain"),
            ("audio_adc_gain", "audio_adc_gain"),
        ]:
            if ck in conf_defaults:
                _set_if_unset(args, an, conf_defaults[ck])

        if "tls_valid_days" in conf_defaults:
            _set_if_matches(args, "tls_valid_days", int(conf_defaults["tls_valid_days"]), {180})
        if "tls_reboot_wait_seconds" in conf_defaults:
            _set_if_matches(args, "tls_reboot_wait_seconds", int(conf_defaults["tls_reboot_wait_seconds"]), {8})

        if "mdns_enabled" in conf_defaults:
            cfg_enabled = bool(conf_defaults["mdns_enabled"])
            if cfg_enabled:
                _set_if_unset(args, "mdns_enabled", True)
            else:
                # only set to disabled if parser offers the flag (configure-device only has mdns_enabled)
                pass

        if "mdns_hostname_template" in conf_defaults and _is_unset(args, "mdns_hostname"):
            t = str(conf_defaults["mdns_hostname_template"])
            expanded = _expand_template(t, args).strip().lower()
            if expanded:
                setattr(args, "mdns_hostname", expanded)

    if command == "config-patch":
        if "mdns_enabled" in conf_defaults:
            cfg_enabled = bool(conf_defaults["mdns_enabled"])
            if cfg_enabled:
                _set_if_unset(args, "mdns_enabled", True)
            else:
                _set_if_unset(args, "mdns_disabled", True)

        if "mdns_hostname_template" in conf_defaults and _is_unset(args, "mdns_hostname"):
            t = str(conf_defaults["mdns_hostname_template"])
            expanded = _expand_template(t, args).strip().lower()
            if expanded:
                setattr(args, "mdns_hostname", expanded)

        if "authorized_listener_ips" in conf_defaults and _is_unset(args, "authorized_listener_ips"):
            v = conf_defaults["authorized_listener_ips"]
            if isinstance(v, list):
                setattr(args, "authorized_listener_ips", [str(x) for x in v])

        if "time_servers" in conf_defaults and _is_unset(args, "time_servers"):
            v = conf_defaults["time_servers"]
            if isinstance(v, list):
                setattr(args, "time_servers", [str(x) for x in v])

    if command == "ota-bundle-create":
        for ck, an in [
            ("ota_channel", "channel"),
            ("ota_upgrade_path", "upgrade_path"),
            ("host", "host"),
            ("http_port", "port"),
            ("timeout_seconds", "timeout"),
        ]:
            if ck in conf_defaults:
                _set_if_unset(args, an, conf_defaults[ck])

        if "ota_version_code_mode" in conf_defaults and _is_unset(args, "version_code"):
            mode = str(conf_defaults["ota_version_code_mode"]).strip().lower()
            if mode in {"timestamp", "explicit"}:
                if mode == "timestamp":
                    setattr(args, "version_code", "timestamp")

        if "ota_rollback_floor_mode" in conf_defaults and _is_unset(args, "rollback_floor_code"):
            mode = str(conf_defaults["ota_rollback_floor_mode"]).strip().lower()
            if mode == "same":
                setattr(args, "rollback_floor_code", "same")


def apply_runtime_defaults(args: argparse.Namespace, repo_root: Path) -> None:
    if bool(getattr(args, "no_config", False)):
        return

    conf_path_raw = str(getattr(args, "config", "azt.conf") or "azt.conf")
    conf_path = Path(conf_path_raw)
    if not conf_path.is_absolute():
        conf_path = repo_root / conf_path

    conf_defaults = load_defaults(conf_path)
    apply_defaults_to_args(args, conf_defaults)
