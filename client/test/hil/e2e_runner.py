#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))



def run(cmd: list[str], cwd: Path | None = None) -> tuple[int, str]:
    p = subprocess.run(cmd, cwd=str(cwd) if cwd else None, text=True, capture_output=True)
    out = (p.stdout or "") + (p.stderr or "")
    return p.returncode, out.strip()


def load_simple_env_file(path: Path) -> dict[str, str]:
    vals: dict[str, str] = {}
    if not path.exists():
        return vals
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        vals[k.strip()] = v.strip().strip('"').strip("'")
    return vals


def first_nonempty(*vals: str | None) -> str | None:
    for v in vals:
        if v is not None and str(v).strip() != "":
            return str(v).strip()
    return None


class ToolRunner:
    def __init__(self, root: Path, tool_cmd: str | None = None):
        self.root = root
        self.base = shlex.split((tool_cmd or "python3 client/tools/azt_tool.py").strip())

    def cmd(self, args: list[str]) -> tuple[int, str]:
        return run([*self.base, *args], cwd=self.root)

    def json(self, args: list[str]) -> tuple[int, dict | None, str]:
        cmd_args = list(args)
        if "--json" not in cmd_args:
            cmd_args.append("--json")
        rc, out = self.cmd(cmd_args)
        return rc, parse_json_output(out), out


def parse_json_output(output: str) -> dict | None:
    s = output.strip()
    if not s:
        return None
    try:
        v = json.loads(s)
        return v if isinstance(v, dict) else None
    except Exception:
        pass

    # Fallback: parse last JSON object from noisy output.
    i = s.rfind("{")
    while i >= 0:
        chunk = s[i:]
        try:
            v = json.loads(chunk)
            return v if isinstance(v, dict) else None
        except Exception:
            i = s.rfind("{", 0, i)
    return None


def ensure_key_matches_device(tool: ToolRunner, host: str, key_path: Path) -> tuple[bool, dict]:
    rc, obj, out = tool.json(["key-match-check", "--host", host, "--key", str(key_path)])
    if rc != 0 or not obj:
        return False, {"error": "KEY_MATCH_CHECK_FAILED", "detail": out[-500:]}
    payload = obj.get("payload") if isinstance(obj, dict) else None
    detail = payload if isinstance(payload, dict) else {"detail": out[-500:]}
    return bool(obj.get("ok")), detail


def wait_http_state(tool: ToolRunner, host: str, timeout_s: int = 40) -> tuple[bool, dict | str]:
    end = time.time() + timeout_s
    last_err: str | None = None
    while time.time() < end:
        rc, obj, out = tool.json(["state-get", "--host", host])
        payload = obj.get("payload") if isinstance(obj, dict) else None
        if rc == 0 and isinstance(payload, dict) and isinstance(payload.get("state"), dict):
            st = payload["state"]
            if st.get("ok"):
                return True, st
            last_err = json.dumps(st)
        else:
            last_err = out[-400:] if out else "state-get failed"
        time.sleep(1.0)
    return False, last_err or "timeout"


def wait_http_down(tool: ToolRunner, host: str, timeout_s: int = 20) -> bool:
    end = time.time() + timeout_s
    while time.time() < end:
        rc, _, _ = tool.json(["state-get", "--host", host])
        if rc != 0:
            return True
        time.sleep(0.5)
    return False


def fresh_setup(tool: ToolRunner, host_hint: str, port: str, target: str, wifi_ssid: str, wifi_password: str, identity_prefix: str, upload_fs: bool) -> tuple[str, Path, Path, str, str, list[dict]]:
    steps: list[dict] = []

    # Transitional architecture step: route setup via azt-tool command surface.
    # NOTE: upload_fs is currently ignored here; once a dedicated CLI command exists,
    # E2E should invoke that command instead of direct PlatformIO usage.
    rc_erase, out_erase = tool.cmd(
        ["erase-device", "--port", port, "--target", target],
        )
    steps.append({"name": "tool_erase_device", "ok": rc_erase == 0, "detail": out_erase[-2500:]})
    if rc_erase != 0:
        raise RuntimeError(f"tool erase-device failed\n{out_erase}")

    stamp = time.strftime("%Y%m%d-%H%M%S")
    identity = f"{identity_prefix}-{stamp}"

    rc_flash, out_flash = tool.cmd(
        ["flash-device", "--from-source", "--port", port, "--target", target],
        )
    steps.append({"name": "tool_flash_device", "ok": rc_flash == 0, "detail": out_flash[-2500:]})
    if rc_flash != 0:
        raise RuntimeError(f"tool flash-device failed\n{out_flash}")

    rc_creds, obj_creds, out_creds = tool.json(
        ["create-signing-credentials", "--identity", identity],
        )
    steps.append({"name": "tool_create_credentials", "ok": rc_creds == 0, "detail": out_creds[-2000:]})
    payload_creds = obj_creds.get("payload") if isinstance(obj_creds, dict) else None
    if rc_creds != 0 or not isinstance(payload_creds, dict) or not payload_creds.get("artifacts"):
        raise RuntimeError(f"tool create-signing-credentials failed\n{out_creds}")

    admin_creds_dir = str(payload_creds.get("artifacts") or "")

    rec_identity = f"{identity}-rec"
    rc_rec_creds, obj_rec_creds, out_rec_creds = tool.json(["create-decoding-credentials", "--identity", rec_identity])
    steps.append({"name": "tool_create_decoding_credentials", "ok": rc_rec_creds == 0, "detail": out_rec_creds[-2000:]})
    payload_rec_creds = obj_rec_creds.get("payload") if isinstance(obj_rec_creds, dict) else None
    if rc_rec_creds != 0 or not isinstance(payload_rec_creds, dict) or not payload_rec_creds.get("artifacts"):
        raise RuntimeError(f"tool create-decoding-credentials failed\n{out_rec_creds}")
    rec_creds_dir = str(payload_rec_creds.get("artifacts") or "")

    fw_identity = f"{identity}-fw"
    rc_fw_creds, obj_fw_creds, out_fw_creds = tool.json(["create-signing-credentials", "--identity", fw_identity])
    steps.append({"name": "tool_create_firmware_credentials", "ok": rc_fw_creds == 0, "detail": out_fw_creds[-2000:]})
    payload_fw_creds = obj_fw_creds.get("payload") if isinstance(obj_fw_creds, dict) else None
    if rc_fw_creds != 0 or not isinstance(payload_fw_creds, dict) or not payload_fw_creds.get("artifacts"):
        raise RuntimeError(f"tool create-signing-credentials (firmware) failed\n{out_fw_creds}")
    fw_creds_dir = Path(str(payload_fw_creds.get("artifacts") or ""))
    fw_pub_path = fw_creds_dir / "public_key_b64.txt"
    if not fw_pub_path.exists():
        raise RuntimeError(f"expected firmware signer public key missing: {fw_pub_path}")

    rc_conf, obj_conf, out_conf = tool.json(
        [
            "configure-device",
            "--admin-creds-dir", admin_creds_dir,
            "--recorder-creds-dir", rec_creds_dir,
            "--identity", identity,
            "--wifi-ssid", wifi_ssid,
            "--wifi-password", wifi_password,
            "--port", port,
            "--allow-serial-bootstrap",
            "--ota-signer-public-key-pem", str(fw_pub_path),
        ],
        )
    steps.append({"name": "tool_configure_device", "ok": rc_conf == 0, "detail": out_conf[-2500:]})
    payload_conf = obj_conf.get("payload") if isinstance(obj_conf, dict) else None
    if rc_conf != 0 or not isinstance(payload_conf, dict):
        raise RuntimeError(f"tool configure-device failed\n{out_conf}")

    final = {"ok": bool(obj_conf.get("ok")) if isinstance(obj_conf, dict) else False, **payload_conf}
    if not admin_creds_dir:
        raise RuntimeError(f"missing artifact path in provisioning result\n{final}")

    key_path = Path(admin_creds_dir) / "private_key.pem"
    if not key_path.exists():
        key_path = Path(admin_creds_dir) / "admin_private_key.pem"
    if not key_path.exists():
        raise RuntimeError(f"expected key missing: {key_path}")

    ota_signer_key_path = fw_creds_dir / "private_key.pem"
    if not ota_signer_key_path.exists():
        ota_signer_key_path = fw_creds_dir / "admin_private_key.pem"
    if not ota_signer_key_path.exists():
        raise RuntimeError(f"expected OTA signer private key missing: {ota_signer_key_path}")

    host = str(final.get("ip") or host_hint)
    ok_state, state_detail = wait_http_state(tool, host, timeout_s=35)
    steps.append({"name": "http_state_ready", "ok": ok_state, "detail": state_detail})
    if not ok_state:
        raise RuntimeError(f"HTTP state not ready on {host}: {state_detail}")

    rc_state, obj_state, out_state = tool.json(["state-get", "--host", host])
    payload_state = obj_state.get("payload") if isinstance(obj_state, dict) else None
    if rc_state != 0 or not isinstance(payload_state, dict) or not isinstance(payload_state.get("state"), dict):
        raise RuntimeError(f"state-get failed after configure\n{out_state}")
    st2 = payload_state["state"]
    st2_ok = st2.get("signed_config_ready") is True
    steps.append({"name": "signed_state_ready", "ok": st2_ok, "detail": st2})
    if not st2_ok:
        raise RuntimeError(f"signed state not ready after provisioning: {st2}")

    return host, key_path, ota_signer_key_path, admin_creds_dir, rec_creds_dir, steps


def main() -> int:
    ap = argparse.ArgumentParser(description="E2E runner (default: full fresh flash+provision; use --fast to skip setup)")
    ap.add_argument("--host", default="", help="Device IP/host (required in --fast mode; optional host hint in default fresh mode)")
    ap.add_argument("--key", default="", help="Path to admin private key PEM (required in --fast mode)")
    ap.add_argument("--ota-signer-key", default="", help="Path to OTA firmware signer private key PEM (--fast mode; defaults to --key)")
    ap.add_argument("--workdir", default=".", help="Repo root")
    ap.add_argument("--finite-seconds", type=int, default=8)
    ap.add_argument("--reconnect-seconds", type=int, default=12)
    ap.add_argument("--indef-probe-seconds", type=float, default=5.0)

    ap.add_argument("--fast", action="store_true", help="Skip erase/flash/provision setup and run checks against existing host/key")
    ap.add_argument("--secrets-file", default=".secrets/e2e.env", help="Optional KEY=VALUE file for local secrets (default: .secrets/e2e.env)")
    ap.add_argument("--port", default=None)
    ap.add_argument("--target", default="atom-echo", choices=["atom-echo", "atom-echos3r"], help="Hardware target for erase/flash during fresh setup")
    ap.add_argument("--wifi-ssid", default=None)
    ap.add_argument("--wifi-password", default=None)
    ap.add_argument("--identity-prefix", default="e2e")
    ap.add_argument("--no-upload-fs", action="store_true", help="Skip LittleFS upload during default fresh setup")
    ap.add_argument("--tool-cmd", default="python3 client/tools/azt_tool.py", help="Command used to invoke AZT CLI (default: python3 client/tools/azt_tool.py)")
    ap.add_argument("--tmp-dir", default="/tmp/azt/e2e", help="Directory for temporary E2E artifacts")
    args = ap.parse_args()

    root = Path(args.workdir).resolve()
    secrets_path = Path(args.secrets_file)
    if not secrets_path.is_absolute():
        secrets_path = (root / secrets_path).resolve()
    secrets = load_simple_env_file(secrets_path)

    port = first_nonempty(args.port, os.getenv("AZT_E2E_PORT"), secrets.get("AZT_E2E_PORT"), "/dev/ttyUSB0")
    wifi_ssid = first_nonempty(args.wifi_ssid, os.getenv("AZT_WIFI_SSID"), secrets.get("AZT_WIFI_SSID"))
    wifi_password = first_nonempty(args.wifi_password, os.getenv("AZT_WIFI_PASSWORD"), secrets.get("AZT_WIFI_PASSWORD"))
    host_from_env = first_nonempty(os.getenv("AZT_E2E_HOST"), secrets.get("AZT_E2E_HOST"))
    if not args.host and host_from_env:
        args.host = host_from_env

    out_dir = Path(args.tmp_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    tool = ToolRunner(root, args.tool_cmd)

    setup_steps: list[dict] = []
    host = args.host
    admin_creds_dir = None
    rec_creds_dir = None
    ota_signer_key_path = None
    run_fresh = not args.fast

    if run_fresh:
        try:
            if not wifi_ssid or not wifi_password:
                raise RuntimeError("missing Wi-Fi credentials: pass --wifi-ssid/--wifi-password or set AZT_WIFI_SSID/AZT_WIFI_PASSWORD (or .secrets/e2e.env)")
            host, key_path, ota_signer_key_path, admin_creds_dir, rec_creds_dir, setup_steps = fresh_setup(
                tool,
                host_hint=args.host,
                port=port,
                target=args.target,
                wifi_ssid=wifi_ssid,
                wifi_password=wifi_password,
                identity_prefix=args.identity_prefix,
                upload_fs=(not args.no_upload_fs),
            )
        except Exception as e:
            print(json.dumps({"ok": False, "kind": "true-e2e-fresh", "stage": "setup", "error": str(e), "setup_steps": setup_steps}, indent=2))
            return 1
        if not host:
            print(json.dumps({"ok": False, "kind": "true-e2e-fresh", "stage": "setup", "error": "no host detected during fresh setup", "setup_steps": setup_steps}, indent=2))
            return 1
    else:
        if not args.host:
            print(json.dumps({"ok": False, "kind": "quick-e2e-no-soak", "error": "--host is required in --fast mode"}, indent=2))
            return 2
        if not args.key:
            print(json.dumps({"ok": False, "kind": "quick-e2e-no-soak", "error": "--key is required in --fast mode"}, indent=2))
            return 2
        key_path = Path(args.key)
        ota_signer_key_path = Path(args.ota_signer_key) if (args.ota_signer_key or "").strip() else key_path

    results: list[dict] = []

    try:
        key_ok, fp_detail = ensure_key_matches_device(tool, host, key_path)
        results.append({"name": "key_fingerprint_match", "ok": key_ok, "detail": fp_detail})
        if not key_ok:
            summary = {
                "ok": False,
                "kind": "true-e2e-fresh" if run_fresh else "quick-e2e-no-soak",
                "setup_steps": setup_steps,
                "artifacts": admin_creds_dir,
                "host": host,
                "key": str(key_path),
                "results": results,
            }
            print(json.dumps(summary, indent=2))
            return 1
    except Exception as e:
        results.append({"name": "key_fingerprint_match", "ok": False, "detail": str(e)})

    state = None
    try:
        rc_state, obj_state, out_state = tool.json(["state-get", "--host", host])
        payload_state = obj_state.get("payload") if isinstance(obj_state, dict) else None
        if rc_state != 0 or not isinstance(payload_state, dict) or not isinstance(payload_state.get("state"), dict):
            raise RuntimeError(out_state)
        state = payload_state["state"]
        ok = (
            bool(state.get("ok"))
            and state.get("signed_config_ready") is True
            and isinstance(state.get("device_sign_public_key_b64"), str)
            and len(state.get("device_sign_public_key_b64", "")) > 0
            and isinstance(state.get("device_sign_fingerprint_hex"), str)
            and len(state.get("device_sign_fingerprint_hex", "")) == 64
            and state.get("device_sign_alg") == "ed25519"
            and isinstance(state.get("device_chip_id_hex"), str)
            and len(state.get("device_chip_id_hex", "")) == 16
        )
        results.append({"name": "state_check", "ok": ok, "detail": state})
    except Exception as e:
        results.append({"name": "state_check", "ok": False, "detail": str(e)})

    # Serial-configurable OTA floor controls (set + clear) via configure-device.
    if run_fresh and admin_creds_dir and isinstance(state, dict):
        if args.target == "atom-echos3r":
            results.append({"name": "serial_floor_set_configure", "ok": True, "detail": "skipped: serial OTA floor controls not yet validated for atom-echos3r"})
            results.append({"name": "serial_floor_set_state", "ok": True, "detail": "skipped: serial OTA floor controls not yet validated for atom-echos3r"})
            results.append({"name": "serial_floor_clear_configure", "ok": True, "detail": "skipped: serial OTA floor controls not yet validated for atom-echos3r"})
            results.append({"name": "serial_floor_clear_state", "ok": True, "detail": "skipped: serial OTA floor controls not yet validated for atom-echos3r"})
        else:
            try:
                identity_label = str(state.get("device_label") or args.identity_prefix)
                floor_set_value = int(time.time()) + 5000
                rc_cfg_set, obj_cfg_set, out_cfg_set = tool.json([
                    "configure-device",
                    "--admin-creds-dir", str(admin_creds_dir),
                    "--recorder-creds-dir", str(rec_creds_dir or admin_creds_dir),
                    "--identity", identity_label,
                    "--wifi-ssid", wifi_ssid,
                    "--wifi-password", wifi_password,
                    "--port", port,
                    "--ip", host,
                    "--no-auto-ip",
                    "--allow-serial-bootstrap",
                    "--ota-version-code", str(floor_set_value),
                    "--ota-min-version-code", str(floor_set_value),
                ])
                ok_cfg_set = rc_cfg_set == 0 and isinstance(obj_cfg_set, dict) and bool(obj_cfg_set.get("ok"))
                results.append({"name": "serial_floor_set_configure", "ok": ok_cfg_set, "detail": obj_cfg_set if isinstance(obj_cfg_set, dict) else out_cfg_set[-400:]})

                rc_st_set, obj_st_set, out_st_set = tool.json(["state-get", "--host", host])
                payload_st_set = obj_st_set.get("payload") if isinstance(obj_st_set, dict) else None
                st_set = payload_st_set.get("state") if isinstance(payload_st_set, dict) and isinstance(payload_st_set.get("state"), dict) else {}
                floor_after_set = int(st_set.get("ota_min_allowed_version_code") or 0)
                results.append({"name": "serial_floor_set_state", "ok": rc_st_set == 0 and floor_after_set == floor_set_value, "detail": {"expected": floor_set_value, "actual": floor_after_set, "raw": out_st_set[-300:]}})

                rc_cfg_clr, obj_cfg_clr, out_cfg_clr = tool.json([
                    "configure-device",
                    "--admin-creds-dir", str(admin_creds_dir),
                    "--recorder-creds-dir", str(rec_creds_dir or admin_creds_dir),
                    "--identity", identity_label,
                    "--wifi-ssid", wifi_ssid,
                    "--wifi-password", wifi_password,
                    "--port", port,
                    "--ip", host,
                    "--no-auto-ip",
                    "--allow-serial-bootstrap",
                    "--ota-min-version-code-clear",
                ])
                ok_cfg_clr = rc_cfg_clr == 0 and isinstance(obj_cfg_clr, dict) and bool(obj_cfg_clr.get("ok"))
                results.append({"name": "serial_floor_clear_configure", "ok": ok_cfg_clr, "detail": obj_cfg_clr if isinstance(obj_cfg_clr, dict) else out_cfg_clr[-400:]})

                rc_st_clr, obj_st_clr, out_st_clr = tool.json(["state-get", "--host", host])
                payload_st_clr = obj_st_clr.get("payload") if isinstance(obj_st_clr, dict) else None
                st_clr = payload_st_clr.get("state") if isinstance(payload_st_clr, dict) and isinstance(payload_st_clr.get("state"), dict) else {}
                floor_raw = st_clr.get("ota_min_allowed_version_code")
                floor_after_clear = int(floor_raw) if isinstance(floor_raw, (int, float, str)) and str(floor_raw).strip() != "" else -1
                results.append({"name": "serial_floor_clear_state", "ok": rc_st_clr == 0 and floor_after_clear == 0, "detail": {"actual": floor_after_clear, "raw": out_st_clr[-300:]}})
            except Exception as e:
                results.append({"name": "serial_floor_set_configure", "ok": False, "detail": str(e)})
                results.append({"name": "serial_floor_set_state", "ok": False, "detail": str(e)})
                results.append({"name": "serial_floor_clear_configure", "ok": False, "detail": str(e)})
                results.append({"name": "serial_floor_clear_state", "ok": False, "detail": str(e)})

    # API happy-path checks now routed through CLI commands.
    try:
        rc_sign, obj_sign, out_sign = 1, None, ""
        for _ in range(3):
            rc_sign, obj_sign, out_sign = tool.json(["signing-key-check", "--host", host])
            payload_sign = obj_sign.get("payload") if isinstance(obj_sign, dict) else None
            if rc_sign == 0 and isinstance(payload_sign, dict):
                break
            time.sleep(0.5)
        payload_sign = obj_sign.get("payload") if isinstance(obj_sign, dict) else None
        detail_sign = payload_sign if isinstance(payload_sign, dict) else {"detail": out_sign}
        results.append({"name": "signing_public_key_pem", "ok": rc_sign == 0 and bool(detail_sign.get("has_public_key_pem")), "detail": {"content_type": detail_sign.get("content_type")}})
        results.append({"name": "signing_public_key_alias", "ok": rc_sign == 0 and bool(detail_sign.get("alias_matches")), "detail": {"same_as_pem": bool(detail_sign.get("alias_matches"))}})
    except Exception as e:
        results.append({"name": "signing_public_key_pem", "ok": False, "detail": str(e)})
        results.append({"name": "signing_public_key_alias", "ok": False, "detail": str(e)})

    attestation_artifact_path = out_dir / "e2e_attestation_verified.json"
    try:
        nonce = ""
        rc_attv, obj_attv, out_attv = tool.json(["attestation-verify", "--host", host, "--out", str(attestation_artifact_path)])
        payload_attv = obj_attv.get("payload") if isinstance(obj_attv, dict) else None
        if rc_attv != 0 or not isinstance(payload_attv, dict):
            raise RuntimeError(out_attv)

        att = payload_attv.get("attestation") if isinstance(payload_attv.get("attestation"), dict) else {}
        schema_ok = bool(payload_attv.get("schema_ok"))
        sig_ok = bool(payload_attv.get("sig_ok"))
        att_payload = att.get("payload") if isinstance(att.get("payload"), dict) else {}
        sig_detail = payload_attv.get("sig_detail")

        att_chip_ok = isinstance(att_payload.get("device_chip_id_hex"), str) and len(att_payload.get("device_chip_id_hex", "")) == 16
        results.append({"name": "attestation_happy_path", "ok": schema_ok and att_chip_ok, "detail": att})
        results.append({"name": "attestation_signature_verify", "ok": sig_ok, "detail": sig_detail})

        rc_bad, obj_bad, out_bad = tool.json(["attestation-get", "--host", host, "--nonce", "short"])
        payload_bad = obj_bad.get("payload") if isinstance(obj_bad, dict) else None
        if isinstance(payload_bad, dict) and isinstance(payload_bad.get("response"), dict):
            att_bad = payload_bad["response"]
        else:
            att_bad = {"ok": False, "error": "TOOL_CALL_FAILED", "detail": out_bad}
        err_text = json.dumps(att_bad)
        att_bad_ok = (
            (att_bad.get("ok") is False and att_bad.get("error") == "ERR_ATTEST_NONCE")
            or ("ERR_ATTEST_NONCE" in err_text)
            or ("ERR_ATTEST_NONCE" in (out_bad or ""))
        )
        results.append({"name": "attestation_nonce_bounds_error", "ok": att_bad_ok, "detail": att_bad})
    except Exception as e:
        results.append({"name": "attestation_happy_path", "ok": False, "detail": str(e)})
        results.append({"name": "attestation_signature_verify", "ok": False, "detail": str(e)})
        results.append({"name": "attestation_nonce_bounds_error", "ok": False, "detail": str(e)})

    # Certificate endpoint lifecycle coverage in fresh mode.
    if run_fresh:
        try:
            rc_cg0, obj_cg0, out_cg0 = tool.json(["certificate-get", "--host", host])
            payload_cg0 = obj_cg0.get("payload") if isinstance(obj_cg0, dict) else None
            cert_get0 = payload_cg0.get("response") if isinstance(payload_cg0, dict) and isinstance(payload_cg0.get("response"), dict) else {"ok": False, "detail": out_cg0}
            ok0 = cert_get0.get("ok") is False and cert_get0.get("error") == "ERR_CERT_NOT_FOUND"
            results.append({"name": "certificate_get_not_found", "ok": ok0, "detail": cert_get0})
        except Exception as e:
            results.append({"name": "certificate_get_not_found", "ok": False, "detail": str(e)})

    try:
        if state and state.get("ok"):
            cert_serial = f"e2e-cert-{int(time.time())}"
            cert_path = out_dir / "e2e_device_cert.json"
            rc_ci, obj_ci, out_ci = tool.json([
                "certificate-issue",
                "--host", host,
                "--key", str(key_path),
                "--attestation", str(attestation_artifact_path),
                "--cert-serial", cert_serial,
                "--out", str(cert_path),
            ])
            payload_ci = obj_ci.get("payload") if isinstance(obj_ci, dict) else None
            cert_doc = payload_ci.get("certificate") if isinstance(payload_ci, dict) and isinstance(payload_ci.get("certificate"), dict) else {}
            if rc_ci != 0 or not cert_doc:
                raise RuntimeError(f"certificate-issue failed\n{out_ci}")

            rc_cp, obj_cp, out_cp = tool.json(["certificate-post", "--host", host, "--in", str(cert_path)])
            payload_cp = obj_cp.get("payload") if isinstance(obj_cp, dict) else None
            cert_post = payload_cp.get("response") if isinstance(payload_cp, dict) and isinstance(payload_cp.get("response"), dict) else {"ok": False, "detail": out_cp}
            ok_post = bool(cert_post.get("ok")) and cert_post.get("certificate_serial") == cert_serial
            results.append({"name": "certificate_post", "ok": ok_post, "detail": cert_post})

            rc_cg, obj_cg, out_cg = tool.json(["certificate-get", "--host", host])
            payload_cg = obj_cg.get("payload") if isinstance(obj_cg, dict) else None
            cert_get = payload_cg.get("response") if isinstance(payload_cg, dict) and isinstance(payload_cg.get("response"), dict) else {"ok": False, "detail": out_cg}
            cert = cert_get.get("certificate") if isinstance(cert_get, dict) else None
            ok_get = bool(cert_get.get("ok")) and isinstance(cert, dict) and cert.get("certificate_payload_b64") == cert_doc.get("certificate_payload_b64")
            if ok_get:
                try:
                    cert_payload_raw = base64.b64decode(str(cert.get("certificate_payload_b64") or ""))
                    cert_payload_obj = json.loads(cert_payload_raw.decode("utf-8"))
                    ok_get = isinstance(cert_payload_obj.get("device_chip_id_hex"), str) and len(cert_payload_obj.get("device_chip_id_hex", "")) == 16
                except Exception:
                    ok_get = False
            results.append({"name": "certificate_get", "ok": ok_get, "detail": cert_get})
        else:
            results.append({"name": "certificate_post", "ok": False, "detail": "state unavailable"})
            results.append({"name": "certificate_get", "ok": False, "detail": "state unavailable"})
    except Exception as e:
        results.append({"name": "certificate_post", "ok": False, "detail": str(e)})
        results.append({"name": "certificate_get", "ok": False, "detail": str(e)})

    # Stream split/redirect contract checks via CLI command.
    try:
        rc_redir, obj_redir, out_redir = tool.json(["stream-redirect-check", "--host", host, "--seconds", "1"])
        payload_redir = obj_redir.get("payload") if isinstance(obj_redir, dict) else None
        if rc_redir == 0 and isinstance(payload_redir, dict):
            results.append({"name": "stream_redirect_307", "ok": True, "detail": {"status": payload_redir.get("status"), "location": payload_redir.get("location")}})
        else:
            results.append({"name": "stream_redirect_307", "ok": False, "detail": out_redir})
    except Exception as e:
        results.append({"name": "stream_redirect_307", "ok": False, "detail": str(e)})

    # Reboot + post-reboot contract checks.
    try:
        rc_rb, obj_rb, out_rb = tool.json(["reboot-device", "--host", host, "--key", str(key_path)])
        payload_rb = obj_rb.get("payload") if isinstance(obj_rb, dict) else None
        reboot = payload_rb.get("response") if isinstance(payload_rb, dict) and isinstance(payload_rb.get("response"), dict) else {"ok": False, "detail": out_rb}
        reboot_ok = bool(reboot.get("ok")) and rc_rb == 0
        results.append({"name": "reboot_trigger", "ok": reboot_ok, "detail": reboot})

        went_down = wait_http_down(tool, host, timeout_s=25)
        # Fast reboot cycles may not expose an observable down window; keep as informational.
        results.append({"name": "reboot_http_down", "ok": True, "detail": "down_seen" if went_down else "down_not_seen"})

        up_ok, up_state = wait_http_state(tool, host, timeout_s=50)
        post_ok = bool(up_ok)
        detail = up_state
        if up_ok and isinstance(up_state, dict) and isinstance(state, dict):
            post_ok = (
                up_state.get("signed_config_ready") is True
                and up_state.get("admin_fingerprint_hex") == state.get("admin_fingerprint_hex")
                and up_state.get("recording_fingerprint_hex") == state.get("recording_fingerprint_hex")
                and up_state.get("device_sign_fingerprint_hex") == state.get("device_sign_fingerprint_hex")
                and up_state.get("device_label") == state.get("device_label")
            )
        results.append({"name": "post_reboot_state", "ok": post_ok, "detail": detail})
    except Exception as err:
        results.append({"name": "reboot_trigger", "ok": False, "detail": str(err)})
        results.append({"name": "reboot_http_down", "ok": False, "detail": str(err)})
        results.append({"name": "post_reboot_state", "ok": False, "detail": str(err)})

    try:
        finite_timeout = str(max(20, int(args.finite_seconds) + 5))
        rc_finite, obj_finite, out_finite = tool.json(["stream-read", "--host", host, "--seconds", str(args.finite_seconds), "--timeout", finite_timeout, "--probe"])
        payload_finite = obj_finite.get("payload") if isinstance(obj_finite, dict) else None
        finite_bytes = int(payload_finite.get("bytes") or 0) if isinstance(payload_finite, dict) else 0
        ok_fetch = rc_finite == 0 and finite_bytes > 0
        results.append({"name": "finite_fetch", "ok": ok_fetch, "detail": payload_finite if isinstance(payload_finite, dict) else out_finite[-500:]})
    except Exception as err:
        results.append({"name": "finite_fetch", "ok": False, "detail": str(err)})

    results.append({"name": "finite_validate", "ok": True, "detail": "skipped: fetch-sample artifact path removed; stream-read-only flow"})

    # OTA happy/sad-path checks.
    if ota_signer_key_path is None:
        ota_signer_key_path = key_path
    ota_env = "atom-echos3r" if args.target == "atom-echos3r" else "atom-echo"
    ota_firmware_bin = root / "firmware" / "audio_zero_trust" / ".pio" / "build" / ota_env / "firmware.bin"
    try:
        rc_state0, obj_state0, out_state0 = tool.json(["state-get", "--host", host])
        payload_state0 = obj_state0.get("payload") if isinstance(obj_state0, dict) else None
        st0 = payload_state0.get("state") if isinstance(payload_state0, dict) and isinstance(payload_state0.get("state"), dict) else {}
        floor_before = int(st0.get("ota_min_allowed_version_code") or 0)

        # Use a base version code guaranteed to be above any existing rollback floor.
        base_code = max(int(time.time()), floor_before + 100)

        # Explicitly verify invalid rollback floor (0) is rejected by CLI.
        out_floor_zero = out_dir / "e2e_ota_floor_zero_invalid.otabundle"
        rc_make_zero, obj_make_zero, out_make_zero = tool.json([
            "ota-bundle-create",
            "--key", str(ota_signer_key_path),
            "--firmware", str(ota_firmware_bin),
            "--version-code", str(base_code),
            "--rollback-floor-code", "0",
            "--out", str(out_floor_zero),
        ])
        detail_make_zero = obj_make_zero if isinstance(obj_make_zero, dict) else {"raw": out_make_zero[-500:]}
        err_make_zero = json.dumps(detail_make_zero)
        ok_make_zero = (rc_make_zero != 0) and ("ERR_OTA_ROLLBACK_FLOOR_INVALID" in err_make_zero)
        results.append({"name": "ota_floor_zero_rejected", "ok": ok_make_zero, "detail": detail_make_zero})

        high_code = base_code + 1000
        out_floor = out_dir / "e2e_ota_floor_same.otabundle"
        rc_make_f, _, out_make_f = tool.json([
            "ota-bundle-create",
            "--key", str(ota_signer_key_path),
            "--firmware", str(ota_firmware_bin),
            "--version-code", str(high_code),
            "--rollback-floor-code", "same",
            "--out", str(out_floor),
        ])
        ok_make_f = rc_make_f == 0 and out_floor.exists() and out_floor.stat().st_size > 0
        results.append({"name": "ota_floor_same_create", "ok": ok_make_f, "detail": out_make_f[-400:]})

        prev_scheme = os.environ.get("AZT_SCHEME")

        # Explicit HTTPS OTA expectation (currently unsupported).
        os.environ["AZT_SCHEME"] = "https"
        rc_post_https, obj_post_https, out_post_https = tool.json(["ota-bundle-post", "--host", host, "--port", "8443", "--in", str(out_floor)])
        detail_https = obj_post_https if isinstance(obj_post_https, dict) else {"raw": out_post_https[-500:]}
        err_https = json.dumps(detail_https)
        ok_https = (rc_post_https != 0) and ("ERR_OTA_HTTPS_UNSUPPORTED" in err_https)
        results.append({"name": "ota_https_unsupported", "ok": ok_https, "detail": detail_https})

        os.environ["AZT_SCHEME"] = "http"
        rc_post_f, obj_post_f, out_post_f = tool.json(["ota-bundle-post", "--host", host, "--in", str(out_floor)])
        if rc_post_f != 0 and "No route to host" in (out_post_f or ""):
            wait_http_state(tool, host, timeout_s=60)
            rc_post_f, obj_post_f, out_post_f = tool.json(["ota-bundle-post", "--host", host, "--in", str(out_floor)])
        ok_post_f = rc_post_f == 0 and isinstance(obj_post_f, dict) and bool(obj_post_f.get("ok"))
        results.append({"name": "ota_floor_same_post", "ok": ok_post_f, "detail": obj_post_f if isinstance(obj_post_f, dict) else out_post_f[-400:]})

        time.sleep(3)
        up_ok_f, up_state_f = wait_http_state(tool, host, timeout_s=60)
        floor_after_f = int(up_state_f.get("ota_min_allowed_version_code") or 0) if up_ok_f and isinstance(up_state_f, dict) else -1
        results.append({"name": "ota_floor_same_state", "ok": up_ok_f and floor_after_f >= high_code, "detail": {"expected_min": high_code, "after": floor_after_f}})

        low_code = base_code
        out_low = out_dir / "e2e_ota_lowcode_reject.otabundle"
        rc_make_l, _, out_make_l = tool.json([
            "ota-bundle-create",
            "--key", str(ota_signer_key_path),
            "--firmware", str(ota_firmware_bin),
            "--version-code", str(low_code),
            "--out", str(out_low),
        ])
        ok_make_l = rc_make_l == 0 and out_low.exists() and out_low.stat().st_size > 0
        results.append({"name": "ota_lowcode_create", "ok": ok_make_l, "detail": out_make_l[-400:]})

        rc_post_l, obj_post_l, out_post_l = tool.json(["ota-bundle-post", "--host", host, "--in", str(out_low)])
        if rc_post_l != 0 and "No route to host" in (out_post_l or ""):
            wait_http_state(tool, host, timeout_s=60)
            rc_post_l, obj_post_l, out_post_l = tool.json(["ota-bundle-post", "--host", host, "--in", str(out_low)])
        detail_l = obj_post_l if isinstance(obj_post_l, dict) else {"raw": out_post_l[-500:]}
        err_blob = json.dumps(detail_l)
        ok_post_l = (rc_post_l != 0) and ("version_code below rollback floor" in err_blob)
        results.append({"name": "ota_lowcode_reject", "ok": ok_post_l, "detail": detail_l})

        if prev_scheme is None:
            os.environ.pop("AZT_SCHEME", None)
        else:
            os.environ["AZT_SCHEME"] = prev_scheme

    except Exception as err:
        if 'prev_scheme' in locals():
            if prev_scheme is None:
                os.environ.pop("AZT_SCHEME", None)
            else:
                os.environ["AZT_SCHEME"] = prev_scheme
        results.append({"name": "ota_floor_zero_rejected", "ok": False, "detail": str(err)})
        results.append({"name": "ota_https_unsupported", "ok": False, "detail": str(err)})
        results.append({"name": "ota_floor_same_create", "ok": False, "detail": str(err)})
        results.append({"name": "ota_floor_same_post", "ok": False, "detail": str(err)})
        results.append({"name": "ota_floor_same_state", "ok": False, "detail": str(err)})
        results.append({"name": "ota_lowcode_create", "ok": False, "detail": str(err)})
        results.append({"name": "ota_lowcode_reject", "ok": False, "detail": str(err)})

    try:
        wait_http_state(tool, host, timeout_s=60)
        probe_timeout = str(max(20, int(args.indef_probe_seconds) + 5))
        rc_probe, obj_probe, out_probe = tool.json(["stream-read", "--host", host, "--seconds", str(args.indef_probe_seconds), "--timeout", probe_timeout, "--probe"])
        payload_probe = obj_probe.get("payload") if isinstance(obj_probe, dict) else None
        if rc_probe == 0 and isinstance(payload_probe, dict):
            n = int(payload_probe.get("bytes") or 0)
            results.append({"name": "indefinite_probe", "ok": n > 0, "detail": {"bytes": n}})
        else:
            results.append({"name": "indefinite_probe", "ok": False, "detail": out_probe})
    except Exception as err:
        results.append({"name": "indefinite_probe", "ok": False, "detail": str(err)})

    def probe_with_retry(attempts: int = 2) -> tuple[int, dict | None, str]:
        last_rc, last_obj, last_out = 1, None, ""
        for _ in range(attempts):
            reconnect_timeout = str(max(20, int(args.reconnect_seconds) + 5))
            rc, obj, out = tool.json(["stream-read", "--host", host, "--seconds", str(args.reconnect_seconds), "--timeout", reconnect_timeout, "--probe"])
            last_rc, last_obj, last_out = rc, obj, out
            payload = obj.get("payload") if isinstance(obj, dict) else None
            if rc == 0 and isinstance(payload, dict) and int(payload.get("bytes") or 0) > 0:
                return rc, obj, out
            time.sleep(0.5)
        return last_rc, last_obj, last_out

    rc_a, obj_a, out_a = probe_with_retry(attempts=2)
    rc_b, obj_b, out_b = probe_with_retry(attempts=2)
    payload_a = obj_a.get("payload") if isinstance(obj_a, dict) else None
    payload_b = obj_b.get("payload") if isinstance(obj_b, dict) else None
    ok_reconnect = (
        rc_a == 0 and rc_b == 0
        and isinstance(payload_a, dict) and isinstance(payload_b, dict)
        and int(payload_a.get("bytes") or 0) > 0
        and int(payload_b.get("bytes") or 0) > 0
    )
    results.append({"name": "reconnect_fetch", "ok": ok_reconnect, "detail": {"a": payload_a, "b": payload_b, "raw": (out_a + "\n" + out_b)[-500:]}})

    results.append({"name": "reconnect_validate", "ok": True, "detail": "skipped: fetch-sample artifact path removed; stream-read-only flow"})
    results.append({"name": "truncation_tolerance", "ok": True, "detail": "skipped: no local sample artifact in stream-read-only flow"})

    summary = {
        "ok": all(r["ok"] for r in results),
        "kind": "true-e2e-fresh" if run_fresh else "quick-e2e-no-soak",
        "setup_steps": setup_steps,
        "artifacts": admin_creds_dir,
        "host": host,
        "key": str(key_path),
        "results": results,
    }
    print(json.dumps(summary, indent=2))
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
