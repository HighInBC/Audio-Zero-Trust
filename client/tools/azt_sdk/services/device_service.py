from __future__ import annotations

from urllib.parse import quote

import base64
from pathlib import Path
from urllib.request import Request
import requests

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from tools.azt_client.crypto import ed25519_fp_hex_from_private_key
import os

from tools.azt_client.http import get_json, http_json, urlopen_with_tls, requests_verify_for_url
from tools.provision_unit import detect_device_ip_from_serial
from tools.azt_sdk.services.url_service import base_url


def _state_get_v0(*, host: str, port: int, timeout: int) -> dict:
    scheme = os.getenv("AZT_SCHEME", "auto")
    b = base_url(host=host, port=port, scheme=scheme)
    return get_json(f"{b}/api/v0/config/state", timeout=timeout)


def _state_get_v1_legacy(*, host: str, port: int, timeout: int) -> dict:
    scheme = os.getenv("AZT_SCHEME", "auto")
    b = base_url(host=host, port=port, scheme=scheme)
    return get_json(f"{b}/api/v1/config/state", timeout=timeout)


def state_get(*, host: str, port: int, timeout: int) -> dict:
    # Preferred current API major.
    st = _state_get_v0(host=host, port=port, timeout=timeout)
    if st.get("ok"):
        return st

    # If the device still serves legacy v1 endpoints, surface a clear major-mismatch error
    # instead of a raw HTTP_404 to guide upgrade path.
    st_v1 = _state_get_v1_legacy(host=host, port=port, timeout=timeout)
    if st_v1.get("ok"):
        return {
            "ok": False,
            "error": "ERR_API_MAJOR_MISMATCH",
            "detail": "firmware API major=1, client API major=0; update firmware/client to matching majors",
            "payload": {
                "client_api_major": 0,
                "firmware_api_major": 1,
                "legacy_state": st_v1,
            },
        }

    return st


def attestation_get(*, host: str, port: int, timeout: int, nonce: str) -> dict:
    b = base_url(host=host, port=port, scheme=os.getenv("AZT_SCHEME", "auto"))
    return get_json(
        f"{b}/api/v0/device/attestation?nonce={quote(nonce, safe='')}",
        timeout=timeout,
    )


def certificate_get(*, host: str, port: int, timeout: int) -> dict:
    b = base_url(host=host, port=port, scheme=os.getenv("AZT_SCHEME", "auto"))
    return get_json(f"{b}/api/v0/device/certificate", timeout=timeout)


def certificate_post(*, host: str, port: int, timeout: int, payload: dict) -> dict:
    b = base_url(host=host, port=port, scheme=os.getenv("AZT_SCHEME", "auto"))
    return http_json("POST", f"{b}/api/v0/device/certificate", payload, timeout=timeout)


def reboot_device(*, host: str, port: int, timeout: int, key_path: str) -> dict:
    b = base_url(host=host, port=port, scheme=os.getenv("AZT_SCHEME", "auto"))
    ch = get_json(f"{b}/api/v0/device/reboot/challenge", timeout=timeout)
    if not ch.get("ok"):
        return {
            "ok": False,
            "error": "ERR_REBOOT_CHALLENGE",
            "detail": ch.get("error") or ch.get("detail") or "challenge request failed",
            "challenge_response": ch,
        }

    nonce = str(ch.get("nonce") or "")
    if not nonce:
        return {"ok": False, "error": "ERR_REBOOT_CHALLENGE", "detail": "missing nonce in challenge response"}

    priv = serialization.load_pem_private_key(Path(key_path).read_bytes(), password=None)
    if not isinstance(priv, ed25519.Ed25519PrivateKey):
        return {"ok": False, "error": "ERR_REBOOT_KEY", "detail": "reboot key must be Ed25519 private key PEM"}

    msg = f"reboot:{nonce}".encode("utf-8")
    sig_b64 = base64.b64encode(priv.sign(msg)).decode("ascii")
    signer_fp = ed25519_fp_hex_from_private_key(Path(key_path))

    payload = {
        "nonce": nonce,
        "signature_algorithm": "ed25519",
        "signature_b64": sig_b64,
        "signer_fingerprint_hex": signer_fp,
    }
    return http_json("POST", f"{b}/api/v0/device/reboot", payload, timeout=timeout)


def signing_key_check(*, host: str, port: int, timeout: int) -> tuple[bool, dict]:
    b = base_url(host=host, port=port, scheme=os.getenv("AZT_SCHEME", "auto"))
    pem_url = f"{b}/api/v0/device/signing-public-key.pem"
    alias_url = f"{b}/api/v0/device/signing-public-key"
    with urlopen_with_tls(Request(pem_url, method="GET"), timeout=timeout) as r:
        pem_body = r.read().decode("utf-8", errors="replace")
        pem_ct = r.headers.get("Content-Type", "")
    with urlopen_with_tls(Request(alias_url, method="GET"), timeout=timeout) as r:
        pem_alias = r.read().decode("utf-8", errors="replace")

    has_pem = "BEGIN PUBLIC KEY" in pem_body
    alias_same = pem_alias == pem_body
    ok = has_pem and ("application/x-pem-file" in pem_ct) and alias_same
    return ok, {
        "content_type": pem_ct,
        "has_public_key_pem": has_pem,
        "alias_matches": alias_same,
    }


def stream_redirect_check(*, host: str, port: int, seconds: int, stream_port: int, timeout: int) -> tuple[bool, dict]:
    b = base_url(host=host, port=port, scheme=os.getenv("AZT_SCHEME", "auto"))
    req_url = f"{b}/stream?seconds={seconds}"
    r = requests.get(req_url, allow_redirects=False, timeout=timeout, verify=requests_verify_for_url(req_url))
    status = int(r.status_code)
    location = r.headers.get("Location")
    ok = (status == 307) and bool(location and f":{stream_port}/stream" in location)
    return ok, {"status": status, "location": location}


def stream_read(*, host: str, port: int, seconds: float | None, timeout: int, out_path: str | None, probe: bool) -> tuple[bool, dict]:
    b = base_url(host=host, port=port, scheme=os.getenv("AZT_SCHEME", "auto"))
    url = f"{b}/stream"
    total = 0
    import time
    from pathlib import Path

    out_file = None
    resolved_out = ""
    if not probe and out_path:
      p = Path(out_path)
      p.parent.mkdir(parents=True, exist_ok=True)
      out_file = p.open("wb")
      resolved_out = str(p)

    r = requests.get(url, stream=True, timeout=timeout, verify=requests_verify_for_url(url))
    try:
        start = time.time()
        for chunk in r.iter_content(chunk_size=4096):
            if chunk:
                total += len(chunk)
                if out_file is not None:
                    out_file.write(chunk)
            if seconds is not None and (time.time() - start >= seconds):
                break
    finally:
        r.close()
        if out_file is not None:
            out_file.close()
    elapsed = time.time() - start
    payload = {"bytes": total, "seconds": elapsed, "requested_seconds": seconds}
    if resolved_out:
        payload["out"] = resolved_out
    return total > 0, payload


def stream_probe(*, host: str, port: int, seconds: float | None, timeout: int) -> tuple[bool, dict]:
    # Back-compat wrapper for older callers.
    return stream_read(host=host, port=port, seconds=seconds, timeout=timeout, out_path=None, probe=True)


def mdns_fqdn_get(*, host: str, port: int, timeout: int) -> tuple[bool, dict]:
    st = state_get(host=host, port=port, timeout=timeout)
    if not st.get("ok"):
        return False, {"state": st}

    fqdn = str(st.get("mdns_fqdn") or "").strip()
    hostname = str(st.get("mdns_hostname") or "").strip()
    if not fqdn:
        label = str(st.get("device_label") or "").strip().lower()
        if label:
            safe = "".join(ch if (ch.isalnum() or ch == '-') else '-' for ch in label).strip("-")
            if safe:
                hostname = hostname or safe
                fqdn = f"{hostname}.local"

    ok = bool(fqdn)
    return ok, {
        "mdns_fqdn": fqdn,
        "mdns_hostname": hostname,
        "state": st,
    }


def ip_detect(*, port: str, baud: int, timeout: int) -> tuple[bool, dict]:
    ip = detect_device_ip_from_serial(port=port, baud=baud, timeout_s=timeout)
    return bool(ip), {"ip": ip, "port": port, "baud": baud, "timeout": timeout}
