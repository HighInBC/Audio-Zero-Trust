from __future__ import annotations

from urllib.parse import quote

import requests
from urllib.request import urlopen

from tools.azt_client.http import get_json, http_json
from tools.provision_unit import detect_device_ip_from_serial


def state_get(*, host: str, port: int, timeout: int) -> dict:
    return get_json(f"http://{host}:{port}/api/v1/config/state", timeout=timeout)


def attestation_get(*, host: str, port: int, timeout: int, nonce: str) -> dict:
    return get_json(
        f"http://{host}:{port}/api/v1/device/attestation?nonce={quote(nonce, safe='')}",
        timeout=timeout,
    )


def certificate_get(*, host: str, port: int, timeout: int) -> dict:
    return get_json(f"http://{host}:{port}/api/v1/device/certificate", timeout=timeout)


def certificate_post(*, host: str, port: int, timeout: int, payload: dict) -> dict:
    return http_json("POST", f"http://{host}:{port}/api/v1/device/certificate", payload, timeout=timeout)


def reboot_device(*, host: str, port: int, timeout: int) -> dict:
    return http_json("POST", f"http://{host}:{port}/api/v1/device/reboot", {}, timeout=timeout)


def signing_key_check(*, host: str, port: int, timeout: int) -> tuple[bool, dict]:
    with urlopen(f"http://{host}:{port}/api/v1/device/signing-public-key.pem", timeout=timeout) as r:
        pem_body = r.read().decode("utf-8", errors="replace")
        pem_ct = r.headers.get("Content-Type", "")
    with urlopen(f"http://{host}:{port}/api/v1/device/signing-public-key", timeout=timeout) as r:
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
    req_url = f"http://{host}:{port}/stream?seconds={seconds}"
    r = requests.get(req_url, allow_redirects=False, timeout=timeout)
    status = int(r.status_code)
    location = r.headers.get("Location")
    ok = (status == 307) and bool(location and f":{stream_port}/stream" in location)
    return ok, {"status": status, "location": location}


def stream_probe(*, host: str, port: int, seconds: float, timeout: int) -> tuple[bool, dict]:
    url = f"http://{host}:{port}/stream"
    total = 0
    r = requests.get(url, stream=True, timeout=timeout)
    try:
        import time

        start = time.time()
        for chunk in r.iter_content(chunk_size=4096):
            if chunk:
                total += len(chunk)
            if time.time() - start >= seconds:
                break
    finally:
        r.close()
    return total > 0, {"bytes": total, "seconds": seconds}


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
