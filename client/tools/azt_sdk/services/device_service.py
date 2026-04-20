from __future__ import annotations

from urllib.parse import quote, urlencode

import base64
import hashlib
import json
import math
import urllib.error
from pathlib import Path
from urllib.request import Request
import requests

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from tools.azt_client.crypto import load_private_key_auto

from tools.azt_client.crypto import ed25519_fp_hex_from_private_key, load_private_key_auto
import os

from tools.azt_client.http import get_json, http_json, urlopen_with_tls, requests_verify_for_url
from tools.provision_unit import detect_device_ip_from_serial
from tools.azt_sdk.services.url_service import base_url


def _api_scheme() -> str:
    return (os.getenv("AZT_SCHEME", "https") or "https").strip().lower()


def _error_detail(*, where: str, exc: Exception, url: str | None = None, context: dict | None = None) -> dict:
    out = {
        "where": where,
        "exception_type": type(exc).__name__,
        "message": str(exc),
    }
    if url:
        out["url"] = url
    if context:
        out["context"] = context
    return out


def _get_json_safe(*, url: str, timeout: int, where: str, error: str) -> dict:
    try:
        return get_json(url, timeout=timeout)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError, OSError) as e:
        return {
            "ok": False,
            "error": error,
            "detail": _error_detail(where=where, exc=e, url=url),
        }
    except Exception as e:
        return {
            "ok": False,
            "error": error,
            "detail": _error_detail(where=where, exc=e, url=url),
        }


def _state_get_v0(*, host: str, port: int, timeout: int) -> dict:
    b = base_url(host=host, port=port, scheme=_api_scheme())
    url = f"{b}/api/v0/config/state"
    return _get_json_safe(url=url, timeout=timeout, where="device_service.state_get.v0", error="STATE_GET_V0_FAILED")


def _state_get_v1_legacy(*, host: str, port: int, timeout: int) -> dict:
    b = base_url(host=host, port=port, scheme=_api_scheme())
    url = f"{b}/api/v1/config/state"
    return _get_json_safe(url=url, timeout=timeout, where="device_service.state_get.v1_legacy", error="STATE_GET_V1_LEGACY_FAILED")


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
    b = base_url(host=host, port=port, scheme=_api_scheme())
    url = f"{b}/api/v0/device/attestation?nonce={quote(nonce, safe='')}"
    return _get_json_safe(url=url, timeout=timeout, where="device_service.attestation_get", error="ATTESTATION_GET_FAILED")


def certificate_get(*, host: str, port: int, timeout: int) -> dict:
    b = base_url(host=host, port=port, scheme=_api_scheme())
    url = f"{b}/api/v0/device/certificate"
    return _get_json_safe(url=url, timeout=timeout, where="device_service.certificate_get", error="CERTIFICATE_GET_FAILED")


def certificate_post(*, host: str, port: int, timeout: int, payload: dict) -> dict:
    b = base_url(host=host, port=port, scheme=_api_scheme())
    url = f"{b}/api/v0/device/certificate"
    try:
        return http_json("POST", url, payload, timeout=timeout)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError, OSError) as e:
        return {
            "ok": False,
            "error": "CERTIFICATE_POST_FAILED",
            "detail": _error_detail(where="device_service.certificate_post", exc=e, url=url),
        }
    except Exception as e:
        return {
            "ok": False,
            "error": "CERTIFICATE_POST_FAILED",
            "detail": _error_detail(where="device_service.certificate_post", exc=e, url=url),
        }


def reboot_device(*, host: str, port: int, timeout: int, key_path: str) -> dict:
    b = base_url(host=host, port=port, scheme=_api_scheme())
    challenge_url = f"{b}/api/v0/device/reboot/challenge"
    ch = _get_json_safe(url=challenge_url, timeout=timeout, where="device_service.reboot_device.challenge", error="REBOOT_CHALLENGE_REQUEST_FAILED")
    if not ch.get("ok"):
        return {
            "ok": False,
            "error": "ERR_REBOOT_CHALLENGE",
            "detail": ch.get("error") or ch.get("detail") or "challenge request failed",
            "challenge_url": challenge_url,
            "challenge_response": ch,
        }

    nonce = str(ch.get("nonce") or "")
    if not nonce:
        return {"ok": False, "error": "ERR_REBOOT_CHALLENGE", "detail": "missing nonce in challenge response"}

    priv = load_private_key_auto(Path(key_path), purpose=str(key_path))
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
    reboot_url = f"{b}/api/v0/device/reboot"
    try:
        return http_json("POST", reboot_url, payload, timeout=timeout)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError, OSError) as e:
        return {
            "ok": False,
            "error": "REBOOT_REQUEST_FAILED",
            "detail": _error_detail(where="device_service.reboot_device.post", exc=e, url=reboot_url),
        }
    except Exception as e:
        return {
            "ok": False,
            "error": "REBOOT_REQUEST_FAILED",
            "detail": _error_detail(where="device_service.reboot_device.post", exc=e, url=reboot_url),
        }


def signing_key_check(*, host: str, port: int, timeout: int) -> tuple[bool, dict]:
    b = base_url(host=host, port=port, scheme=_api_scheme())
    pem_url = f"{b}/api/v0/device/signing-public-key.pem"
    alias_url = f"{b}/api/v0/device/signing-public-key"
    try:
        with urlopen_with_tls(Request(pem_url, method="GET"), timeout=timeout) as r:
            pem_body = r.read().decode("utf-8", errors="replace")
            pem_ct = r.headers.get("Content-Type", "")
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError) as e:
        return False, {
            "error": "SIGNING_KEY_CHECK_PEM_FETCH_FAILED",
            "detail": _error_detail(where="device_service.signing_key_check.pem", exc=e, url=pem_url),
        }
    except Exception as e:
        return False, {
            "error": "SIGNING_KEY_CHECK_PEM_FETCH_FAILED",
            "detail": _error_detail(where="device_service.signing_key_check.pem", exc=e, url=pem_url),
        }

    try:
        with urlopen_with_tls(Request(alias_url, method="GET"), timeout=timeout) as r:
            pem_alias = r.read().decode("utf-8", errors="replace")
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError) as e:
        return False, {
            "error": "SIGNING_KEY_CHECK_ALIAS_FETCH_FAILED",
            "detail": _error_detail(where="device_service.signing_key_check.alias", exc=e, url=alias_url),
        }
    except Exception as e:
        return False, {
            "error": "SIGNING_KEY_CHECK_ALIAS_FETCH_FAILED",
            "detail": _error_detail(where="device_service.signing_key_check.alias", exc=e, url=alias_url),
        }

    has_pem = "BEGIN PUBLIC KEY" in pem_body
    alias_same = pem_alias == pem_body
    ok = has_pem and ("application/x-pem-file" in pem_ct) and alias_same
    return ok, {
        "content_type": pem_ct,
        "has_public_key_pem": has_pem,
        "alias_matches": alias_same,
        "pem_url": pem_url,
        "alias_url": alias_url,
    }


def stream_redirect_check(*, host: str, port: int, seconds: int, stream_port: int, timeout: int) -> tuple[bool, dict]:
    req_url = f"http://{host}:{int(stream_port)}/stream?seconds={seconds}"
    try:
        r = requests.get(req_url, allow_redirects=False, timeout=timeout, verify=requests_verify_for_url(req_url))
    except (requests.RequestException, TimeoutError, OSError) as e:
        return False, {
            "error": "STREAM_REDIRECT_CHECK_REQUEST_FAILED",
            "detail": _error_detail(where="device_service.stream_redirect_check", exc=e, url=req_url),
        }
    except Exception as e:
        return False, {
            "error": "STREAM_REDIRECT_CHECK_REQUEST_FAILED",
            "detail": _error_detail(where="device_service.stream_redirect_check", exc=e, url=req_url),
        }
    status = int(r.status_code)
    location = r.headers.get("Location")
    ok = (status == 307) and bool(location and f":{stream_port}/stream" in location)
    return ok, {"status": status, "location": location, "url": req_url}


def _verify_stream_header_cert_gate(preface: bytes, admin_pub: ed25519.Ed25519PublicKey) -> tuple[bool, str]:
    if not preface.startswith(b"AZT1\n"):
        return False, "ERR_STREAM_MAGIC"
    off = 5
    nl = preface.find(b"\n", off)
    if nl < 0:
        return False, "ERR_STREAM_HEADER_JSON"
    plain_line = preface[off:nl]
    sig_nl = preface.find(b"\n", nl + 1)
    if sig_nl < 0:
        return False, "ERR_STREAM_HEADER_SIG_LINE"
    sig_line = preface[nl + 1:sig_nl]

    try:
        plain = json.loads(plain_line.decode("utf-8"))
    except Exception:
        return False, "ERR_STREAM_HEADER_JSON"

    cert_doc = plain.get("device_certificate")

    signer_b64 = plain.get("this_header_signing_key_b64")
    if not isinstance(signer_b64, str) or not signer_b64:
        return False, "ERR_STREAM_HEADER_SIGNER_KEY"

    try:
        pub = ed25519.Ed25519PublicKey.from_public_bytes(base64.b64decode(signer_b64, validate=True))
        sig = base64.b64decode(sig_line, validate=True)
        pub.verify(sig, plain_line)
    except Exception:
        return False, "ERR_STREAM_HEADER_SIG_VERIFY"

    # Backward compatibility: allow stream headers without embedded certificate.
    # In this mode, we verify self-signed header integrity only (no admin trust binding).
    if not isinstance(cert_doc, dict) or not isinstance(cert_doc.get("certificate_payload_b64"), str) or not cert_doc.get("certificate_payload_b64"):
        return True, ""

    try:
        cert_payload_raw = base64.b64decode(cert_doc["certificate_payload_b64"], validate=True)
        cert_payload = json.loads(cert_payload_raw.decode("utf-8"))
        cert_sig_b64 = cert_doc.get("signature_b64")
        if not isinstance(cert_sig_b64, str) or not cert_sig_b64:
            return False, "ERR_STREAM_CERT_SIG"
        cert_sig = base64.b64decode(cert_sig_b64, validate=True)
    except Exception:
        return False, "ERR_STREAM_CERT_SCHEMA"

    try:
        admin_pub.verify(cert_sig, cert_payload_raw)
    except Exception:
        return False, "ERR_STREAM_CERT_SIG_VERIFY"

    # Binding checks
    if cert_payload.get("device_sign_public_key_b64") != signer_b64:
        return False, "ERR_STREAM_CERT_BINDING"
    header_serial = plain.get("device_certificate_serial")
    if isinstance(header_serial, str) and header_serial:
        if cert_payload.get("certificate_serial") != header_serial:
            return False, "ERR_STREAM_CERT_SERIAL"

    return True, ""


def _stream_gate_detail(error_code: str, preface: bytes) -> str:
    details = {
        "ERR_STREAM_MAGIC": "stream did not start with AZT1 header; endpoint likely returned non-stream data",
        "ERR_STREAM_HEADER_JSON": "stream header JSON was not parseable",
        "ERR_STREAM_HEADER_SIG_LINE": "stream header signature line missing",
        "ERR_STREAM_HEADER_SIGNER_KEY": "stream header missing this_header_signing_key_b64",
        "ERR_STREAM_HEADER_SIG_VERIFY": "stream header signature verification failed",
        "ERR_STREAM_CERT_SCHEMA": "device certificate in stream header is malformed",
        "ERR_STREAM_CERT_SIG": "device certificate is missing signature",
        "ERR_STREAM_CERT_SIG_VERIFY": "device certificate signature verification failed against admin key",
        "ERR_STREAM_CERT_BINDING": "certificate signing key does not match stream header signing key",
        "ERR_STREAM_CERT_SERIAL": "certificate serial does not match stream header serial",
        "ERR_STREAM_HEADER_TOO_LARGE": "stream header exceeded maximum preface size before signature line",
    }
    msg = details.get(error_code, "stream rejected before write")

    # Helpful hint when the endpoint returned plain text/HTML/JSON instead of AZT1 bytes.
    snippet = ""
    try:
        snippet = preface[:180].decode("utf-8", errors="replace").replace("\r", " ").replace("\n", " ").strip()
    except Exception:
        snippet = ""
    if snippet and not preface.startswith(b"AZT1\n"):
        msg += f"; first bytes: {snippet}"

    return msg


def stream_read(*, host: str, port: int, seconds: float | None, timeout: int, out_path: str | None, probe: bool, key_path: str | None = None) -> tuple[bool, dict]:
    api_b = base_url(host=host, port=port, scheme=_api_scheme())
    stream_b = base_url(host=host, port=8081, scheme="http")
    total = 0
    nonce = ""
    import time
    from pathlib import Path

    admin_pub = None
    if not probe:
        if not key_path:
            return False, {"error": "STREAM_READ_ARGS", "detail": "trusted recording requires key_path"}
        try:
            priv = load_private_key_auto(Path(str(key_path)), purpose=str(key_path))
            if not isinstance(priv, ed25519.Ed25519PrivateKey):
                return False, {"error": "STREAM_READ_KEY", "detail": "admin key must be Ed25519 private key"}
            admin_pub = priv.public_key()
        except Exception as e:
            return False, {
                "error": "STREAM_READ_KEY",
                "detail": _error_detail(where="device_service.stream_read.key", exc=e),
            }

    params: dict[str, str] = {}
    planned_duration_stop = bool((seconds is not None) and (seconds > 0) and (not probe))
    if planned_duration_stop:
        # Tell device to own stream shutdown so it can finalize on-frame/signature boundaries.
        params["seconds"] = str(max(1, int(math.ceil(float(seconds)))))

    # Probe mode remains backwards-compatible with plain stream reads.
    if not probe:
        # Stream freshness challenge (required by firmware).
        try:
            challenge = get_json(f"{api_b}/api/v0/device/stream/challenge", timeout=timeout)
        except Exception as e:
            return False, {
                "error": "STREAM_CHALLENGE_FAILED",
                "detail": _error_detail(where="device_service.stream_read.challenge", exc=e, url=f"{api_b}/api/v0/device/stream/challenge"),
            }
        nonce = str((challenge or {}).get("nonce") or "").strip()
        if not nonce:
            return False, {"error": "STREAM_CHALLENGE_FAILED", "detail": "missing nonce"}

        params["nonce"] = nonce
        if bool((challenge or {}).get("recorder_auth_required")):
            if not key_path:
                return False, {"error": "STREAM_AUTH_KEY_REQUIRED", "detail": "device requires recorder auth signature"}
            try:
                priv = load_private_key_auto(Path(str(key_path)), purpose=str(key_path))
                if not isinstance(priv, ed25519.Ed25519PrivateKey):
                    return False, {"error": "STREAM_AUTH_KEY", "detail": "recorder auth key must be Ed25519 private key"}
                signer_fp = ed25519_fp_hex_from_private_key(Path(str(key_path)))
                device_fp = str((challenge or {}).get("device_sign_fingerprint_hex") or "").strip().lower()
                msg = f"stream:{nonce}:{device_fp}".encode("utf-8")
                sig_b64 = base64.b64encode(priv.sign(msg)).decode("ascii")
                params.update({"sig_alg": "ed25519", "sig": sig_b64, "signer_fp": signer_fp})
            except Exception as e:
                return False, {
                    "error": "STREAM_AUTH_KEY",
                    "detail": _error_detail(where="device_service.stream_read.auth", exc=e),
                }

    url = f"{stream_b}/stream"
    if params:
        url = f"{url}?{urlencode(params)}"

    out_file = None
    resolved_out = ""
    preface_buf = bytearray()
    preface_checked = bool(probe)
    # Header preface can exceed 4 KiB when certificate blobs are present.
    # Keep buffering until we have both header lines, with a hard cap to avoid unbounded memory.
    preface_required_bytes = 65536
    if not probe and out_path:
      p = Path(out_path)
      p.parent.mkdir(parents=True, exist_ok=True)
      out_file = p.open("wb")
      resolved_out = str(p)

    try:
        r = requests.get(url, stream=True, timeout=timeout, verify=requests_verify_for_url(url))
    except (requests.RequestException, TimeoutError, OSError) as e:
        if out_file is not None:
            out_file.close()
        return False, {
            "error": "STREAM_READ_REQUEST_FAILED",
            "detail": _error_detail(where="device_service.stream_read", exc=e, url=url),
            "out": resolved_out,
        }
    except Exception as e:
        if out_file is not None:
            out_file.close()
        return False, {
            "error": "STREAM_READ_REQUEST_FAILED",
            "detail": _error_detail(where="device_service.stream_read", exc=e, url=url),
            "out": resolved_out,
        }

    try:
        start = time.time()
        for chunk in r.iter_content(chunk_size=4096):
            if chunk:
                total += len(chunk)
                if not preface_checked:
                    preface_buf.extend(chunk)
                    # Need at least first two lines: plaintext header + signature line.
                    if len(preface_buf) >= 12:
                        first_nl = preface_buf.find(b"\n", 5)
                        second_nl = preface_buf.find(b"\n", first_nl + 1) if first_nl >= 0 else -1
                        if second_nl >= 0:
                            ok_hdr, err_hdr = _verify_stream_header_cert_gate(bytes(preface_buf), admin_pub)
                            if not ok_hdr:
                                return False, {
                                    "error": err_hdr,
                                    "detail": _stream_gate_detail(err_hdr, bytes(preface_buf)),
                                    "bytes": total,
                                    "out": resolved_out,
                                    "url": url,
                                }
                            preface_checked = True
                            if out_file is not None and len(preface_buf) > 0:
                                out_file.write(preface_buf)
                            preface_buf.clear()
                        elif len(preface_buf) >= preface_required_bytes:
                            return False, {
                                "error": "ERR_STREAM_HEADER_TOO_LARGE",
                                "detail": f"stream header preface exceeded {preface_required_bytes} bytes before signature line terminator",
                                "bytes": total,
                                "out": resolved_out,
                                "url": url,
                            }
                    continue

                if out_file is not None:
                    out_file.write(chunk)
            if seconds is not None:
                elapsed = (time.time() - start)
                if not planned_duration_stop and elapsed >= seconds:
                    break
                # In planned-duration mode the device should close gracefully.
                # Keep a bounded local failsafe in case firmware/network never closes.
                if planned_duration_stop and elapsed >= (float(seconds) + 8.0):
                    break
    except (requests.RequestException, OSError, ValueError) as e:
        return False, {
            "error": "STREAM_READ_ITERATION_FAILED",
            "detail": _error_detail(where="device_service.stream_read.iter", exc=e, url=url),
            "bytes": total,
            "out": resolved_out,
        }
    except Exception as e:
        return False, {
            "error": "STREAM_READ_ITERATION_FAILED",
            "detail": _error_detail(where="device_service.stream_read.iter", exc=e, url=url),
            "bytes": total,
            "out": resolved_out,
        }
    finally:
        r.close()
        if out_file is not None:
            out_file.close()
    if not preface_checked and not probe:
        ok_hdr, err_hdr = _verify_stream_header_cert_gate(bytes(preface_buf), admin_pub)
        if not ok_hdr:
            return False, {
                "error": err_hdr,
                "detail": _stream_gate_detail(err_hdr, bytes(preface_buf)),
                "bytes": total,
                "out": resolved_out,
                "url": url,
            }
        if out_file is not None and len(preface_buf) > 0:
            out_file.write(preface_buf)

    elapsed = time.time() - start
    payload = {"bytes": total, "seconds": elapsed, "requested_seconds": seconds, "url": url}
    if nonce:
        payload["stream_auth_nonce"] = nonce
    if resolved_out:
        payload["out"] = resolved_out
    return total > 0, payload


def stream_probe(*, host: str, port: int, seconds: float | None, timeout: int) -> tuple[bool, dict]:
    # Back-compat wrapper for older callers.
    return stream_read(host=host, port=port, seconds=seconds, timeout=timeout, out_path=None, probe=True)


def stream_terminate(*, host: str, port: int, timeout: int, key_path: str, stream_auth_nonce: str, reason_code: int = 2, message_json: dict | None = None) -> tuple[bool, dict]:
    api_b = base_url(host=host, port=port, scheme=_api_scheme())
    url = f"{api_b}/api/v0/device/stream/terminate"

    try:
        priv = load_private_key_auto(Path(str(key_path)), purpose=str(key_path))
        if not isinstance(priv, ed25519.Ed25519PrivateKey):
            return False, {"error": "STREAM_TERMINATE_KEY", "detail": "key must be Ed25519 private key"}
    except Exception as e:
        return False, {
            "error": "STREAM_TERMINATE_KEY",
            "detail": _error_detail(where="device_service.stream_terminate.key", exc=e),
        }

    try:
        st = state_get(host=host, port=port, timeout=timeout)
        if not st.get("ok"):
            return False, {"error": "STREAM_TERMINATE_STATE", "detail": st}
        device_fp = str(st.get("device_sign_fingerprint_hex") or "").strip().lower()
        if not device_fp:
            return False, {"error": "STREAM_TERMINATE_STATE", "detail": "missing device_sign_fingerprint_hex in state"}
    except Exception as e:
        return False, {
            "error": "STREAM_TERMINATE_STATE",
            "detail": _error_detail(where="device_service.stream_terminate.state", exc=e),
        }

    user_msg = message_json if isinstance(message_json, dict) else {}
    user_json_str = json.dumps(user_msg, separators=(",", ":"), sort_keys=True)
    user_hash_hex = hashlib.sha256(user_json_str.encode("utf-8")).hexdigest()

    signer_fp = ed25519_fp_hex_from_private_key(Path(str(key_path)))
    signed_msg = f"stream_terminate:{stream_auth_nonce}:{device_fp}:{int(reason_code)}:{user_hash_hex}".encode("utf-8")
    sig_b64 = base64.b64encode(priv.sign(signed_msg)).decode("ascii")

    payload = {
        "stream_auth_nonce": stream_auth_nonce,
        "reason_code": int(reason_code),
        "message_json": user_msg,
        "signature_algorithm": "ed25519",
        "signature_b64": sig_b64,
        "signer_fingerprint_hex": signer_fp,
    }

    try:
        res = http_json("POST", url, payload, timeout=timeout)
        return bool(res.get("ok")), res
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError, OSError) as e:
        return False, {
            "error": "STREAM_TERMINATE_REQUEST_FAILED",
            "detail": _error_detail(where="device_service.stream_terminate.post", exc=e, url=url),
        }
    except Exception as e:
        return False, {
            "error": "STREAM_TERMINATE_REQUEST_FAILED",
            "detail": _error_detail(where="device_service.stream_terminate.post", exc=e, url=url),
        }


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
